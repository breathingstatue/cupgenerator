// opponentsmod.cpp — Opponents lineup + optional grid reordering (unified)
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_WARNINGS
#define NOMINMAX
#include <windows.h>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "core.h"
#include "opponentsmod.h"
#include "obtainmod.h"      // SetActiveCupContext
#include "CupGenGlobals.h"  // paths / env helpers
#include "addresses.h"     // g_addrs + AI slot stride

static constexpr int       OFF_NUMCARS = 0x68;        // int NumCars at +0x68

// ============================== Globals ==============================

static uint8_t** g_ppCarTableBase = nullptr; // &DAT_006fab50
static int* g_pCarCount = nullptr; // &DAT_006fab58

static uint8_t* gCarTableBase = nullptr;    // snapshot
static int       gCarCount = 0;

static uintptr_t gOppIndexSlotAddrs[16] = {}; // absolute addresses for legacy write

struct CarEntry { uint8_t pad[0x14]; char folder[0x40]; }; // (assumed) layout

static std::unordered_map<std::string, int> gIndexByFolder;
static std::vector<std::string>             gOpponents;
static std::vector<int>                     gOppIndices;

// one-time init
static std::once_flag gLoadOnce;

// Parsed from cup
static int  gParsedStartGridMode = 0;
static bool gOpponentsLoaded = false;

// NEW: Joker / RandomCars (+ Joker name)
static bool gParsedJoker = false;            // Joker 1 => AI mirror player's car
static std::string gJokerExplicitName;       // optional: Joker 1 <foldername>

// --- RandomCars pool flags + sticky pick per-cup ---
static bool gParsedRandomPlayer = false;     // already existed
struct PoolFlags { bool stock = false, main = false, bonus = false; };
static PoolFlags gRandomPools{};
static int  gRandomPlayerIdx = -1;           // chosen once per cup (sticky)
static std::string gRandomCupId;             // cup id for which gRandomPlayerIdx is valid

// --- Sticky AI selection from RandomCars pools (when no Opponents line) ---
static std::vector<int> gStickyAiIndices; // size up to 15
static std::string      gAiCupId;         // cup id for which gStickyAiIndices is valid

// --- Stock (game_files) blacklist ---
static const std::unordered_set<std::string> kStockGameFilesBlacklist = {
    "misc","q","trolley","ufo","wincar","wincar2","wincar3","wincar4"
};

// ============================== Small helpers ==============================

static inline uint8_t* active_cup() {
    auto pp = reinterpret_cast<uint8_t**>(AbsFromMaybeRva(g_addrs.rva_ActiveCupPtr));
    return pp ? *pp : nullptr;
}
static inline int cup_numcars() {
    auto c = active_cup(); if (!c) return 0;
    return *reinterpret_cast<int*>(c + OFF_NUMCARS);
}

static std::string filename_noext_lower(const char* path) {
    const char* slash = strrchr(path, '\\');
    const char* base = slash ? slash + 1 : path;
    std::string s(base);
    size_t dot = s.find_last_of('.');
    if (dot != std::string::npos) s.resize(dot);
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)tolower(c); });
    return s;
}

static void DumpCarFoldersIfWanted(int limit) {
    const bool wantDump = !get_env("RVGL_OPP_DUMP").empty();
    if (!wantDump) return;
    if (!gCarTableBase || gCarCount <= 0)
        return;
    if (limit <= 0) limit = (std::min)(40, gCarCount);
    for (int i = 0; i < limit && i < gCarCount; ++i) {
        auto* car = reinterpret_cast<const CarEntry*>(gCarTableBase + i * 0x110);
        char name[65] = {}; memcpy(name, car->folder, 64);
        for (int k = 0; k < 64; ++k) {
            unsigned char c = (unsigned char)name[k];
            if (!c) break; if (c < 32 || c > 126) name[k] = '?';
        }
    }
}

static void BuildFolderIndex() {
    gIndexByFolder.clear();
    if (!gCarTableBase || gCarCount <= 0) {
        return;
    }
    for (int i = 0; i < gCarCount; ++i) {
        auto* car = reinterpret_cast<const CarEntry*>(gCarTableBase + i * 0x110);
        if (!car->folder[0]) continue;
        std::string name = car->folder;
        if (!name.empty() && name.size() < 64) {
            std::transform(name.begin(), name.end(), name.begin(),
                [](unsigned char c) { return (char)tolower(c); });
            gIndexByFolder[name] = i;
        }
    }
    DumpCarFoldersIfWanted(40);
}

static void SnapshotRegistry(const char* tag) {
    if (!g_ppCarTableBase || !g_pCarCount) return;
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(g_ppCarTableBase, &mbi, sizeof(mbi)) == sizeof(mbi))
        gCarTableBase = *g_ppCarTableBase;
    if (VirtualQuery(g_pCarCount, &mbi, sizeof(mbi)) == sizeof(mbi))
        gCarCount = *g_pCarCount;
}

static void EnsureSnapshotIfNeeded(const char* who) {
    if ((!gCarTableBase || gCarCount <= 0) && g_ppCarTableBase && g_pCarCount) {
        SnapshotRegistry(who);
        BuildFolderIndex();
    }
}

static void Trim(std::string& s) {
    auto issp = [](unsigned char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ','; };
    auto b = std::find_if_not(s.begin(), s.end(), issp);
    auto e = std::find_if_not(s.rbegin(), s.rend(), issp).base();
    if (b < e) s.assign(b, e); else s.clear();
}
static std::vector<std::string> SplitTokens(const std::string& line) {
    std::vector<std::string> out; std::string tok;
    for (char c : line) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ',') { if (!tok.empty()) { out.push_back(tok); tok.clear(); } }
        else tok.push_back(c);
    }
    if (!tok.empty()) out.push_back(tok);
    for (auto& s : out)
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char ch) { return (char)tolower(ch); });
    return out;
}

static bool DirExistsA(const std::string& path) {
    DWORD attr = GetFileAttributesA(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES) && (attr & FILE_ATTRIBUTE_DIRECTORY);
}

static std::string DetectRootFromCupPath(const std::string& cupPath) {
    // Walk upward to find "packs" folder, then return its parent as the root.
    // cupPath is e.g. C:\...\profiles\...\cups\mycup.txt
    std::string p = cupPath;
    for (int i = 0; i < 10; ++i) {
        size_t pos = p.find_last_of("\\/");
        if (pos == std::string::npos) break;
        p.resize(pos);
        size_t leaf = p.find_last_of("\\/");
        std::string last = (leaf == std::string::npos) ? p : p.substr(leaf + 1);
        if (_stricmp(last.c_str(), "packs") == 0) {
            // parent of packs is root
            if (leaf == std::string::npos) return "";
            return p.substr(0, leaf);
        }
    }
    // Fallback: environment variable if available
    std::string env = get_env("RVGL_ROOT");
    return env;
}

// Stock now means only packs\main_files\cars\*
static bool CarFolderInStock(const std::string& root, const std::string& folder) {
    if (root.empty()) return false;
    std::string mainPath = root + "\\packs\\main_files\\cars\\" + folder;
    return DirExistsA(mainPath);
}

static bool CarFolderInMain(const std::string& root, const std::string& folder) {
    if (root.empty()) return false;
    std::string p = root + "\\packs\\io_cars\\cars\\" + folder;
    return DirExistsA(p);
}

static bool CarFolderInBonus(const std::string& root, const std::string& folder) {
    if (root.empty()) return false;
    std::string p = root + "\\packs\\io_cars_bonus\\cars\\" + folder;
    return DirExistsA(p);
}

// Build pool indices once we know root + registry
static void BuildPoolIndices(const std::string& root, std::vector<int>& out) {
    out.clear();
    if (!gCarTableBase || gCarCount <= 0) return;

    for (int i = 0; i < gCarCount; ++i) {
        auto* car = reinterpret_cast<const CarEntry*>(gCarTableBase + i * 0x110);
        if (!car->folder[0]) continue;

        std::string folder = car->folder;
        std::transform(folder.begin(), folder.end(), folder.begin(),
            [](unsigned char c) { return (char)tolower(c); });

        // ---- NEW: skip stock blacklisted names ----
        if (CarFolderInStock(root, folder) &&
            kStockGameFilesBlacklist.find(folder) != kStockGameFilesBlacklist.end()) {
            continue;
        }

        bool ok = false;
        if (gRandomPools.stock && CarFolderInStock(root, folder)) ok = true;
        if (!ok && gRandomPools.main && CarFolderInMain(root, folder))  ok = true;
        if (!ok && gRandomPools.bonus && CarFolderInBonus(root, folder)) ok = true;

        if (ok) out.push_back(i);
    }
}

static uintptr_t PlayerIndexAddr() {
    // Player slot is the block immediately *before* AISlot0.
    if (!g_addrs.rva_AISlot0) return 0;
    const uint32_t rvaPlayer = g_addrs.rva_AISlot0 - static_cast<uint32_t>(AI_SLOT_STRIDE);
    return AbsFromMaybeRva(rvaPlayer);
}

static bool ReadPlayerCarIndex(int& outIdx) {
    uintptr_t pAddr = PlayerIndexAddr();
    if (!pAddr) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery((void*)pAddr, &mbi, sizeof(mbi)) != sizeof(mbi) ||
        mbi.State != MEM_COMMIT ||
        !(mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return false;
    outIdx = *(volatile int*)pAddr;
    return true;
}

static bool WritePlayerCarIndex(int idx) {
    uintptr_t pAddr = PlayerIndexAddr();
    if (!pAddr) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery((void*)pAddr, &mbi, sizeof(mbi)) != sizeof(mbi) ||
        mbi.State != MEM_COMMIT ||
        !(mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return false;
    *(volatile int*)pAddr = idx;
    return true;
}

static void EnsureRandomPlayerPickOnce() {
    if (!gParsedRandomPlayer) return;

    // Identify the cup; if changed, clear sticky pick
    std::string cupPath, cupId;
    if (!ObtainMod::GetLaunchedCupPath(cupPath, cupId)) return;

    if (gRandomCupId != cupId) {
        gRandomCupId = cupId;
        gRandomPlayerIdx = -1;
    }
    if (gRandomPlayerIdx >= 0) return; // already picked

    // Build allowed pool
    std::string root = DetectRootFromCupPath(cupPath);
    std::vector<int> pool;
    if (gRandomPools.stock || gRandomPools.main || gRandomPools.bonus) {
        BuildPoolIndices(root, pool);
    }
    if (pool.empty()) {
        // fallback to all cars if pool ended up empty
        for (int i = 0; i < gCarCount; ++i) pool.push_back(i);
    }

    if (pool.empty()) {
        return;
    }

    LARGE_INTEGER t; QueryPerformanceCounter(&t);
    unsigned seed = (unsigned)(t.LowPart ^ t.HighPart);
    srand(seed);
    int rnd = pool[rand() % (int)pool.size()];
    gRandomPlayerIdx = rnd;
}

static void EnsureStickyAiFromPoolsOnce() {
    // Only if RandomCars is active and we don't already have a sticky set
    if (!gParsedRandomPlayer) return;

    std::string cupPath, cupId;
    if (!ObtainMod::GetLaunchedCupPath(cupPath, cupId)) return;

    // Determine current AI count from the active cup (NumCars - 1, clamp 1..15)
    int numCars = cup_numcars();
    int nAi = std::max(0, std::min(numCars - 1, 15));
    if (nAi <= 0) { gStickyAiIndices.clear(); gAiCupId.clear(); return; }

    // Reset if cup changed or size changed
    if (gAiCupId != cupId || (int)gStickyAiIndices.size() != nAi) {
        gStickyAiIndices.clear();
        gAiCupId.clear();
    }
    if ((int)gStickyAiIndices.size() == nAi) return; // already picked for this cup

    // Build pool from requested sources
    std::string root = DetectRootFromCupPath(cupPath);
    std::vector<int> pool;
    if (gRandomPools.stock || gRandomPools.main || gRandomPools.bonus) {
        BuildPoolIndices(root, pool);
    }
    if (pool.empty()) {
        // fallback: all cars
        for (int i = 0; i < gCarCount; ++i) pool.push_back(i);
    }

    // Exclude the chosen player index if available
    int playerIdx = -1;
    ReadPlayerCarIndex(playerIdx);
    if (playerIdx >= 0) {
        pool.erase(std::remove(pool.begin(), pool.end(), playerIdx), pool.end());
    }

    if (pool.empty()) {
        return;
    }

    // Sample without replacement where possible; if pool < nAi, allow repeats
    LARGE_INTEGER t; QueryPerformanceCounter(&t);
    unsigned seed = (unsigned)(t.LowPart ^ t.HighPart);
    srand(seed);

    std::vector<int> bag = pool;                // mutable bag for no-replacement
    gStickyAiIndices.reserve(nAi);
    for (int i = 0; i < nAi; ++i) {
        if (!bag.empty()) {
            int k = rand() % (int)bag.size();
            gStickyAiIndices.push_back(bag[k]);
            bag.erase(bag.begin() + k);
        }
        else {
            // pool exhausted -> repeat from original pool
            int k = rand() % (int)pool.size();
            gStickyAiIndices.push_back(pool[k]);
        }
    }
    gAiCupId = cupId;
}

static void WriteAiFirstInts(const std::vector<int>& aiIdx) {
    if (aiIdx.empty()) return;
    uintptr_t aiBase = AbsFromMaybeRva(g_addrs.rva_AISlot0);
    if (!aiBase)
        return;

    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery((void*)aiBase, &mbi, sizeof(mbi)) != sizeof(mbi) ||
        mbi.State != MEM_COMMIT ||
        !(mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
        return;
    }
    for (size_t i = 0; i < aiIdx.size(); ++i)
        *(volatile int*)(aiBase + i * AI_SLOT_STRIDE) = aiIdx[i];
    }

// ============================== Cup parsing ==============================

static void ResolveOppIndices() {
    gOppIndices.clear();
    gOppIndices.reserve(gOpponents.size());
    for (auto& s : gOpponents) {
        auto it = gIndexByFolder.find(s);
        if (it != gIndexByFolder.end()) gOppIndices.push_back(it->second);
    }
    if (!gOpponents.empty() && gOppIndices.empty()) {
        DumpCarFoldersIfWanted(40);
    }
}

static bool LoadOpponentsFromCup() {
    std::string cupPath, cupId;
    if (!ObtainMod::GetLaunchedCupPath(cupPath, cupId)) {
        // Hard reset to avoid carrying state
        gOpponents.clear();
        gOppIndices.clear();
        gParsedStartGridMode = 0;
        gParsedJoker = false;
        gParsedRandomPlayer = false;
        gJokerExplicitName.clear();
        gRandomPools = {};
        // Also clear any sticky picks
        gRandomCupId.clear();
        gRandomPlayerIdx = -1;
        gAiCupId.clear();
        gStickyAiIndices.clear();
        return false;
    }

    FILE* f = fopen(cupPath.c_str(), "rb");
    if (!f) {
        gOpponents.clear();
        gOppIndices.clear();
        gParsedStartGridMode = 0;
        // Ensure toggles are not left true from a previous cup
        gParsedJoker = false;
        gParsedRandomPlayer = false;
        gJokerExplicitName.clear();
        gRandomPools = {};
        return false;
    }

    std::string content; char buf[4096]; size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) content.append(buf, n);
    fclose(f);

    // ===== IMPORTANT: reset all parse-time toggles BEFORE scanning lines =====
    gOpponents.clear();
    gOppIndices.clear();
    gParsedStartGridMode = 0;
    gParsedJoker = false;
    gParsedRandomPlayer = false;
    gJokerExplicitName.clear();
    gRandomPools = {};    // stock/main/bonus all false until explicitly enabled

    size_t pos = 0;
    bool sawOpponents = false;
    while (pos < content.size()) {
        size_t eol = content.find_first_of("\r\n", pos);
        if (eol == std::string::npos) eol = content.size();
        std::string line = content.substr(pos, eol - pos);
        pos = (eol == content.size()) ? eol : eol + 1;

        std::string lower = line;
        std::transform(lower.begin(), lower.end(), lower.begin(),
            [](unsigned char c) { return (char)tolower(c); });

        // StartGrid M
        if (lower.rfind("startgrid", 0) == 0) {
            size_t sp = line.find_first_of(" \t");
            if (sp != std::string::npos) {
                std::string rest = line.substr(sp);
                Trim(rest);
                auto toks = SplitTokens(rest);
                if (!toks.empty()) {
                    int v = 0;
                    try { v = std::stoi(toks[0]); }
                    catch (...) { v = 0; }
                    gParsedStartGridMode = (v >= 0 && v <= 2) ? v : 0;
                }
            }
            continue;
        }

        // Opponents a b c ...
        if (!sawOpponents && lower.rfind("opponents", 0) == 0) {
            size_t sp = line.find_first_of(" \t");
            if (sp != std::string::npos) {
                std::string rest = line.substr(sp);
                Trim(rest);
                gOpponents = SplitTokens(rest);
                sawOpponents = true;
            }
            continue;
        }

        // Joker N [carfolder]
        if (lower.rfind("joker", 0) == 0) {
            size_t sp = line.find_first_of(" \t");
            if (sp != std::string::npos) {
                std::string rest = line.substr(sp);
                Trim(rest);
                auto toks = SplitTokens(rest); // already lowercased
                int v = 0; if (!toks.empty()) { try { v = std::stoi(toks[0]); } catch (...) { v = 0; } }
                gParsedJoker = (v != 0);
                if (gParsedJoker && toks.size() >= 2) {
                    gJokerExplicitName = toks[1]; // folder name like "toyeca"
                }
            }
            continue;
        }

        // RandomCars N [stock] [main] [bonus]
        if (lower.rfind("randomcars", 0) == 0) {
            size_t sp = line.find_first_of(" \t");
            if (sp != std::string::npos) {
                std::string rest = line.substr(sp);
                Trim(rest);
                auto toks = SplitTokens(rest); // already lowercased
                int v = 0;
                if (!toks.empty()) { try { v = std::stoi(toks[0]); } catch (...) { v = 0; } }
                gParsedRandomPlayer = (v != 0);
                gRandomPools = {};  // reset pools every parse of this line

                if (gParsedRandomPlayer) {
                    // default if no pools listed: allow ALL
                    bool any = false;
                    for (size_t i = 1; i < toks.size(); ++i) {
                        const std::string& t = toks[i];
                        if (t == "stock" || t == "game_files") { gRandomPools.stock = true; any = true; }
                        else if (t == "main" || t == "io_cars") { gRandomPools.main = true; any = true; }
                        else if (t == "bonus" || t == "io_cars_bonus") { gRandomPools.bonus = true; any = true; }
                    }
                    if (!any) { gRandomPools.stock = gRandomPools.main = gRandomPools.bonus = true; }
                }

                // If cup changed, clear sticky pick
                std::string cid;
                if (ObtainMod::GetLaunchedCupPath(cupPath, cid)) {
                    if (cid != gRandomCupId) {
                        gRandomCupId.clear();
                        gRandomPlayerIdx = -1;
                    }
                }
            }
            continue;
        }
    }

    // If RandomCars was NOT present or is 0, ensure no leftover sticky picks
    if (!gParsedRandomPlayer) {
        gRandomCupId.clear();
        gRandomPlayerIdx = -1;
        gAiCupId.clear();
        gStickyAiIndices.clear();
    }

    std::string joined;
    for (size_t i = 0; i < gOpponents.size(); ++i) { if (i) joined += ' '; joined += gOpponents[i]; }

    ResolveOppIndices();
    return true;
}

// ============================== Grid application ==============================

// Overwrite the first int of each AI slot-struct with our car index list.
static void ApplyOpponentsIndices_PreBuild() {
    if (gOppIndices.empty()) return;
    uintptr_t aiBase = AbsFromMaybeRva(g_addrs.rva_AISlot0);
    if (!aiBase) 
        return;

    size_t nAi = std::min<size_t>(gOppIndices.size(), 15);
    for (size_t i = 0; i < nAi; ++i) {
        uintptr_t slot0 = aiBase + i * AI_SLOT_STRIDE;
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery((void*)slot0, &mbi, sizeof(mbi)) != sizeof(mbi) ||
            mbi.State != MEM_COMMIT ||
            !(mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
            break;
        }
        *(volatile int*)slot0 = (int)gOppIndices[i];
    }
}

// Swap two AI slot "structs" (0x25 dwords each). Safe even if count small.
static void SwapAiSlotStructs(uintptr_t base, size_t a, size_t b) {
    if (a == b) return;
    uint8_t* pa = reinterpret_cast<uint8_t*>(base + a * AI_SLOT_STRIDE);
    uint8_t* pb = reinterpret_cast<uint8_t*>(base + b * AI_SLOT_STRIDE);
    std::vector<uint8_t> tmp(AI_SLOT_STRIDE);
    memcpy(tmp.data(), pa, AI_SLOT_STRIDE);
    memcpy(pa, pb, AI_SLOT_STRIDE);
    memcpy(pb, tmp.data(), AI_SLOT_STRIDE);
}

// Apply a desired ordering of AI logical indices (values in 0..nAi-1, BEST-FIRST).
// This reorders the AI slot-structs [1..nAi] in memory to match the desired order,
// keeping the player (slot 0) untouched.
static void ApplyPermutationByAiOrder(const std::vector<uint8_t>& desired) {
    if (desired.empty()) return;
    int numCars = cup_numcars();
    if (numCars <= 1) return;
    size_t nAi = (size_t)std::min(std::max(numCars - 1, 0), 15);
    if (nAi == 0) return;

    // Clamp desired to nAi.
    std::vector<uint8_t> order = desired;
    if (order.size() > nAi) order.resize(nAi);

    uintptr_t aiBase = AbsFromMaybeRva(g_addrs.rva_AISlot0);
    if (!aiBase)
        return;

    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery((void*)aiBase, &mbi, sizeof(mbi)) != sizeof(mbi) ||
        mbi.State != MEM_COMMIT ||
        !(mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
        return;
    }

    // Current logical order is identity: cur[i] = i
    std::vector<uint8_t> cur(nAi);
    for (size_t i = 0; i < nAi; ++i) cur[i] = (uint8_t)i;

    // For each target position p, ensure desired[p] is at position p by swapping structs.
    for (size_t p = 0; p < order.size(); ++p) {
        uint8_t need = order[p];
        if (need >= nAi) continue; // safety

        // find `need` in cur
        size_t at = p;
        while (at < nAi && cur[at] != need) ++at;
        if (at == p) continue;          // already correct
        if (at >= nAi) continue;        // shouldn't happen

        // swap physical slot-structs
        SwapAiSlotStructs(aiBase, p, at);
        std::swap(cur[p], cur[at]);
    }
}

// We now prefer standings-based ordering via ObtainMod. If not available, we fall back:
// - mode 1/2 fallback: simple reverse AI block (leader last).
static void ApplyStartGridPolicy() {
    if (gParsedStartGridMode == 0) return; // vanilla

    std::vector<uint8_t> aiOrder;
    int numDrivers = 0, playerSlot = 0;
    if (ObtainMod::ComputeAiGridOrder(gParsedStartGridMode, aiOrder, numDrivers, playerSlot)) {
        ApplyPermutationByAiOrder(aiOrder);
        return;
    }
}

// ============================== Hooks ==============================

// 1) Calling-convention macro & typedefs
#if defined(_M_IX86)
#  define RVGL_FASTCALL __fastcall
#else
#  define RVGL_FASTCALL __fastcall
#endif

using FnLoadCars = void (RVGL_FASTCALL*)(void);
using FnBuildGrid = void (RVGL_FASTCALL*)(void);

static FnLoadCars  s_LoadCars_Orig = nullptr;
static FnBuildGrid s_BuildGrid_Orig = nullptr;

// 2) Detour signatures must match
static void RVGL_FASTCALL LoadCars_Hook() {
    if (!ObtainMod::EnsureGateForCurrentCupOnce()) return;
    if (s_LoadCars_Orig) s_LoadCars_Orig();
    SnapshotRegistry("Loader");
    BuildFolderIndex();
}

static void RVGL_FASTCALL BuildGrid_Hook() {
    if (!active_cup()) { if (s_BuildGrid_Orig) s_BuildGrid_Orig(); return; }
    EnsureSnapshotIfNeeded("BuildGrid");
    LoadOpponentsFromCup();
    ResolveOppIndices();

    // --- Decide/assign PLAYER car first ---
    if (gParsedRandomPlayer) {
        // Pick once per cup from the requested pools
        EnsureRandomPlayerPickOnce();
        if (gRandomPlayerIdx >= 0) {
            WritePlayerCarIndex(gRandomPlayerIdx);   // << set player car
        }
    }
    else if (gParsedJoker && !gJokerExplicitName.empty()) {
        // Only if RandomCars is NOT active: set an explicit player car for Joker
        auto it = gIndexByFolder.find(gJokerExplicitName);
        if (it != gIndexByFolder.end()) {
            WritePlayerCarIndex(it->second);         // << set player car
        }
    }

    // --- Now set AI according to Joker / Opponents / RandomCars-pools ---
    if (gParsedJoker) {
        int playerIdx = -1;
        if (ReadPlayerCarIndex(playerIdx) && playerIdx >= 0 && playerIdx < gCarCount) {
            int numCars = cup_numcars();
            size_t nAi = (size_t)std::min(std::max(numCars - 1, 0), 15);
            std::vector<int> same(nAi, playerIdx);
            WriteAiFirstInts(same);
        }
    }
    else if (!gOppIndices.empty()) {
        // Explicit Opponents list wins
        ApplyOpponentsIndices_PreBuild();
    }
    else if (gParsedRandomPlayer) {
        // No Opponents line; restrict AI to the same pools (sticky per cup)
        EnsureStickyAiFromPoolsOnce();

        // Ensure size matches current AI count
        int numCars = cup_numcars();
        size_t nAi = (size_t)std::min(std::max(numCars - 1, 0), 15);
        if (gStickyAiIndices.size() != nAi) {
            gAiCupId.clear();
            gStickyAiIndices.clear();
            EnsureStickyAiFromPoolsOnce();
        }
        if (!gStickyAiIndices.empty()) {
            WriteAiFirstInts(gStickyAiIndices);
        }
    }
    else {
        // Vanilla CPU selection
    }

    // StartGrid policy still applies (standings/reverse, etc.)
    ApplyStartGridPolicy();

    if (s_BuildGrid_Orig) s_BuildGrid_Orig();
}

// ============================== Public API ==============================

void OpponentsMod::NotifyActiveCup(const char* cupPathResolved) {
    // Inform ObtainMod (kept so other systems can resolve the same cup)
    if (cupPathResolved && *cupPathResolved) {
        auto id = filename_noext_lower(cupPathResolved);
        ObtainMod::SetActiveCupContext(cupPathResolved, id.c_str());
    }
    else {
        ObtainMod::SetActiveCupContext("", "");
    }
}

bool OpponentsMod::InstallOpponentsHooks() {
    // Resolve globals
    g_ppCarTableBase = reinterpret_cast<uint8_t**>(AbsFromMaybeRva(g_addrs.rva_CarTablePtr));
    g_pCarCount = reinterpret_cast<int*>(AbsFromMaybeRva(g_addrs.rva_CarCount));

    const uintptr_t loadCarsAbs = AbsFromMaybeRva(g_addrs.rva_LoadCars);
    const uintptr_t buildAbs = AbsFromMaybeRva(g_addrs.rva_BuildGrid);

    bool ok = true;
    if (loadCarsAbs) ok &= HookFunction(loadCarsAbs, (LPVOID)&LoadCars_Hook, (LPVOID*)&s_LoadCars_Orig);
    if (buildAbs)    ok &= HookFunction(buildAbs, (LPVOID)&BuildGrid_Hook, (LPVOID*)&s_BuildGrid_Orig);

    return ok;
}
