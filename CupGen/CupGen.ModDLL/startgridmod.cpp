// startgridmod.cpp — Start Grid manager + session-log mirror for CupGenerator

#define NOMINMAX

#include "core.h"
#include "startgridmod.h"
#include "CupGenGlobals.h"
#include <windows.h>
#include <shlwapi.h>
#include <atomic>
#include <chrono>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>
#include <map>
#include <algorithm>     // sort / reverse
#include <string_view>   // std::string_view in Basename()
#include <direct.h>      // for _mkdir
#include <cctype>        // for isdigit

#pragma comment(lib, "shlwapi.lib")

namespace fs = std::filesystem;

// ------------------------------- configuration ----------------------------

// Canonical filenames/exts (keep these consistent everywhere)
static const char* kRaceLogTxt = "race_log.txt"; // live CSV-ish mirror
static const char* kRaceSummaryExt = ".race";        // per-cup rolling summary
static const char* kGridExt = ".grid";        // per-cup next-grid suggestion

// Classic 10-8-6-5-4-3-2-1 fallback
static const int kDefaultPoints[16] = {
    10, 8, 6, 5, 4, 3, 2, 1,
    0, 0, 0, 0, 0, 0, 0, 0
};

// Known literal used by RVGL’s session logger; we use it to locate the function.
static const char* kSessionFmtLiteral =
"profiles/session_%.4d-%.2d-%.2d_%.2d-%.2d-%.2d.log";

// ------------------------------- engine ABI (lazy-found) ------------------

using FnSessionOpen = void(*)(void);                        // FUN_00473c50 (heuristic)
using FnRvFPrintf = int (*)(void* f, const char* fmt, ...); // fprintf-like (heuristic)

static FnSessionOpen  g_RvSessionOpen = nullptr;
static FnRvFPrintf    g_RvFPrintf = nullptr;
static FnSessionOpen  g_Tramp_SessionOpen = nullptr;
static FnRvFPrintf    g_Tramp_FPrintf = nullptr;

static std::atomic<void*> g_CurrentSessionFile{ nullptr };

// ------------------------------- RVGL BuildGrid hook (local) -------------
// We mirror the addresses already used in opponentsmod so this TU can reorder
// the AI slot structs just before the game finalizes the grid.
static constexpr uint32_t RVA_FUN_BUILD_GRID = 0x00449DC0;   // FUN_00449DC0
static constexpr uint32_t RVA_AI_SLOT0 = 0x006FBC90;    // first AI slot "struct"
static constexpr size_t   AI_SLOT_INTS = 0x25;          // dwords per struct
static constexpr size_t   AI_SLOT_STRIDE = AI_SLOT_INTS * sizeof(int);

// To detect how many drivers RVGL plans to use, read the live cup struct:
static constexpr uintptr_t ABS_PTR_ACTIVE_CUP = 0x0065EC60;  // PTR_DAT_0065EC60
static constexpr int       OFF_NUMCARS = 0x68;        // int NumCars at +0x68

// ------------------------------- StartGrid state --------------------------

enum class GridMode : int {
    VanillaRandomPlayerLast = 0,
    ReverseByTotal = 1,
    ReverseByPrevious = 2,
};

struct PlayerResult {
    std::string name;
    int place = -1;   // 1..N
    int points = 0;
    std::string car;
};

struct RaceResult {
    int raceIndex = 0;                       // 0-based
    std::vector<PlayerResult> results;       // place-sorted
};

static std::mutex                gMx;
static GridMode                  gMode = GridMode::VanillaRandomPlayerLast;
static std::string               gProfile;                 // active profile (may be empty -> fallback)
static std::string               gCupName;
static std::vector<int>          gCupPoints;               // size >= grid size
static std::vector<RaceResult>   gHistory;                 // races done in this cup
static std::set<fs::path>        gTempRaceFiles;           // files to delete on shutdown
static FILE* gMirror = nullptr;        // our race_log.txt mirror
static std::atomic<bool>         gCleanupArmed{ false };

// ------------------------------- helpers ----------------------------------

// Path utils (lightweight, UTF-8 friendly enough for our use)
static std::string parent_dir(std::string p) {
    if (!p.empty() && (p.back() == '\\' || p.back() == '/')) p.pop_back();
    size_t pos = p.find_last_of("\\/");
    return (pos == std::string::npos) ? p : p.substr(0, pos);
}
static std::string exe_dir() {
    char buf[MAX_PATH]{ 0 };
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (char* s = strrchr(buf, '\\')) *s = 0;
    return std::string(buf);
}
static inline bool dir_exists(const std::string& p) {
    DWORD a = GetFileAttributesA(p.c_str());
    return (a != INVALID_FILE_ATTRIBUTES) && (a & FILE_ATTRIBUTE_DIRECTORY);
}
static void ensure_dir(const char* path) {
    char tmp[MAX_PATH]; strncpy(tmp, path, MAX_PATH - 1); tmp[MAX_PATH - 1] = 0;
    for (char* p = tmp + 1; *p; ++p) {
        if (*p == '\\' || *p == '/') { char c = *p; *p = 0; _mkdir(tmp); *p = c; }
    }
    _mkdir(tmp);
}

static std::string_view Basename(std::string_view path) {
    size_t pos = path.find_last_of("/\\");
    if (pos == std::string_view::npos) return path;
    return path.substr(pos + 1);
}

static void ArmCleanup() {
    if (gCleanupArmed.exchange(true)) return;
    // We rely on Shutdown() on DLL detach.
}

// Resolve logs base (RVGL\packs\rvgl_assets\cups\cupgen\cupgen_logs)
static inline fs::path LogsBase() {
    return fs::path(CupGen::CupGenLogsDir());
}

// Per-cup helper paths (use the current gCupName or fallback)
static inline std::string CurrentCupSafe() {
    return gCupName;
}
static inline fs::path RaceSummaryPath() { return LogsBase() / (CurrentCupSafe() + kRaceSummaryExt); }
static inline fs::path GridPath() { return LogsBase() / (CurrentCupSafe() + kGridExt); }
static inline fs::path CsvLogPath() { return LogsBase() / kRaceLogTxt; }

static std::string ReadWholeFile(const fs::path& p) {
    FILE* f = nullptr; fopen_s(&f, p.u8string().c_str(), "rb");
    if (!f) return {};
    std::string s; char buf[4096]; size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) s.append(buf, buf + n);
    fclose(f);
    // trim \r\n
    while (!s.empty() && (s.back() == '\r' || s.back() == '\n')) s.pop_back();
    return s;
}

// Prefer explicit SetProfile; else CUPGEN_PROFILE env; else cupgen\active_profile.txt; else "default"
static std::string ActiveProfileName() {
    {
        std::lock_guard<std::mutex> lk(gMx);
        if (!gProfile.empty()) return gProfile;
    }
    if (const char* env = std::getenv("CUPGEN_PROFILE")) {
        if (env && *env) return std::string(env);
    }
    fs::path ap = LogsBase().parent_path() / "active_profile.txt";
    std::string p = ReadWholeFile(ap);
    if (!p.empty()) return p;
    return "default";
}

static FILE* OpenMirrorAppend() {
    ensure_dir(CupGen::CupGenLogsDir().c_str());
    FILE* f = nullptr;
    auto p = CsvLogPath();
    ::fopen_s(&f, p.u8string().c_str(), "ab");
    return f;
}

static void CloseMirror() {
    if (gMirror) {
        ::fflush(gMirror);
        ::fclose(gMirror);
        gMirror = nullptr;
    }
}

static std::string& Trim(std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    size_t b = s.find_last_not_of(" \t\r\n");
    if (a == std::string::npos) { s.clear(); return s; }
    s = s.substr(a, b - a + 1);
    return s;
}

// CSV block parser (Results,"Track",N + rows)
struct CsvState {
    bool inCsv = false;
    int expectRows = 0;
    int collected = 0;
    int raceCounter = 0;
    std::vector<std::string> names;
};

// Active cup helpers (copied locally to avoid cross-TU deps)
static inline uint8_t* sg_active_cup() {
    return *reinterpret_cast<uint8_t**>(ABS_PTR_ACTIVE_CUP);
}
static inline int sg_cup_numcars() {
    if (auto* c = sg_active_cup()) return *reinterpret_cast<int*>(c + OFF_NUMCARS);
    return 0;
}

// Swap two AI slot "structs" (0x25 dwords each). Safe even if n is small.
static void SwapAiSlotStructs(uintptr_t base, size_t a, size_t b) {
    if (a == b) return;
    uint32_t tmp[AI_SLOT_INTS];
    uint32_t* pa = reinterpret_cast<uint32_t*>(base + a * AI_SLOT_STRIDE);
    uint32_t* pb = reinterpret_cast<uint32_t*>(base + b * AI_SLOT_STRIDE);
    memcpy(tmp, pa, sizeof(tmp));
    memcpy(pa, pb, sizeof(tmp));
    memcpy(pb, tmp, sizeof(tmp));
}

// Apply reverse grid policy (simple and deterministic):
// - Leave player (slot 0) alone.
// - Reverse the order of AI slot structs [1..N-1] in memory.
// This works as a generic "leader-last" effect because FUN_00449DC0 will
// iterate slots in order after we reshuffle them.
static void ApplyReverseGridIfWanted() {
    // Only apply if StartGrid mode requests reversing
    if (gMode == GridMode::VanillaRandomPlayerLast) return;

    // Determine how many cars RVGL will spawn
    int numCars = sg_cup_numcars();
    if (numCars <= 1) return;

    // Clamp: player is slot 0, then up to 15 AI (slots 1..15)
    size_t nAi = (size_t)std::min(std::max(numCars - 1, 0), 15);
    if (nAi == 0) return;

    uintptr_t aiBase = AbsFromMaybeRva(RVA_AI_SLOT0);
    if (!aiBase) { logf("StartGrid: AI slot base null"); return; }

    // Basic page/writeability sanity check
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery((void*)aiBase, &mbi, sizeof(mbi)) != sizeof(mbi) ||
        mbi.State != MEM_COMMIT ||
        !(mbi.Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY))) {
        logf("StartGrid: AI slot area not writable @%p", (void*)aiBase);
        return;
    }

    // Reverse AI slots [1..nAi] → that is logical indices [0..nAi-1] in this buffer.
    // We only touch AI (skip player-at-0).
    for (size_t i = 0; i < nAi / 2; ++i) {
        size_t a = i;             // AI logical index from front
        size_t b = nAi - 1 - i;   // AI logical index from back
        SwapAiSlotStructs(aiBase, a, b);
    }

    logf("StartGrid: reversed AI order for %zu opponents (mode=%d)", nAi, (int)gMode);
}

// ------------------------------- points / parsing -------------------------

// Points lookup (place is 1-based). Returns 0 if out of range.
static int PointsForPlace(int place) {
    if (place <= 0) return 0;
    if ((size_t)place <= gCupPoints.size()) return gCupPoints[place - 1];
    if (place <= 16) return kDefaultPoints[place - 1];
    return 0;
}

// Build or replace points scheme from a "Points = a,b,c,..." string
static void SetPointsFromString(const std::string& csv) {
    std::lock_guard<std::mutex> lk(gMx);
    gCupPoints.clear();
    int v = 0;
    bool have = false;
    for (char ch : csv) {
        if (ch >= '0' && ch <= '9') { v = v * 10 + (ch - '0'); have = true; continue; }
        if (ch == ',' || ch == ';' || ch == ' ') {
            if (have) { gCupPoints.push_back(v); v = 0; have = false; }
            continue;
        }
    }
    if (have) gCupPoints.push_back(v);
    if (gCupPoints.empty()) {
        for (int i = 0; i < 16; i++) gCupPoints.push_back(kDefaultPoints[i]);
    }
}

// ------------------------------- mirror writer ---------------------------

static bool TryParseResultLine(const char* line, RaceResult& out) {
    if (!line || !*line) return false;

    // legacy "Result #d: 1) Name  2) Name ..." (optional)
    {
        const char* p = ::strstr(line, "Result");
        if (!p) p = ::strstr(line, "Finish");
        if (p) {
            int r = 0;
            if (const char* hash = ::strchr(p, '#')) {
                r = ::strtol(hash + 1, nullptr, 10);
                if (r > 0) r--;
            }
            std::vector<std::string> names;
            const char* q = p;
            while ((q = ::strchr(q, ')'))) {
                const char* t = q - 1;
                while (t >= line && *t >= '0' && *t <= '9') t--;
                if (t < line || *t != ' ') { q++; continue; }
                int place = ::strtol(t + 1, nullptr, 10);
                const char* nameStart = q + 1;
                while (*nameStart == ' ' || *nameStart == '\t') nameStart++;
                const char* nameEnd = nameStart;
                while (*nameEnd && !(nameEnd[0] == ' ' && nameEnd[1] == ' ')) nameEnd++;
                std::string nm(nameStart, nameEnd);
                Trim(nm);
                if (!nm.empty()) {
                    if ((int)names.size() < place) names.resize(place);
                    names[place - 1] = nm;
                }
                q = nameEnd;
            }
            if (!names.empty()) {
                out.raceIndex = r;
                out.results.clear();
                for (size_t i = 0; i < names.size(); ++i) {
                    PlayerResult pr; pr.name = names[i]; pr.place = (int)i + 1; pr.points = PointsForPlace(pr.place);
                    out.results.push_back(std::move(pr));
                }
                return true;
            }
        }
    }

    size_t len = ::strlen(line);
    while (len && (line[len - 1] == '\r' || line[len - 1] == '\n')) --len;

    auto starts_with = [&](const char* kw) -> bool {
        size_t k = ::strlen(kw);
        return len >= k && ::memcmp(line, kw, k) == 0;
        };
    return false;
}

static void MirrorWrite(const char* fmt, va_list ap) {
    if (!fmt) return;

    if (!gMirror) {
        gMirror = OpenMirrorAppend();
        if (!gMirror) return;
    }

    char buf[4096];
    int n = _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    if (n <= 0) return;

    fwrite(buf, 1, (size_t)n, gMirror);
    fflush(gMirror);

    RaceResult rr;
    if (TryParseResultLine(buf, rr)) {
        std::lock_guard<std::mutex> lk(gMx);

        for (auto& pr : rr.results) pr.points = PointsForPlace(pr.place);

        if ((int)gHistory.size() <= rr.raceIndex) gHistory.resize(rr.raceIndex + 1);
        gHistory[rr.raceIndex] = std::move(rr);

        ensure_dir(CupGen::CupGenLogsDir().c_str());
        fs::path p = RaceSummaryPath();
        FILE* rf = nullptr;
        fopen_s(&rf, p.u8string().c_str(), "wb");
        if (rf) {
            const std::string prof = ActiveProfileName();
            const std::string cup = CurrentCupSafe();
            fprintf(rf, "PROFILE=%s\n", prof.c_str());
            fprintf(rf, "CUP=%s\n", cup.c_str());
            fprintf(rf, "POINTS=");
            if (!gCupPoints.empty()) {
                for (size_t i = 0; i < gCupPoints.size(); ++i) {
                    if (i) fputc(',', rf);
                    fprintf(rf, "%d", gCupPoints[i]);
                }
            }
            else {
                for (int i = 0; i < 16; ++i) {
                    if (i) fputc(',', rf);
                    fprintf(rf, "%d", kDefaultPoints[i]);
                }
            }
            fputc('\n', rf);

            for (size_t i = 0; i < gHistory.size(); ++i) {
                const auto& r = gHistory[i];
                if (r.results.empty()) continue;
                fprintf(rf, "RACE=%u\n", (unsigned)(i + 1));
                for (const auto& pr : r.results) {
                    fprintf(rf, "  %2d) %s | PTS=%d\n", pr.place, pr.name.c_str(), pr.points);
                }
            }
            fclose(rf);
            gTempRaceFiles.insert(p);
            ArmCleanup();
        }
    }
}

// ----------------------------- grid reordering ----------------------------

static std::vector<std::pair<std::string, int>> Totals() {
    std::vector<std::pair<std::string, int>> totals;
    std::map<std::string, int> acc;
    for (const auto& r : gHistory) {
        for (const auto& pr : r.results) acc[pr.name] += pr.points;
    }
    totals.reserve(acc.size());
    for (auto& kv : acc) totals.emplace_back(kv.first, kv.second);
    return totals;
}

static void WriteNextGridSuggestion(int nextRaceIndex) {
    if (gMode == GridMode::VanillaRandomPlayerLast) {
        std::error_code ec; fs::remove(GridPath(), ec);
        return;
    }

    std::vector<std::string> order;

    if (gMode == GridMode::ReverseByPrevious) {
        if (nextRaceIndex == 0) { order.clear(); }
        else if (nextRaceIndex - 1 < (int)gHistory.size() && !gHistory[nextRaceIndex - 1].results.empty()) {
            for (auto& pr : gHistory[nextRaceIndex - 1].results) order.push_back(pr.name);
        }
    }
    else if (gMode == GridMode::ReverseByTotal) {
        if (nextRaceIndex == 0) { order.clear(); }
        else {
            auto totals = Totals();
            std::sort(totals.begin(), totals.end(), [](auto& a, auto& b) {
                if (a.second != b.second) return a.second > b.second; // higher points first
                return a.first < b.first;
                });
            for (auto& kv : totals) order.push_back(kv.first);
        }
    }

    if (order.empty()) {
        std::error_code ec; fs::remove(GridPath(), ec);
        return;
    }

    std::reverse(order.begin(), order.end()); // leader last

    ensure_dir(CupGen::CupGenLogsDir().c_str());
    fs::path p = GridPath();
    FILE* f = nullptr; fopen_s(&f, p.u8string().c_str(), "wb");
    if (!f) return;

    const std::string prof = ActiveProfileName();
    fprintf(f, "PROFILE=%s\n", prof.c_str());
    fprintf(f, "MODE=%d\n", (int)gMode);
    fprintf(f, "NEXTRACE=%d\n", (int)(nextRaceIndex + 1));
    for (size_t i = 0; i < order.size(); ++i) {
        fprintf(f, "%u) %s\n", (unsigned)(i + 1), order[i].c_str());
    }
    fclose(f);
    gTempRaceFiles.insert(p);
}

// Very light-weight scan for a string literal inside readable memory pages.
static void* FindReadableRange(const char* needle, size_t nlen) {
    SYSTEM_INFO si; GetSystemInfo(&si);
    const uint8_t* p = reinterpret_cast<const uint8_t*>(si.lpMinimumApplicationAddress);
    const uint8_t* maxp = reinterpret_cast<const uint8_t*>(si.lpMaximumApplicationAddress);

    MEMORY_BASIC_INFORMATION mbi{};
    for (; p < maxp; ) {
        if (VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
        const bool ok = (mbi.State == MEM_COMMIT) &&
            (mbi.Protect == PAGE_READONLY ||
                mbi.Protect == PAGE_READWRITE ||
                mbi.Protect == PAGE_EXECUTE_READ ||
                mbi.Protect == PAGE_EXECUTE_READWRITE);
        if (ok) {
            const uint8_t* start = reinterpret_cast<const uint8_t*>(mbi.BaseAddress);
            const uint8_t* end = start + mbi.RegionSize;
            for (const uint8_t* s = start; s + nlen < end; ++s) {
                if (std::memcmp(s, needle, nlen) == 0) {
                    return const_cast<uint8_t*>(s);
                }
            }
        }
        p += mbi.RegionSize;
    }
    return nullptr;
}

// We keep it intentionally permissive; worst case, install fails and we proceed without mirroring.
static void TryLocateSessionOpenByString() {
    if (g_RvSessionOpen) return;
    void* pStr = FindReadableRange(kSessionFmtLiteral, strlen(kSessionFmtLiteral));
    if (!pStr) {
        logf("StartGrid: cannot find session literal; mirroring disabled.");
        return;
    }

    SYSTEM_INFO si; GetSystemInfo(&si);
    uint8_t* p = reinterpret_cast<uint8_t*>(si.lpMinimumApplicationAddress);
    MEMORY_BASIC_INFORMATION mbi{};
    for (; p < (uint8_t*)si.lpMaximumApplicationAddress; ) {
        if (VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
        bool exec = (mbi.State == MEM_COMMIT) &&
            (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE);
        if (exec) {
            uint8_t* s = (uint8_t*)mbi.BaseAddress;
            uint8_t* e = s + mbi.RegionSize;
            for (; s + 8 < e; ++s) {
                // quick check: RIP-relative LEA of the literal (48 8D 15 ? ? ? ?)
                if (s[0] == 0x48 && s[1] == 0x8D && s[2] == 0x15) {
                    int32_t rel = *(int32_t*)(s + 3);
                    uint8_t* tgt = s + 7 + rel;
                    if (tgt == pStr) {
                        // backtrack to nearby function start (align-ish)
                        uint8_t* fn = s;
                        for (int k = 0; k < 64 && fn >(uint8_t*)mbi.BaseAddress; ++k, --fn) {
                            if ((fn[0] == 0x40 && (fn[1] == 0x53 || fn[1] == 0x55)) || fn[0] == 0x55) {
                                g_RvSessionOpen = (FnSessionOpen)fn;
                                logf("StartGrid: SessionOpen @ %p", fn);
                                return;
                            }
                        }
                    }
                }
            }
        }
        p += mbi.RegionSize;
    }
}

static void TryLocateRvFPrintfNearSession() {
    if (g_RvFPrintf) return;
    if (!g_RvSessionOpen) return;

    // Scan forward in SessionOpen for a CALL to a printf-like wrapper.
    uint8_t* pc = (uint8_t*)g_RvSessionOpen;
    for (int i = 0; i < 0x300; ++i) {
        if (pc[i] == 0xE8) { // CALL rel32
            int32_t rel = *(int32_t*)(pc + i + 1);
            uint8_t* tgt = pc + i + 5 + rel;
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(tgt, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                if (mbi.State == MEM_COMMIT &&
                    (mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE)) {
                    g_RvFPrintf = (FnRvFPrintf)tgt;
                    logf("StartGrid: printf-like @ %p", g_RvFPrintf);
                    return;
                }
            }
        }
    }
}

// ------------------------------- detour prototypes ------------------------
static int  __cdecl Hook_RvFPrintf(void* f, const char* fmt, ...);
static void __cdecl Hook_SessionOpen();

// ------------------------------ API (StartGridMod) ------------------------

using FnBuildGrid = void(*)();   // FUN_00449DC0 signature compatible
static FnBuildGrid g_Tramp_BuildGrid = nullptr;

void StartGridMod::PreBuildGrid() {
    // Reorder AI slot structs [1..N-1] according to the selected mode.
    ApplyReverseGridIfWanted();
}

// Our detour: apply grid reshuffle *before* the game finalizes the grid.
static void __cdecl Hook_BuildGrid() {
    // Make our change first so the game picks it up
    ApplyReverseGridIfWanted();

    // Call original
    if (g_Tramp_BuildGrid) g_Tramp_BuildGrid();
}

bool StartGridMod::Install() {
    // Ensure default points
    {
        std::lock_guard<std::mutex> lk(gMx);
        gCupPoints.assign(kDefaultPoints, kDefaultPoints + 16);
    }
    logf("StartGrid: logs base = %s", CupGen::CupGenLogsDir().c_str());

    TryLocateSessionOpenByString();
    TryLocateRvFPrintfNearSession();

    if (g_RvSessionOpen) {
        if (HookFunctionPtr((void*)g_RvSessionOpen, (void*)Hook_SessionOpen, (void**)&g_Tramp_SessionOpen)) {
            logf("StartGrid: Hooked SessionOpen");
        }
        else {
            logf("StartGrid: Hook SessionOpen FAILED");
        }
    }
    else {
        logf("StartGrid: SessionOpen not found; still running without mirroring.");
    }

    if (g_RvFPrintf) {
        if (HookFunctionPtr((void*)g_RvFPrintf, (void*)Hook_RvFPrintf, (void**)&g_Tramp_FPrintf)) {
            logf("StartGrid: Hooked fprintf-like");
        }
        else {
            logf("StartGrid: Hook fprintf-like FAILED");
        }
    }
    else {
        logf("StartGrid: fprintf-like not found; still running without mirroring.");
    }

    logf("StartGrid: Install OK (mode=%d).", (int)gMode);
    return true;

    {
        const uintptr_t buildAbs = AbsFromMaybeRva(RVA_FUN_BUILD_GRID);
        if (buildAbs) {
            if (HookFunction(buildAbs, (LPVOID)&Hook_BuildGrid, (LPVOID*)&g_Tramp_BuildGrid)) {
                logf("StartGrid: Hooked BuildGrid @%p", (void*)buildAbs);
            }
            else {
                logf("StartGrid: Hook BuildGrid FAILED @%p", (void*)buildAbs);
            }
        }
    }
}

void StartGridMod::Shutdown() {
    for (const auto& p : gTempRaceFiles) {
        std::error_code ec; fs::remove(p, ec);
    }
    gTempRaceFiles.clear();
    CloseMirror();
}

void StartGridMod::SetMode(int m) {
    std::lock_guard<std::mutex> lk(gMx);
    if (m == 1) gMode = GridMode::ReverseByTotal;
    else if (m == 2) gMode = GridMode::ReverseByPrevious;
    else             gMode = GridMode::VanillaRandomPlayerLast;
    logf("StartGrid: mode set to %d", (int)gMode);
}

void StartGridMod::SetCupName(const char* cupName) {
    std::lock_guard<std::mutex> lk(gMx);
    gCupName = cupName;
}

void StartGridMod::SetPointsCsv(const char* csv) {
    SetPointsFromString(csv ? csv : "");
    logf("StartGrid: points = %s", csv ? csv : "(default)");
}

void StartGridMod::SetProfile(const char* profile) {
    std::lock_guard<std::mutex> lk(gMx);
    gProfile = profile ? profile : "";
}

void StartGridMod::OnStartCup() {
    std::lock_guard<std::mutex> lk(gMx);
    gHistory.clear();
    CloseMirror(); // start fresh log file for this cup
    logf("StartGrid: OnStartCup (profile=%s, cup=%s, mode=%d)",
        ActiveProfileName().c_str(), CurrentCupSafe().c_str(), (int)gMode);

    std::error_code ec;
    fs::remove(RaceSummaryPath(), ec);
    fs::remove(GridPath(), ec);
    std::error_code ec2;
    fs::remove(fs::path(CupGen::CupGenLogsDir()) / "race_log.txt", ec2);
}

void StartGridMod::OnRaceFinished(int justFinishedRaceIndex) {
    WriteNextGridSuggestion(justFinishedRaceIndex + 1);
}

void StartGridMod::OnSessionFile(void* rvFileHandle) {
    g_CurrentSessionFile.store(rvFileHandle);
}

// Set cup id from a resolved cup path (friendly name)
void StartGridMod::NotifyActiveCup(const char* cupPathResolved) {
    if (cupPathResolved && *cupPathResolved) {
        std::string base(Basename(cupPathResolved));
        size_t dot = base.find_last_of('.');
        if (dot != std::string::npos) base.resize(dot);
        SetCupName(base.c_str());
    }
}

// Fallback logger if engine mirroring is unavailable
void StartGridMod::LogLine(const char* fmt, ...) {
    if (!fmt) return;

    if (!gMirror) {
        gMirror = OpenMirrorAppend();
        if (!gMirror) return;
    }

    char buf[4096];
    va_list ap; va_start(ap, fmt);
    int n = _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    if (n <= 0) return;

    fwrite(buf, 1, (size_t)n, gMirror);
    fflush(gMirror);

    RaceResult rr;
    if (TryParseResultLine(buf, rr)) {
        std::lock_guard<std::mutex> lk(gMx);

        for (auto& pr : rr.results) pr.points = PointsForPlace(pr.place);

        if ((int)gHistory.size() <= rr.raceIndex) gHistory.resize(rr.raceIndex + 1);
        gHistory[rr.raceIndex] = std::move(rr);

        ensure_dir(CupGen::CupGenLogsDir().c_str());
        fs::path p = RaceSummaryPath();
        if (FILE* rf = nullptr; fopen_s(&rf, p.u8string().c_str(), "wb"), rf) {
            const std::string prof = ActiveProfileName();
            const std::string cup = CurrentCupSafe();
            fprintf(rf, "PROFILE=%s\n", prof.c_str());
            fprintf(rf, "CUP=%s\n", cup.c_str());
            fprintf(rf, "POINTS=");
            if (!gCupPoints.empty()) {
                for (size_t i = 0; i < gCupPoints.size(); ++i) {
                    if (i) fputc(',', rf);
                    fprintf(rf, "%d", gCupPoints[i]);
                }
            }
            else {
                for (int i = 0; i < 16; ++i) {
                    if (i) fputc(',', rf);
                    fprintf(rf, "%d", kDefaultPoints[i]);
                }
            }
            fputc('\n', rf);

            for (size_t i = 0; i < gHistory.size(); ++i) {
                const auto& r = gHistory[i];
                if (r.results.empty()) continue;
                fprintf(rf, "RACE=%zu\n", i + 1);
                for (const auto& pr : r.results)
                    fprintf(rf, "  %2d) %s | PTS=%d\n", pr.place, pr.name.c_str(), pr.points);
            }
            fclose(rf);
            gTempRaceFiles.insert(p);
            ArmCleanup();
        }
    }
}

// ------------------------------- detours ----------------------------------

static int __cdecl Hook_RvFPrintf(void* f, const char* fmt, ...) {
    va_list ap1; va_start(ap1, fmt);
    va_list ap2; ap2 = ap1; // MSVC ok
    int r = g_Tramp_FPrintf ? g_Tramp_FPrintf(f, fmt, ap1) : 0;
    va_end(ap1);
    if (f && f == g_CurrentSessionFile.load()) {
        MirrorWrite(fmt, ap2);
    }
    return r;
}

static void __cdecl Hook_SessionOpen() {
    if (g_Tramp_SessionOpen) g_Tramp_SessionOpen();
    CloseMirror();
    gMirror = OpenMirrorAppend();
    if (gMirror) {
        const char sep[] = "================ NEW SESSION ================\n";
        fwrite(sep, 1, sizeof(sep) - 1, gMirror);
        fflush(gMirror);
    }
}