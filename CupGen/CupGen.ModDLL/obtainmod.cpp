// obtainmod.cpp
// CupGen "ObtainCustom" gating + temp-based series tracking for RVGL (verbose debug)
// Build: x64, /std:c++17
// Requires: core.h providing HookFunction, AbsFromMaybeRva, logf

#define NOMINMAX
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <direct.h>
#include <windows.h>
#include <unordered_map>
#include "core.h"       // HookFunction, AbsFromMaybeRva, logf
#include "obtainmod.h"
#include "CupGenGlobals.h"
#include <thread>
#include "addresses.h"    // HookAddrs + extern g_addrs

#ifndef MAX_PATH
#define MAX_PATH 260
#endif

// ======================================================
//               RVAs / ABSOLUTE ADDRESSES
// ======================================================

// All function RVAs now come from g_addrs (populated by update.json → scanner → fallbacks).
// Note: our PAT_CUPPARSE actually anchors the StartCup entry (0x0044BB80 in your dump).
static inline uintptr_t ABS_FN_START_CUP() { return AbsFromMaybeRva(g_addrs.rva_CupParse); }
static inline uintptr_t ABS_FN_RACE_RESULTS() { return AbsFromMaybeRva(g_addrs.rva_RaceResults); }
static inline uintptr_t ABS_FN_CUP_FINALIZE() { return AbsFromMaybeRva(g_addrs.rva_CupFinalize); }

// Globals (RVA -> ABS)
static inline void** PP_ACTIVE_CUP() { return reinterpret_cast<void**>(AbsFromMaybeRva(g_addrs.rva_ActiveCupPtr)); }
static inline uint8_t* PLAYERS_BASE() { return reinterpret_cast<uint8_t*>(AbsFromMaybeRva(g_addrs.rva_PlayersBase)); }
static inline int* PLAYERS_COUNT() { return reinterpret_cast<int*>(AbsFromMaybeRva(g_addrs.rva_PlayersCount)); }

// Offsets inside the cup struct (unchanged)
static constexpr int OFF_NAME = 0x00;
static constexpr int OFF_CUP_ID = 0x20;
static constexpr int OFF_DIFFICULTY = 0x64;
static constexpr int OFF_NUMCARS = 0x68;
static constexpr int OFF_MAXSTAGES = 0x78;
static constexpr int OFF_POINTS = 0x154;
static constexpr int OFF_LOCKBYTE = 0x195;

// Player struct (for profile-name match)
static constexpr int OFF_PLAYER_NAME = 0x6A70;

// ======================================================
//                     State (process-wide)
// ======================================================

static std::string g_activeCupPath;
static std::string g_activeCupId;
static std::string g_activeProfile;

static std::unordered_map<std::string, bool> g_unlockCache; // cupId -> last known unlocked?

// Vanilla obtain (kept inert but parsed for completeness)
static int                      g_activeObtain = 0;
static std::vector<std::string> g_obtainArgs;

// ObtainCustom (our gate)
static bool                     g_hasObtainCustom = false;
static int                      g_activeObtainCustom = 0;
static std::vector<std::string> g_obtainCustomArgs;

// ======================================================
//                    Small utils / fs
// ======================================================

static inline int selected_index() {
    auto p = *reinterpret_cast<uint8_t**>(0x006A7910);
    return p ? *reinterpret_cast<int*>(p + 4) : 0;
}
static inline uint8_t* selected_cup_ptr_from_index(int idx) {
    if (idx > 4) {
        auto list = *reinterpret_cast<uint8_t**>(0x006FBBC8); // custom cups array
        return list ? (list + (idx - 4) * 0x198) : nullptr;
    }
    else {
        return reinterpret_cast<uint8_t*>(0x0065F4A0) + idx * 0x198; // built-ins
    }
}
static inline const char* cup_id_from_ptr(uint8_t* cup) {
    return cup ? reinterpret_cast<const char*>(cup + OFF_CUP_ID) : nullptr; // +0x20
}

static inline void ensure_dir(const char* path) {
    char tmp[MAX_PATH]; strncpy(tmp, path, MAX_PATH - 1); tmp[MAX_PATH - 1] = 0;
    for (char* p = tmp + 1; *p; ++p) {
        if (*p == '\\' || *p == '/') { char c = *p; *p = 0; _mkdir(tmp); *p = c; }
    }
    _mkdir(tmp);
}

static inline bool dir_exists(const std::string& p) {
    DWORD a = GetFileAttributesA(p.c_str());
    return (a != INVALID_FILE_ATTRIBUTES) && (a & FILE_ATTRIBUTE_DIRECTORY);
}

static std::string exe_dir() {
    char buf[MAX_PATH]{ 0 }; GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (char* s = strrchr(buf, '\\')) *s = 0;
    return std::string(buf);
}

static std::string join2(const std::string& a, const char* b) {
    if (a.empty()) return b ? b : "";
    return a + "\\" + (b ? b : "");
}

static std::string parent_dir(std::string p) {
    if (!p.empty() && (p.back() == '\\' || p.back() == '/')) p.pop_back();
    size_t pos = p.find_last_of("\\/"); return (pos == std::string::npos) ? p : p.substr(0, pos);
}

// Case-insensitive find of subpath
static size_t ifind(const std::string& hay, const char* needle) {
    std::string h = hay, n = (needle ? needle : "");
    std::transform(h.begin(), h.end(), h.begin(), ::tolower);
    std::transform(n.begin(), n.end(), n.begin(), ::tolower);
    return h.find(n);
}

// Folders (now trivial)
static inline std::string cups_base_dir() { return CupGen::CupsDir(); }
static inline std::string logs_dir() { return CupGen::CupGenLogsDir(); }
static inline std::string profile_cfg_path() { return CupGen::CupGenDir() + "\\active_profile.txt"; }
static inline std::string profiles_base_dir() { return CupGen::ProfilesBase(); }

static std::string level_path(const std::string& profile, const std::string& trackId) {
    return profiles_base_dir() + "\\" + profile + "\\" + trackId + ".level";
}

// Simple file read (active_profile.txt)
static std::string read_text_file(const std::string& p) {
    FILE* f = fopen(p.c_str(), "rb"); if (!f)
        return {};
    char buf[256]; size_t n = fread(buf, 1, sizeof(buf) - 1, f); fclose(f);
    while (n && (buf[n - 1] == '\r' || buf[n - 1] == '\n' || buf[n - 1] == ' ' || buf[n - 1] == '\t')) --n;
    buf[n] = 0;
    return std::string(buf);
}

// One-shot latch so we only set the path once per session (optional)
static bool g_cupResolvedOnce = false;

static inline const char* cup_id_from_struct(void* cupStruct) {
    if (!cupStruct) return nullptr;
    return reinterpret_cast<const char*>(reinterpret_cast<uint8_t*>(cupStruct) + OFF_CUP_ID); // +0x20
}

// --- Minimal parser that only fills selector-visible fields ---
static void MiniParseForMenu(void* cupStruct, const char* cupPath)
{
    if (!cupStruct || !cupPath || !*cupPath) return;

    FILE* f = std::fopen(cupPath, "rb");
    if (!f)
        return;

    char* c = reinterpret_cast<char*>(cupStruct);

    // Clean defaults
    *reinterpret_cast<int*>(c + OFF_DIFFICULTY) = 1;
    *reinterpret_cast<int*>(c + OFF_MAXSTAGES) = 0;

    std::string cupName, unlockTracks;
    int stageCount = 0;

    char line[1024];
    while (std::fgets(line, sizeof(line), f)) {
        if (char* sc = std::strchr(line, ';')) *sc = 0;

        char key[64]{};
        const char* val = nullptr;

        // basic key/val split
        char* p = line;
        while (*p == ' ' || *p == '\t') ++p;
        char* k = p;
        while (*p && *p != ' ' && *p != '\t' && *p != '=') ++p;
        size_t klen = (size_t)(p - k);
        if (klen == 0 || klen >= sizeof(key)) continue;

        std::memcpy(key, k, klen); key[klen] = 0;
        for (char* q = key; *q; ++q) if (*q >= 'A' && *q <= 'Z') *q += 32;

        while (*p == ' ' || *p == '\t') ++p;
        if (*p == '=') ++p;
        while (*p == ' ' || *p == '\t') ++p;
        val = p;

        if (std::strcmp(key, "name") == 0) {
            std::string v = val ? val : "";
            v.erase(0, v.find_first_not_of(" \t\r\n\"'"));
            v.erase(v.find_last_not_of(" \t\r\n\"'") + 1);
            cupName = v;
        }
        else if (std::strcmp(key, "stage") == 0) {
            stageCount++;
            // capture track name (2nd token if index present, else 1st)
            std::string v = val ? val : "";
            auto toks = std::vector<std::string>();
            {
                char* ctx = nullptr;
                char* tok = strtok_s(v.data(), " \t\r\n", &ctx);
                while (tok) { toks.emplace_back(tok); tok = strtok_s(nullptr, " \t\r\n", &ctx); }
            }
            if (!toks.empty()) {
                std::string track = toks.size() >= 5 ? toks[1] : toks[0];
                if (!unlockTracks.empty()) unlockTracks += ", ";
                unlockTracks += track;
            }
        }
    }
    fclose(f);

    // --- Build compact locked display name (Difficulty untouched) ---
    std::string finalName = cupName.empty() ? "Custom Cup" : cupName;

    // Write back to 32-byte NAME field (31 chars + NUL), like original does
    {
        const size_t cap = 31;
        size_t n = finalName.size();
        if (n > cap) n = cap;
        if (n) std::memcpy(c + OFF_NAME, finalName.c_str(), n);
        // zero-rest + force NUL at [0x1F]
        std::memset(c + OFF_NAME + n, 0, 32 - n);
        *(c + OFF_NAME + 0x1F) = 0;
    }

    // Optional: hint bit often used by UI to show a lock / needs-gen badge
    c[OFF_LOCKBYTE] = 1;
}

// Read Difficulty and Stage count from a .cup file
static bool ParseDiffAndStageCount(const char* cupPath, int& outDiff, int& outStages) {
    outDiff = 1;
    outStages = 0;
    if (!cupPath || !*cupPath) return false;

    FILE* f = std::fopen(cupPath, "rb");
    if (!f)
        return false;

    char line[1024];
    while (std::fgets(line, sizeof(line), f)) {
        if (char* sc = std::strchr(line, ';')) *sc = 0;

        // trim left
        char* p = line; while (*p == ' ' || *p == '\t') ++p;
        if (!*p) continue;

        // lowercase key
        char key[32] = { 0 };
        char val[960] = { 0 };
        if (std::sscanf(p, " %31[^= \t] = %959[^\n]", key, val) == 2 ||
            std::sscanf(p, " %31s %959[^\n]", key, val) == 2) {
            for (char* q = key; *q; ++q) if (*q >= 'A' && *q <= 'Z') *q += 32;
            if (std::strcmp(key, "difficulty") == 0) {
                int d = 1;
                if (std::sscanf(val, "%d", &d) == 1) outDiff = d;
            }
            else if (std::strcmp(key, "stage") == 0) {
                ++outStages;
            }
        }
    }
    std::fclose(f);
    return true;
}

// ===== Menu memory helpers =====

// Menu state block: *(0x006A7910) points to a struct where [ +4 ] is current selection index
static inline uint8_t* menu_state_ptr() {
    return *reinterpret_cast<uint8_t**>(0x006A7910);
}

// Builtin cups base (fixed) and stride; customs list pointer and same stride
static inline uint8_t* builtin_cups_base() { return reinterpret_cast<uint8_t*>(0x0065F4A0); }
static inline uint8_t* custom_cups_base() { return *reinterpret_cast<uint8_t**>(0x006FBBC8); }
static constexpr int   CUP_STRIDE = 0x198;

// Read cup id field
static inline const char* cup_id_from_struct(uint8_t* cup) {
    return cup ? reinterpret_cast<const char*>(cup + OFF_CUP_ID) : nullptr;
}

// Find a cup struct by id in builtin (first ~5) or custom list (scan until empty id)
static uint8_t* FindCupStructById(const char* targetId) {
    if (!targetId || !*targetId) return nullptr;

    // 1) Builtins: index 0..4 (safe, small)
    {
        uint8_t* base = builtin_cups_base();
        for (int i = 0; i < 5; ++i) {
            uint8_t* c = base + i * CUP_STRIDE;
            if (const char* id = cup_id_from_struct(c)) {
                if (*id && _stricmp(id, targetId) == 0) return c;
            }
        }
    }

    // 2) Customs: array at 0x006FBBC8; scan up to a sane cap (e.g. 512), stop at first empty id
    {
        uint8_t* base = custom_cups_base();
        if (base) {
            for (int i = 0; i < 512; ++i) {
                uint8_t* c = base + i * CUP_STRIDE;
                const char* id = cup_id_from_struct(c);
                if (!id || !*id) break; // reached end
                if (_stricmp(id, targetId) == 0) return c;
            }
        }
    }
    return nullptr;
}

// Nudge the selection index to force the UI to repaint the list entry.
// Safe no-op if menu state is missing.
static void ForceMenuRedrawBySelectionBounce() {
    uint8_t* st = menu_state_ptr();
    if (!st) return;
    int* pSel = reinterpret_cast<int*>(st + 4);
    const int old = *pSel;
    // bounce to a different index if possible
    const int alt = (old == 0) ? 1 : 0;
    *pSel = alt;
    *pSel = old;
}

// ========= Cup wins store: logs\wins\<cupId>.cup (text) =========
static inline std::string wins_dir() { return logs_dir() + "\\wins"; }
static inline std::string wins_path(const std::string& cupId) { return wins_dir() + "\\" + cupId + ".cup"; }

// Format: first line "CUPWIN1"
// Then either "Profiles: name1,name2,..." OR one profile per line ("name: <profile>")
static void write_win_for_profile(const std::string& cupId, const std::string& profile)
{
    if (cupId.empty() || profile.empty()) return;
    ensure_dir(wins_dir().c_str());

    // Read existing to de-dup
    std::string p = wins_path(cupId);
    std::vector<std::string> profiles;

    if (FILE* rf = std::fopen(p.c_str(), "rb")) {
        char line[512];
        bool header_ok = false;
        if (std::fgets(line, sizeof(line), rf)) {
            if (std::strncmp(line, "CUPWIN1", 7) == 0) header_ok = true;
        }
        // Accept files without header too (best effort)
        while (std::fgets(line, sizeof(line), rf)) {
            // Accept both “Profiles: a,b” and “name: a”
            char* s = line;
            while (*s == ' ' || *s == '\t') ++s;
            if (_strnicmp(s, "Profiles:", 9) == 0) {
                s += 9;
                // split by comma
                char* ctx = nullptr;
                for (char* tok = strtok_s(s, ",\r\n", &ctx); tok; tok = strtok_s(nullptr, ",\r\n", &ctx)) {
                    while (*tok == ' ' || *tok == '\t') ++tok;
                    if (*tok) profiles.emplace_back(tok);
                }
            }
            else if (_strnicmp(s, "name:", 5) == 0) {
                s += 5;
                while (*s == ' ' || *s == '\t') ++s;
                char* e = s + std::strlen(s);
                while (e > s && (e[-1] == '\r' || e[-1] == '\n')) --e;
                *e = 0;
                if (*s) profiles.emplace_back(s);
            }
        }
        std::fclose(rf);
        (void)header_ok;
    }

    // De-dup (case-insensitive)
    auto hasName = [&](const std::string& n) {
        for (auto& x : profiles) if (_stricmp(x.c_str(), n.c_str()) == 0) return true;
        return false;
        };
    if (!hasName(profile)) profiles.push_back(profile);

    // Atomic write
    char tmpPath[MAX_PATH];
    _snprintf(tmpPath, MAX_PATH, "%s.tmp", p.c_str());
    if (FILE* wf = std::fopen(tmpPath, "wb")) {
        std::fprintf(wf, "CUPWIN1\n");
        // Compact single line
        std::fprintf(wf, "Profiles: ");
        for (size_t i = 0; i < profiles.size(); ++i) {
            if (i) std::fputc(',', wf);
            std::fprintf(wf, "%s", profiles[i].c_str());
        }
        std::fputc('\n', wf);
        std::fclose(wf);
        MoveFileExA(tmpPath, p.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED | MOVEFILE_WRITE_THROUGH);
    }
}

static bool cup_was_won_by_profile(const std::string& cupId, const std::string& profile)
{
    if (cupId.empty() || profile.empty()) return false;

    // Back-compat: accept legacy logs_dir\<cupId>.log with CUPGEN1
    {
        const std::string legacy = logs_dir() + "\\" + cupId + ".log";
        if (FILE* f = std::fopen(legacy.c_str(), "rb")) {
            char magic[8]{};
            size_t n = std::fread(magic, 1, 7, f);
            std::fclose(f);
            if (n == 7 && std::memcmp(magic, "CUPGEN1", 7) == 0) {
                return true;
            }
        }
    }

    const std::string p = wins_path(cupId);
    FILE* f = std::fopen(p.c_str(), "rb");
    if (!f) {
        return false;
    }
    char line[512];
    bool header_ok = false;
    if (std::fgets(line, sizeof(line), f)) {
        if (std::strncmp(line, "CUPWIN1", 7) == 0) header_ok = true;
    }
    (void)header_ok;

    // Case-insensitive search for profile in either format
    bool found = false;
    const std::string targetLower = [&] {
        std::string t = profile; std::transform(t.begin(), t.end(), t.begin(), ::tolower); return t;
        }();
    while (std::fgets(line, sizeof(line), f)) {
        std::string s = line;
        std::transform(s.begin(), s.end(), s.begin(), ::tolower);
        if (s.find(targetLower) != std::string::npos) { found = true; break; }
    }
    std::fclose(f);
    return found;
}

// ======================================================
//          API to set cup/profile from CupGenerator
// ======================================================

namespace ObtainMod {
    void SetActiveCupContext(const char* cupPath, const char* cupId) {
        g_activeCupPath = cupPath ? cupPath : "";
        g_activeCupId = cupId ? cupId : "";
    }
    void SetActiveProfileName(const char* profileName) {
        g_activeProfile = profileName ? profileName : "";
    }
}

// ======================================================
//                 Profile & .level flags
// ======================================================

static std::string active_profile_name() {
    // Prefer the file so attaching to a running RVGL works reliably
    std::string fromFile = read_text_file(profile_cfg_path());
    if (!fromFile.empty()) {
        std::transform(fromFile.begin(), fromFile.end(), fromFile.begin(), ::tolower);
        return fromFile;
    }
    if (!g_activeProfile.empty()) {
        std::string p = g_activeProfile; std::transform(p.begin(), p.end(), p.begin(), ::tolower);
        return p;
    }
    return "default";
}

// Bits: TT N=0x01, TT R=0x02, TT M=0x04, Practice=0x08, Single=0x10
static bool read_level_flags(const std::string& trackId, uint16_t& outFlags) {
    const std::string prof = active_profile_name();
    const std::string p = level_path(prof, trackId);
    FILE* f = fopen(p.c_str(), "rb");
    if (!f) return false;

    if (fseek(f, 64, SEEK_SET) != 0) { fclose(f); return false; }

    uint8_t lo = 0, hi = 0;
    if (fread(&lo, 1, 1, f) != 1 || fread(&hi, 1, 1, f) != 1) { fclose(f); return false; }

    fclose(f);
    outFlags = static_cast<uint16_t>(lo | (static_cast<uint16_t>(hi) << 8));
    return true;
}

static inline bool level_has_practice_star(const std::string& t) {
    uint16_t f = 0; return read_level_flags(t, f) && (f & 0x0008);
}
static inline bool level_has_tt_normal(const std::string& t) {
    uint16_t f = 0; return read_level_flags(t, f) && (f & 0x0001);
}
static inline bool level_has_single_win(const std::string& t) {
    uint16_t f = 0; return read_level_flags(t, f) && (f & 0x0010);
}


// ======================================================
//                Cup log (CUPGEN1) helpers
// ======================================================

static bool check_cup_log_with_magic(const std::string& cupId) {
    const std::string p = logs_dir() + "\\" + cupId + ".log";
    FILE* f = fopen(p.c_str(), "rb");
    if (!f)
        return false;
    char magic[8]{}; size_t n = fread(magic, 1, 7, f); fclose(f);
    const bool ok = (n == 7 && std::memcmp(magic, "CUPGEN1", 7) == 0);
    return ok;
}
static void write_cupgen_log(const char* cupId) {
    if (!cupId || !*cupId) return;
    ensure_dir(logs_dir().c_str());
    std::string p = logs_dir() + "\\" + std::string(cupId) + ".log";
    FILE* f = fopen(p.c_str(), "wb"); if (!f)
        return;
    fwrite("CUPGEN1", 1, 7, f); fclose(f);
}

// ======================================================
//              Cup file parsing (Obtain/Custom)
// ======================================================

static inline char ci(char a) { return (a >= 'A' && a <= 'Z') ? (a + 32) : a; }

static bool starts_key(const char* p, const char* key, const char** outAfterKey) {
    int i = 0; while (key[i] && p[i] && ci(p[i]) == key[i]) ++i;
    if (key[i] == 0 && (p[i] == 0 || p[i] == ' ' || p[i] == '\t')) { if (outAfterKey)*outAfterKey = p + i; return true; }
    return false;
}

static void parse_mode_and_args(const char* p, int& outMode, std::vector<std::string>& outArgs) {
    while (*p == ' ' || *p == '\t') ++p;
    int mode = 0;
    if (sscanf(p, "%d", &mode) == 1) {
        outMode = mode;
        while (*p && *p != ' ' && *p != '\t') ++p;
        while (*p == ' ' || *p == '\t') ++p;
        while (*p) {
            while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') ++p; if (!*p) break;
            const char* e = p; while (*e && *e != ' ' && *e != '\t' && *e != '\r' && *e != '\n') ++e;
            outArgs.emplace_back(std::string(p, e - p)); p = e;
        }
    }
}

static void parse_obtain_from_cupfile(const char* cupPath) {
    g_activeObtain = 0; g_obtainArgs.clear();
    g_hasObtainCustom = false; g_activeObtainCustom = 0; g_obtainCustomArgs.clear();

    FILE* f = fopen(cupPath, "rb");
    if (!f)
        return;
    char line[1024];
    int lineNo = 0;
    while (fgets(line, sizeof(line), f)) {
        ++lineNo;
        if (char* sc = strchr(line, ';')) *sc = 0;
        char* p = line; while (*p == ' ' || *p == '\t') ++p;
        if (!*p) continue;
        const char* after = nullptr;
        if (starts_key(p, "obtaincustom", &after)) {
            parse_mode_and_args(after, g_activeObtainCustom, g_obtainCustomArgs);
            g_hasObtainCustom = true;
        }
        else if (starts_key(p, "obtain", &after)) {
            parse_mode_and_args(after, g_activeObtain, g_obtainArgs);
        }
    }
    fclose(f);
}

static std::string ParseCupNameOnly(const char* cupPath) {
    FILE* f = std::fopen(cupPath, "rb");
    if (!f) return {};
    char line[1024]; std::string name;
    while (std::fgets(line, sizeof(line), f)) {
        if (char* sc = std::strchr(line, ';')) *sc = 0;
        char key[32]; char val[960];
        if (std::sscanf(line, " %31[^= \t] = %959[^\n]", key, val) == 2 ||
            std::sscanf(line, " %31s %959[^\n]", key, val) == 2)
        {
            // tolower(key)
            for (char* p = key; *p; ++p) if (*p >= 'A' && *p <= 'Z') *p += 32;
            if (std::strcmp(key, "name") == 0) {
                // trim quotes/space
                char* v = val;
                while (*v == ' ' || *v == '\t' || *v == '"' || *v == '\'') ++v;
                char* e = v + std::strlen(v);
                while (e > v && (e[-1] == '\r' || e[-1] == '\n' || e[-1] == ' ' || e[-1] == '\t' || e[-1] == '"' || e[-1] == '\'')) --e;
                *e = 0;
                name = v; break;
            }
        }
    }
    std::fclose(f);
    return name;
}

static std::string BuildObtainCustomDialogText(const char* cupPath) {
    // Use already-parsed globals if available; else parse now
    if (g_obtainCustomArgs.empty() && cupPath) {
        parse_obtain_from_cupfile(cupPath);
    }

    const std::string cupName = ParseCupNameOnly(cupPath ? cupPath : "");
    auto join = [](const std::vector<std::string>& v) {
        std::string s; for (size_t i = 0; i < v.size(); ++i) { if (i) s += ", "; s += v[i]; } return s;
        };

    std::string msg = "Locked! Sorry!\n\n";
    switch (g_activeObtainCustom) {
    case 1:
        msg += "Complete " + join(g_obtainCustomArgs) + " to unlock.";
        break;
    case 2:
        msg += "Complete " + join(g_obtainCustomArgs) + " in Practice mode to unlock.";
        break;
    case 3:
        msg += "Complete " + join(g_obtainCustomArgs) + " in Time-Trial mode to unlock.";
        break;
    case 4:
        msg += "Complete " + join(g_obtainCustomArgs) + " in Single Player mode to unlock.";
        break;
    default:
        msg += "Complete the required objectives to unlock.";
        break;
    }
    if (!cupName.empty())
        msg = "Locked! Sorry!\n\n" + cupName + "\n\n" + msg.substr(std::string("Locked! Sorry!\n\n").size());

    return msg;
}

// ======================================================
//             Evaluate ObtainCustom requirements
// ======================================================

static bool eval_obtaincustom_gate(int mode, const std::vector<std::string>& args, std::string* msg) {
    switch (mode) {
    case 0:
        return true;

    case 1: { // prerequisite custom cups
        if (args.empty()) { if (msg) *msg = "ObtainCustom: missing prerequisite cup id."; return false; }
        const std::string prof = active_profile_name();
        for (const auto& id : args) {
            bool ok = cup_was_won_by_profile(id, prof);
            if (!ok) { if (msg) *msg = "Locked: finish custom cup '" + id + "' as profile '" + prof + "' first."; return false; }
        }
        return true;
    }

    case 2: { // practice star
        if (args.empty()) { if (msg) *msg = "ObtainCustom: no tracks for Practice."; return false; }
        for (const auto& t : args) {
            if (!level_has_practice_star(t)) { if (msg) *msg = "Collect Practice star on '" + t + "'."; return false; }
        }
        return true;
    }

    case 3: { // time trial normal
        if (args.empty()) { if (msg) *msg = "ObtainCustom: no tracks for Time Trial."; return false; }
        for (const auto& t : args) {
            if (!level_has_tt_normal(t)) { if (msg) *msg = "Beat Time Trial (Normal) on '" + t + "'."; return false; }
        }
        return true;
    }

    case 4: { // single race win
        if (args.empty()) { if (msg) *msg = "ObtainCustom: no tracks for Single Race."; return false; }
        for (const auto& t : args) {
            if (!level_has_single_win(t)) { if (msg) *msg = "Win a Single Race on '" + t + "'."; return false; }
        }
        return true;
    }

    default:
        return true; // unknown -> allow
    }
}

// --- Hard cancel helper ---
static void CancelActiveCupWithDialog(const std::string& reason) {
    *PP_ACTIVE_CUP() = nullptr;
    g_activeCupId.clear();
    g_activeCupPath.clear();
    g_cupResolvedOnce = false;
}

// --- Public "gate now" entrypoint ---
namespace ObtainMod {
    // Returns true if the cup is allowed. If false, the function has already cancelled the cup.
    bool GateCupFileNow(const char* cupPath, const char* cupId, bool showDialog /*=true*/) {
        if (!cupPath || !*cupPath) return true;  // nothing to gate

        // Parse cup for Obtain/ObtainCustom
        parse_obtain_from_cupfile(cupPath);

        // No ObtainCustom line? allow.
        if (!g_hasObtainCustom) {
            // Latch if not yet latched
            g_activeCupId = cupId ? cupId : "";
            g_activeCupPath = cupPath;
            g_cupResolvedOnce = true;
            return true;
        }

        // Evaluate gate
        std::string reason;
        if (!eval_obtaincustom_gate(g_activeObtainCustom, g_obtainCustomArgs, &reason)) {
            if (showDialog) CancelActiveCupWithDialog(reason);
            else            CancelActiveCupWithDialog("Cup locked.");
            return false;
        }

        // Passed: latch authoritatively
        g_activeCupId = cupId ? cupId : "";
        g_activeCupPath = cupPath;
        g_cupResolvedOnce = true;
        return true;
    }
}

// ======================================================
//                   Live game access
// ======================================================

static inline uint8_t* active_cup() {
    return reinterpret_cast<uint8_t*>(*PP_ACTIVE_CUP());
}
static inline const char* active_cup_id() {
    if (auto c = active_cup()) return reinterpret_cast<const char*>(c + OFF_CUP_ID);
    return nullptr;
}
static inline int cup_points_at(int place /*0-based*/) {
    auto c = active_cup(); if (!c) return 0;
    if (place < 0 || place > 7) return 0;
    return *reinterpret_cast<int*>(c + OFF_POINTS + place * 4);
}
static inline int cup_max_stages() {
    auto c = active_cup(); if (!c) return 0;
    return *reinterpret_cast<int*>(c + OFF_MAXSTAGES);
}
static inline int cup_numcars() {
    auto c = active_cup(); if (!c) return 0;
    return *reinterpret_cast<int*>(c + OFF_NUMCARS);
}

// Race-results rows as used by FUN_004604C0
struct ResRow { uint64_t playerPtr; uint64_t info; };
static inline int       results_count() { return *PLAYERS_COUNT(); }
static inline ResRow* results_rows() { return reinterpret_cast<ResRow*>(PLAYERS_BASE()); }

// ======================================================
//                   Temp championship state
// ======================================================

struct CupTmpState {
    char     magic[7];      // "CUPTMP1"
    uint8_t  version;       // 1
    char     cupId[64];
    char     profile[64];
    uint32_t maxStages;
    uint32_t stagePlayed;
    uint32_t numDrivers;
    uint64_t driverIds[16];
    int32_t  points[16];
    uint8_t  lastOrder[16];
    uint8_t  playerIndex;
    uint8_t  reserved[15];
};

static inline std::string temp_dir() { return logs_dir() + "\\temp"; }
static inline std::string temp_path(const std::string& cupId, const std::string& prof) {
    return temp_dir() + "\\" + prof + "_" + cupId + ".tmp";
}
static bool load_tmp(const std::string& cupId, const std::string& prof, CupTmpState& s) {
    std::string p = temp_path(cupId, prof);
    FILE* f = fopen(p.c_str(), "rb"); if (!f)
        return false;
    bool ok = fread(&s, 1, sizeof(s), f) == sizeof(s)
        && std::memcmp(s.magic, "CUPTMP1", 7) == 0 && s.version == 1
        && std::strncmp(s.cupId, cupId.c_str(), 63) == 0
        && std::strncmp(s.profile, prof.c_str(), 63) == 0;
    fclose(f);
    return ok;
}
static void save_tmp(const CupTmpState& s) {
    ensure_dir(temp_dir().c_str());
    std::string p = temp_path(s.cupId, s.profile);
    FILE* f = fopen(p.c_str(), "wb");
    if (!f) {
        return;
    }
    fwrite(&s, 1, sizeof(s), f);
    fclose(f);
    // Log both the path and the cup id for clarity
}
static void del_tmp(const std::string& cupId, const std::string& prof) {
    std::string p = temp_path(cupId, prof); remove(p.c_str());
}

static int resolve_player_index_by_name(const std::vector<uint64_t>& ids) {
    const std::string prof = active_profile_name();
    for (size_t i = 0; i < ids.size(); ++i) {
        const char* nm = reinterpret_cast<const char*>(ids[i] + OFF_PLAYER_NAME);
        if (nm && _stricmp(nm, prof.c_str()) == 0) return (int)i;
    }
    return 0;
}

// Try read the latest temp state for current active cup/profile.
static bool try_read_current_tmp(CupTmpState& s) {
    const char* cid = active_cup_id();
    if (!cid || !*cid) return false;
    const std::string prof = active_profile_name();
    return load_tmp(cid, prof, s);
}

namespace ObtainMod {
    bool ComputeAiGridOrder(int mode,
        std::vector<uint8_t>& outAiOrder,
        int& outNumDrivers,
        int& outPlayerSlot)
    {
        outAiOrder.clear();
        outNumDrivers = 0;
        outPlayerSlot = 0;

        if (mode != 1 && mode != 2) return false;

        CupTmpState s{};
        if (!try_read_current_tmp(s)) {
            return false;
        }

        const int num = (int)std::clamp<int>((int)s.numDrivers, 1, 16);
        const int player = (s.playerIndex <= 15) ? (int)s.playerIndex : 0;
        outNumDrivers = num;
        outPlayerSlot = player;

        // Build a list of AI roster slots (exclude player)
        std::vector<int> aiSlots;
        aiSlots.reserve(num > 0 ? num - 1 : 0);
        for (int k = 0; k < num; ++k) if (k != player) aiSlots.push_back(k);

        // Sort according to mode
        if (mode == 2) {
            // Previous race order: smaller lastOrder = better
            std::sort(aiSlots.begin(), aiSlots.end(), [&](int a, int b) {
                const uint8_t la = s.lastOrder[a] ? s.lastOrder[a] : 255;
                const uint8_t lb = s.lastOrder[b] ? s.lastOrder[b] : 255;
                if (la != lb) return la < lb;
                return a < b; // stabilize
                });
        }
        else {
            // Points desc; tie-break by better last result
            std::sort(aiSlots.begin(), aiSlots.end(), [&](int a, int b) {
                const int pa = s.points[a], pb = s.points[b];
                if (pa != pb) return pa > pb;
                const uint8_t la = s.lastOrder[a] ? s.lastOrder[a] : 255;
                const uint8_t lb = s.lastOrder[b] ? s.lastOrder[b] : 255;
                if (la != lb) return la < lb;
                return a < b; // stabilize
                });
        }

        // Convert roster slots -> logical AI indices (0..nAi-1)
        outAiOrder.reserve(aiSlots.size());
        for (int slot : aiSlots) {
            const int logical = (slot > player) ? (slot - 1) : slot;
            if (logical >= 0 && logical <= 14) outAiOrder.push_back((uint8_t)logical);
        }

        return !outAiOrder.empty();
    }
}

// ======================================================
//                       Hooks
// ======================================================

// ================== Shared gate helpers (new) ==================

struct GateDecision {
    bool allow = true;
    std::string reason;  // if !allow, user-facing message
    std::string id;      // cup id without .txt
    std::string path;    // absolute cups\*.txt
};

static GateDecision DecideGateFromSelection()
{
    GateDecision d{};

    // Prefer the engine's active cup if it's already known.
    if (const char* aid = active_cup_id(); aid && *aid) {
        d.id = aid;
        d.path = CupGen::CupsDir() + "\\" + d.id + ".txt";

        // Must exist
        if (FILE* f = std::fopen(d.path.c_str(), "rb")) {
            std::fclose(f);

            // Parse + gate now (early block is OK when we know the id)
            parse_obtain_from_cupfile(d.path.c_str());
            if (g_hasObtainCustom) {
                std::string reason;
                if (!eval_obtaincustom_gate(g_activeObtainCustom, g_obtainCustomArgs, &reason)) {
                    d.allow = false;
                    d.reason = reason;
                }
            }
        }
        else {
            d.allow = false;
            d.reason = "Cup file not found:\n" + d.path;
        }
        return d; // done via active cup
    }

    // No reliable active cup yet. Do NOT touch menu memory.
    // Let hkCupFinalize() do the gating once the real cupStruct is available.
    d.allow = true;  // proceed for now
    d.id.clear();
    d.path.clear();
    return d;
}

static void EnforceDecision_PreLoad(const GateDecision& d)
{
    if (d.allow) {
        // Only latch if we really have a non-empty custom cup id
        if (!d.id.empty()) {
            g_activeCupId = d.id;
            g_activeCupPath = d.path;
            g_cupResolvedOnce = true;

            // Optional: keep both sides perfectly in sync
            // OpponentsMod::NotifyActiveCup(g_activeCupPath.c_str());
        }
        return;
    }

    *PP_ACTIVE_CUP() = nullptr;
}

// ================== Hooks ==================

using tStartCup = void(__fastcall*)(void*, void*, void*, void*);
using tRaceResults = void(__fastcall*)(unsigned long long);
using tAfterCupFinish = void(__fastcall*)(void*);
using tCupFinalize = void(*)(void*);

static tStartCup    oStartCup = nullptr;
static tRaceResults oRaceResults = nullptr;
static tCupFinalize oCupFinalize = nullptr;
static tAfterCupFinish oAfterCupFinish = nullptr;

// Helper: build cups\<id>.txt
static inline std::string cup_txt_path_from_id(const char* id) {
    if (!id || !*id) return {};
    return CupGen::CupsDir() + "\\" + std::string(id) + ".txt";
}

// ------- Unlock rescanner (file-scope) -------

// Quick gate check for a specific cup id/path using your existing logic.
static bool IsCupUnlockedNow(const std::string& cupId, const std::string& cupPath)
{
    FILE* f = std::fopen(cupPath.c_str(), "rb");
    if (!f) {
        return false; // missing file -> treat as locked
    }
    std::fclose(f);

    parse_obtain_from_cupfile(cupPath.c_str());

    // No ObtainCustom line means allowed by definition.
    if (!g_hasObtainCustom) {
        return true;
    }

    std::string reason;
    const bool ok = eval_obtaincustom_gate(g_activeObtainCustom, g_obtainCustomArgs, &reason);
    return ok;
}

// If the currently selected cup just flipped to unlocked, force a re-finalize to refresh the menu.
static void MaybeRefreshCurrentlySelectedIfJustUnlocked()
{
    const int idx = selected_index();
    uint8_t* sel = selected_cup_ptr_from_index(idx);
    const char* id = cup_id_from_ptr(sel);

    if (!sel || !id || !*id) return;  // builtin/empty

    const std::string cupId = id;
    const std::string cupPath = cups_base_dir() + "\\" + cupId + ".txt";

    const bool nowUnlocked = IsCupUnlockedNow(cupId, cupPath);
    const auto it = g_unlockCache.find(cupId);
    const bool wasUnlocked = (it != g_unlockCache.end()) ? it->second : false;

    // keep cache coherent
    g_unlockCache[cupId] = nowUnlocked;

    if (!wasUnlocked && nowUnlocked) {

        int diff = 1, stages = 0;
        ParseDiffAndStageCount(cupPath.c_str(), diff, stages);

        char* c = reinterpret_cast<char*>(sel);
        *reinterpret_cast<int*>(c + OFF_DIFFICULTY) = diff;
        *reinterpret_cast<int*>(c + OFF_MAXSTAGES) = stages;
        c[OFF_LOCKBYTE] = 0;

        if (oCupFinalize) oCupFinalize(sel); // optional full refresh
    }
}

static void RefreshCupRowById_Unlocked(const std::string& cupId);

// Enumerate cups\*.txt to prewarm/refresh the unlock cache.
// We don’t touch the menu here (only the cache); the real-time refresh is limited to the currently selected cup.
static void RebuildUnlockCache_AllCups()
{
    const std::string pattern = cups_base_dir() + "\\*.txt";

    WIN32_FIND_DATAA fd{};
    HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) {
        return;
    }
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            std::string fn = fd.cFileName;
            // strip ".txt" to get id
            if (fn.size() > 4 && _stricmp(fn.substr(fn.size() - 4).c_str(), ".txt") == 0) {
                std::string id = fn.substr(0, fn.size() - 4);
                std::string path = cups_base_dir() + "\\" + fn;

                bool unlocked = IsCupUnlockedNow(id, path);

                // detect transition: locked -> unlocked
                auto it = g_unlockCache.find(id);
                bool wasUnlocked = (it != g_unlockCache.end()) ? it->second : false;

                if (!wasUnlocked && unlocked) {
                    RefreshCupRowById_Unlocked(id);   // <-- the missing action
                }

                g_unlockCache[id] = unlocked;
            }
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);

}

static HANDLE g_timerQ = nullptr;

static VOID CALLBACK DelayedRescanCB(PVOID, BOOLEAN) {
    // One more pass after RVGL likely flushed .level files
    RebuildUnlockCache_AllCups();
    MaybeRefreshCurrentlySelectedIfJustUnlocked();
}

static void QueueDelayedRescan(DWORD delay_ms = 600) {
    if (!g_timerQ) g_timerQ = CreateTimerQueue();
    HANDLE t = nullptr;
    // one-shot timer; no repeat
    CreateTimerQueueTimer(&t, g_timerQ, DelayedRescanCB, nullptr, delay_ms, 0, WT_EXECUTEDEFAULT);
}

// --- CANCEL BY MAKING THE CUP INERT AND RETURNING ---
static void MakeCupInertAndReturn(void* cup /* param_1 */) {
    char* c = reinterpret_cast<char*>(cup);

    // 1) No stages => unplayable
    *reinterpret_cast<int*>(c + OFF_MAXSTAGES) = 0;     // 0x78

    // 2) Zero cars (belt & suspenders)
    *reinterpret_cast<int*>(c + OFF_NUMCARS) = 0;     // 0x68

    // 3) Clear stage table (STAGE entries live at 0x94 .. 0x94+0xC*16)
    std::memset(c + 0x94, 0, 0x0C * 16);

    // 4) Zero points array (optional)
    std::memset(c + OFF_POINTS, 0, 4 * 16);             // 0x154

    // 5) If you want, force the loader "ready" byte off (from your Ghidra dump)
    //    This is optional; 1 often means "needs generation/locked".
    // c[0x195] = 1;

}

// ---- StartCup: single source of truth ----
static void __fastcall hkStartCup(void* rcx, void* rdx, void* r8, void* r9)
{

    // --- NEW: drop any stale latch from a previous cup ---
    g_activeCupId.clear();
    g_activeCupPath.clear();
    g_cupResolvedOnce = false;         // optional; lets finalize re-latch if needed

    // Reset transient parse state
    g_hasObtainCustom = false;
    g_activeObtainCustom = 0;
    g_obtainCustomArgs.clear();

    // Decide and enforce immediately
    GateDecision d = DecideGateFromSelection();
    if (!d.allow) {
        // Pop a user-facing dialog with the precise unlock info
        std::string text = BuildObtainCustomDialogText(d.path.c_str());
        MessageBoxA(nullptr, text.c_str(), "Cup locked", MB_OK | MB_ICONWARNING | MB_SETFOREGROUND | MB_TASKMODAL);

        EnforceDecision_PreLoad(d); // this will null active cup; we already mini-parsed at finalize for UI
        return; // DO NOT call original when blocked
    }

    // Latch cup id/path now to normalize ordering for Opponents/StartGrid.
    EnforceDecision_PreLoad(d);

    // Proceed
    if (oStartCup) oStartCup(rcx, rdx, r8, r9);
}

// Our hook for FUN_00448500
static void __fastcall hkCupFinalize(void* cupStruct)
{
    const char* cid = cupStruct
        ? reinterpret_cast<const char*>(reinterpret_cast<uint8_t*>(cupStruct) + OFF_CUP_ID)
        : nullptr;
    const std::string path = cup_txt_path_from_id(cid);

    if (!path.empty()) {
        // Evaluate gate silently; if FAIL => populate selector fields, then return.
        if (!ObtainMod::GateCupFileNow(path.c_str(), cid ? cid : "", /*showDialog*/false)) {
            // << changed here >>
            MiniParseForMenu(cupStruct, path.c_str());  // fill NAME/DIFF/CARS/POINTS/STAGES for selector
            return;                                     // do NOT call original
        }
    }

    // Allowed -> run original parser
    if (oCupFinalize) oCupFinalize(cupStruct);
}

// -------- StartGrid logging helpers (file-scope) --------

// Stable placeholder name when we don't have a readable player name
static std::string sg_hex_name(uint64_t id) {
    char buf[32];
    _snprintf(buf, sizeof(buf), "ID_%016llX", (unsigned long long)id);
    return std::string(buf);
}

// Track name if you have a resolver; otherwise "Unknown"
static const char* sg_track_name() {
    // If you have something like get_current_track_name(), call it here.
    return "Unknown";
}

// -- per-race results: accumulate points and unlock on series end --
static void __fastcall hkRaceResults(unsigned long long sink) {
    if (oRaceResults) oRaceResults(sink);

    // Prefer latched id, then engine's id as a fallback
    const char* activeCid = active_cup_id();
    const char* latched   = g_activeCupId.empty() ? nullptr : g_activeCupId.c_str();
    const char* cid       = latched ? latched : activeCid;

    QueueDelayedRescan(700);  // ~0.7s later; tweak if needed
    RebuildUnlockCache_AllCups();
    MaybeRefreshCurrentlySelectedIfJustUnlocked();

    if (!cid || !*cid)
        return;

    const std::string prof = active_profile_name();
    CupTmpState s{};
    if (!load_tmp(cid, prof, s)) {
        std::memcpy(s.magic, "CUPTMP1", 7); s.version = 1;
        std::strncpy(s.cupId, cid, 63); s.cupId[63] = 0;
        std::strncpy(s.profile, prof.c_str(), 63); s.profile[63] = 0;
        s.maxStages = (uint32_t)std::max(cup_max_stages(), 0);
        s.stagePlayed = 0;
        s.numDrivers = (uint32_t)std::clamp(cup_numcars(), 1, 16);
        std::memset(s.driverIds, 0, sizeof(s.driverIds));
        std::memset(s.points, 0, sizeof(s.points));
        std::memset(s.lastOrder, 0, sizeof(s.lastOrder));
        s.playerIndex = 0xFF;
        save_tmp(s);
    }

    // Current race index (0-based) is the stage that's just been finished BEFORE we increment it
    const int currentRaceIndex = (int)s.stagePlayed;

    // Finishing order from results rows (ids[i] is place i+1)
    std::vector<uint64_t> ids;
    {
        int n = results_count(); ResRow* rows = results_rows();
        for (int i = 0; i < n; i++) {
            if (rows[i].info != 0) ids.push_back(rows[i].playerPtr);
        }
    }

    if (ids.empty()) {
        save_tmp(s);
        return;
    }

    const int num = (int)std::min<size_t>(ids.size(), s.numDrivers);

    // Initialize roster on first race
    if (s.stagePlayed == 0 && s.driverIds[0] == 0) {
        for (int i = 0; i < num; i++) s.driverIds[i] = ids[i];
        s.playerIndex = (uint8_t)resolve_player_index_by_name(ids);
    }

    int slotOf[16]; for (int i = 0; i < 16; i++) slotOf[i] = -1;
    for (int i = 0; i < num; i++) {
        uint64_t id = ids[i]; int slot = -1;
        for (int k = 0; k < num; k++) if (s.driverIds[k] == id) { slot = k; break; }
        if (slot == -1) {
            for (int k = 0; k < num; k++) if (s.driverIds[k] == 0) { s.driverIds[k] = id; slot = k; break; }
        }
        if (slot != -1) slotOf[slot] = i;
    }

    for (int slot = 0; slot < num; ++slot) {
        int place = slotOf[slot];
        if (place >= 0) {
            int pts = cup_points_at(place);
            s.points[slot] += pts;
            s.lastOrder[slot] = (uint8_t)(place + 1); // 1 is best
        }
    }

    // === StartGrid: emit a minimal CSV block into race_log.txt (parsable by StartGrid) ===
    {
        const char* trackName = sg_track_name();
        for (int i = 0; i < num; ++i) {
            // We don't have a reliable readable name yet, so use a stable hex label.
            const std::string disp = sg_hex_name(ids[i]);
        }
    }

    // Advance stage counter
    if (s.stagePlayed < s.maxStages) s.stagePlayed++;
    const bool finished = (s.stagePlayed >= s.maxStages && s.maxStages > 0);

    if (!finished) {
        save_tmp(s);
        // NEW: per-race refresh – may flip mode 2/3/4 requirements on .level files.
        QueueDelayedRescan(700);  // ~0.7s later; tweak if needed
        RebuildUnlockCache_AllCups();
        MaybeRefreshCurrentlySelectedIfJustUnlocked();
        return;
    }

    // Final rank with tie-break: last race better place wins
    const int pSlot = (s.playerIndex <= 15) ? (int)s.playerIndex : 0;
    const int pPts = s.points[pSlot];
    const int pLast = s.lastOrder[pSlot] ? s.lastOrder[pSlot] : 255;
    int betterCount = 0;
    for (int k = 0; k < num; k++) if (k != pSlot) {
        if (s.points[k] > pPts) betterCount++;
        else if (s.points[k] == pPts) {
            int theirLast = s.lastOrder[k] ? s.lastOrder[k] : 255;
            if (theirLast < pLast) betterCount++;
        }
    }
    const int finalRank = betterCount + 1;

    // UnlockPos from cup file (launcher-aware, prefers the exact active path)
    auto parse_unlockpos_from_cupfile = [](const char* id) -> int {
        char path[MAX_PATH];

        // If we know the exact file path for this cup, use it.
        if (id && *id && !g_activeCupPath.empty() && _stricmp(id, g_activeCupId.c_str()) == 0) {
            std::strncpy(path, g_activeCupPath.c_str(), MAX_PATH - 1);
            path[MAX_PATH - 1] = 0;
        }
        else {
            // Otherwise build from the resolved cups base dir.
            _snprintf(path, MAX_PATH, "%s\\%s.txt", cups_base_dir().c_str(), (id && *id) ? id : "");
        }

        FILE* f = std::fopen(path, "rb");
        if (!f)
            return 1;

        char line[512];
        int  val = 1;

        while (std::fgets(line, sizeof(line), f)) {
            if (char* sc = std::strchr(line, ';')) *sc = 0;           // strip ; comment
            // Try "UnlockPos 2" and tolerate "UnlockPos=2"
            char key[32]; int v;
            if (std::sscanf(line, " %31[^= \t] = %d", key, &v) == 2 ||
                std::sscanf(line, " %31s %d", key, &v) == 2) {
                // tolower(key)
                for (char* p = key; *p; ++p) if (*p >= 'A' && *p <= 'Z') *p += 32;
                if (std::strcmp(key, "unlockpos") == 0) { val = v; break; }
            }
        }

        std::fclose(f);
        return val;
        };

    const int unlockPos = parse_unlockpos_from_cupfile(cid);
    if (finalRank > 0 && finalRank <= unlockPos) {
        write_win_for_profile(cid, active_profile_name());  // NEW
        QueueDelayedRescan(700);
        RebuildUnlockCache_AllCups();
        MaybeRefreshCurrentlySelectedIfJustUnlocked();
    }
    else {
        save_tmp(s);
        QueueDelayedRescan(700);  // ~0.7s later; tweak if needed
        RebuildUnlockCache_AllCups();
        MaybeRefreshCurrentlySelectedIfJustUnlocked();
        return;
    }
}

// Optional after-finish (not used yet)
static void __fastcall hkAfterCupFinish(void* ctx) {
    if (oAfterCupFinish) oAfterCupFinish(ctx);
}

// Update the menu row for a given cup id: write real fields, clear lock, run finalize, bounce redraw.
static void RefreshCupRowById_Unlocked(const std::string& cupId) {
    if (cupId.empty()) return;

    const std::string path = cups_base_dir() + "\\" + cupId + ".txt";
    uint8_t* cup = FindCupStructById(cupId.c_str());
    if (!cup) {
        return;
    }

    int diff = 1, stages = 0;
    ParseDiffAndStageCount(path.c_str(), diff, stages);

    char* c = reinterpret_cast<char*>(cup);
    *reinterpret_cast<int*>(c + OFF_DIFFICULTY) = diff;
    *reinterpret_cast<int*>(c + OFF_MAXSTAGES) = stages;
    c[OFF_LOCKBYTE] = 0; // clear "locked/needs-gen" hint

    // Optional: also refresh the name (nice polish)
    std::string nm = ParseCupNameOnly(path.c_str());
    if (!nm.empty()) {
        const size_t cap = 31;
        size_t n = (nm.size() > cap ? cap : nm.size());
        std::memcpy(c + OFF_NAME, nm.c_str(), n);
        std::memset(c + OFF_NAME + n, 0, 32 - n);
        *(c + OFF_NAME + 0x1F) = 0;
    }

    if (oCupFinalize) {
        oCupFinalize(cup); // let the game rebuild any derived fields for that entry
    }

    // Bounce selection to force immediate repaint (covers cases where the UI caches row visuals)
    ForceMenuRedrawBySelectionBounce();

}

// ======================================================
//                 Installer / wiring (FIXED)
// ======================================================

namespace ObtainMod {
    bool InstallObtainSystem() {
        bool ok = true;

        const uintptr_t startAbs = AbsFromMaybeRva(g_addrs.rva_CupParse);
        ok &= (startAbs && HookFunction(startAbs, (LPVOID)&hkStartCup, (LPVOID*)&oStartCup));

        const uintptr_t raceAbs = AbsFromMaybeRva(g_addrs.rva_RaceResults);
        if (raceAbs)
            ok &= HookFunction(raceAbs, (LPVOID)&hkRaceResults, (LPVOID*)&oRaceResults);

        const uintptr_t finAbs = AbsFromMaybeRva(g_addrs.rva_CupFinalize);
        if (finAbs)
            ok &= HookFunction(finAbs, (LPVOID)&hkCupFinalize, (LPVOID*)&oCupFinalize);

        return ok;
    }
}

namespace ObtainMod {
    bool GetLaunchedCupPath(std::string& outPath, std::string& outId) {
        // Prefer engine's active cup if available
        if (const char* aid = active_cup_id(); aid && *aid) {
            if (g_activeCupId.empty() || _stricmp(g_activeCupId.c_str(), aid) != 0) {
                std::string p = cups_base_dir() + "\\" + std::string(aid) + ".txt";
                if (FILE* f = std::fopen(p.c_str(), "rb")) {
                    std::fclose(f);
                    if (!GateCupFileNow(p.c_str(), aid, /*showDialog*/true)) {
                        return false;  // already cancelled by GateCupFileNow
                    }
                }
            }
        }

        // Return latched if we have it
        if (!g_activeCupId.empty() && !g_activeCupPath.empty()) {
            outPath = g_activeCupPath;
            outId = g_activeCupId;
            return true;
        }
        return false;
    }
}


static std::string g_lastGatedId;  // last cup id we evaluated this session

namespace ObtainMod {
    bool EnsureGateForCurrentCupOnce() {
        const char* aid = active_cup_id();
        if (!aid || !*aid) {
            return true; // nothing to do
        }
        // Already evaluated this id this session?
        if (!g_lastGatedId.empty() && _stricmp(g_lastGatedId.c_str(), aid) == 0) {
            return true;
        }

        // Resolve path and latch (promote if needed)
        std::string path = cups_base_dir() + "\\" + std::string(aid) + ".txt";
        FILE* f = std::fopen(path.c_str(), "rb");
        if (!f) {
            *PP_ACTIVE_CUP() = nullptr;
            g_activeCupId.clear();
            g_activeCupPath.clear();
            g_cupResolvedOnce = false;
            g_lastGatedId.clear();
            return false;
        }
        std::fclose(f);

        // Parse + evaluate ObtainCustom
        parse_obtain_from_cupfile(path.c_str());
        if (g_hasObtainCustom) {
            std::string reason;
            if (!eval_obtaincustom_gate(g_activeObtainCustom, g_obtainCustomArgs, &reason)) {
                *PP_ACTIVE_CUP() = nullptr;
                g_activeCupId.clear();
                g_activeCupPath.clear();
                g_cupResolvedOnce = false;
                g_lastGatedId.clear();
                return false;
            }
        }

        // Authoritative latch + mark gated
        g_activeCupId = aid;
        g_activeCupPath = path;
        g_cupResolvedOnce = true;
        g_lastGatedId = aid;
        return true;
    }
}
