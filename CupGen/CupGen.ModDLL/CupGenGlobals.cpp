#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_WARNINGS
#include "CupGenGlobals.h"
#include <algorithm>
#include <string>
#include <windows.h>
#include <direct.h>
#include <cstring>   // strrchr, strncpy
#include <cstdlib>   // getenv

int gParsedStartGridMode = 0;
std::string gParsedPointsCsv;

namespace {
    std::string gRoot; // normalized absolute RVGL root, no trailing slash
    std::string gProfiles;
    std::string gCups;
    std::string gCupGen;
    std::string gCupGenLogs;

    // Put this above strip_launcher_suffix in CupGenGlobals.cpp
    static inline void norm(std::string& s) {
        for (auto& ch : s) if (ch == '/') ch = '\\';
        while (!s.empty() && (s.back() == '\\' || s.back() == '/')) s.pop_back();
    }

    static inline std::string strip_launcher_suffix(std::string ed) {
        norm(ed); // normalize to backslashes, trim trailing slashes
        // Try the two known launcher dirs:
        const char* suffixes[] = { "\\packs\\rvgl_win64", "\\packs\\rvgl_win32" };
        for (auto sfx : suffixes) {
            auto pos = ed.rfind(sfx);
            if (pos != std::string::npos && pos + std::strlen(sfx) == ed.size()) {
                return ed.substr(0, pos);
            }
        }
        // Generic safety: if we see "\packs\rvgl_win??" as the last two segments, strip them
        auto packsPos = ed.rfind("\\packs\\");
        if (packsPos != std::string::npos) {
            auto tail = ed.substr(packsPos + 7); // after "\packs\"
            if (tail.rfind("rvgl_win", 0) == 0) {
                return ed.substr(0, packsPos);
            }
        }
        return ed; // no launcher path, assume ed is already the root
    }

    static inline void ensure_dir(const std::string& p) {
        char tmp[MAX_PATH]; std::strncpy(tmp, p.c_str(), MAX_PATH - 1); tmp[MAX_PATH - 1] = 0;
        for (char* q = tmp + 1; *q; ++q) {
            if (*q == '\\' || *q == '/') { char c = *q; *q = 0; _mkdir(tmp); *q = c; }
        }
        _mkdir(tmp);
    }
    static inline std::string join2(const std::string& a, const char* b) {
        if (a.empty()) return b ? b : "";
        return a + "\\" + (b ? b : "");
    }
    static inline std::string exe_dir() {
        char buf[MAX_PATH]{ 0 }; GetModuleFileNameA(nullptr, buf, MAX_PATH);
        char* s = std::strrchr(buf, '\\'); if (s) *s = 0;
        return std::string(buf);
    }

    static void rebuild() {
        // Build from gRoot (must be set)
        gProfiles = join2(gRoot, "save\\profiles");
        gCups = join2(gRoot, "packs\\rvgl_assets\\cups");
        gCupGen = join2(gCups, "cupgen");
        gCupGenLogs = join2(gCupGen, "cupgen_logs");

        // Create CupGen dirs on demand
        ensure_dir(gCupGen);
        ensure_dir(gCupGenLogs);
    }
}

namespace CupGen {
    void CupGen::SetRvglRoot(const char* rootAbs) {
        if (!rootAbs || !*rootAbs) {
            gRoot = strip_launcher_suffix(exe_dir());
        }
        else {
            gRoot = rootAbs;
            norm(gRoot);
        }
        rebuild();
    }

    extern "C" __declspec(dllexport) void CupGen_SetRvglRoot(const char* rootAbs) {
        SetRvglRoot(rootAbs);
    }

    // First call lazy-init: allow EXE to skip SetRvglRoot if env present
    const std::string& RvglRoot() {
        if (gRoot.empty()) {
            const char* env = std::getenv("CUPGEN_RVGL_ROOT");
            SetRvglRoot(env);
        }
        return gRoot;
    }
    const std::string& ProfilesBase() { if (gRoot.empty()) RvglRoot(); return gProfiles; }
    const std::string& CupsDir() { if (gRoot.empty()) RvglRoot(); return gCups; }
    const std::string& CupGenDir() { if (gRoot.empty()) RvglRoot(); return gCupGen; }
    const std::string& CupGenLogsDir() { if (gRoot.empty()) RvglRoot(); return gCupGenLogs; }
}
