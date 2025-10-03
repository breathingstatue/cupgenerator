// RvglSigHelper.cpp  (build as a DLL, same solution as RVGLCupOpponents)
// Exports a single function you can P/Invoke from WPF.
// Reuses your signatures.h / ResolveHookRVAsFromFile().

#define NOMINMAX
#include <windows.h>
#include <cstdio>
#include <string>
#include <vector>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <ctime>
#include "signatures_helper.h"

// -------------------- tiny logging --------------------
static std::wstring NowIsoLocal() {
    wchar_t buf[64]{};
    std::time_t t = std::time(nullptr);
    std::tm tm{}; localtime_s(&tm, &t);
    std::wcsftime(buf, 64, L"%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

static std::wstring DirName(const std::wstring& p) {
    auto s = p.find_last_of(L"\\/");
    return (s == std::wstring::npos) ? L"." : p.substr(0, s);
}

// -------------------- existing helpers ----------------
struct ScopeW {
    std::wstring v;
    ScopeW() = default;
    ScopeW(const wchar_t* s) : v(s ? s : L"") {}
    bool empty() const { return v.empty(); }
    const wchar_t* c_str() const { return v.c_str(); }
};

static std::wstring Join2(const std::wstring& a, const std::wstring& b) {
    if (a.empty()) return b;
    if (a.back() == L'\\' || a.back() == L'/') return a + b;
    return a + L"\\" + b;
}

static bool GetFileTimestampISO8601(const wchar_t* path, std::string& outIso) {
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fad)) return false;
    FILETIME ft = fad.ftLastWriteTime;
    SYSTEMTIME stUTC; FileTimeToSystemTime(&ft, &stUTC);
    char tmp[64];
    std::snprintf(tmp, sizeof(tmp), "%04u-%02u-%02uT%02u:%02u:%02uZ",
        stUTC.wYear, stUTC.wMonth, stUTC.wDay, stUTC.wHour, stUTC.wMinute, stUTC.wSecond);
    outIso.assign(tmp);
    return true;
}

static std::string Hex32(uint32_t v) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << v;
    return oss.str();
}

// Try to find rvgl.exe under launcher layouts if caller passed a *root* dir.
static std::wstring ResolveRvglExeFromRoot(const wchar_t* rvglRootOrExe) {
    if (!rvglRootOrExe || !*rvglRootOrExe) return L"";
    std::wstring p(rvglRootOrExe);

    // If the input already points to an .exe, just return it when it exists.
    if (p.size() > 4) {
        auto tail = p.substr(p.size() - 4);
        for (auto& ch : tail) ch = (wchar_t)towlower(ch);
        if (tail == L".exe" && GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES)
            return p;
    }

    // Otherwise treat input as *root* and try known subpaths.
    std::vector<std::wstring> candidates = {
        Join2(p, L"rvgl.exe"),
        Join2(p, L"packs\\rvgl_win64\\rvgl.exe"),
        Join2(p, L"packs\\rvgl_win32\\rvgl.exe"),
        Join2(p, L"packs\\game_files\\rvgl.exe")
    };
    for (const auto& c : candidates) {
        if (GetFileAttributesW(c.c_str()) != INVALID_FILE_ATTRIBUTES)
            return c;
    }
    return L"";
}

extern "C" __declspec(dllexport)
int /*cdecl*/ ScanRvglOnDisk(const wchar_t* rvglRootOrExe,
    const wchar_t* outJsonPath)
{
    ScopeW in(rvglRootOrExe), out(outJsonPath);
    if (in.empty() || out.empty()) {
        return -10;
    }

    std::wstring exe = ResolveRvglExeFromRoot(in.c_str());
    if (exe.empty()) {
        return -11;
    }

    // Prepare debug sink next to the JSON
    const std::wstring outDir = DirName(out.v);
    const std::wstring dbgPath = Join2(outDir, L"rvgl_addrs.debug.txt");

    HookAddrs addrs{};
    std::wstring dbgMsg;

    // NOTE: signatures_helper.cpp will fill dbgMsg with details
    if (!ResolveHookRVAsFromFile(exe.c_str(), addrs, &dbgMsg)) {
        return -12; // signature scan failed
    }

    std::string isoTime;
    GetFileTimestampISO8601(exe.c_str(), isoTime);

    std::ofstream f(out.c_str(), std::ios::binary);
    if (!f) {
        return -13;
    }

    // Emit JSON (same as before)
    f << "{\n";
    f << "  \"schema_version\": 1,\n";
    f << "  \"rvgl_path\": \"";
    for (auto ch : exe) { if (ch == L'\\') f << "\\\\"; else f << (char)ch; }
    f << "\",\n";
    f << "  \"rvgl_last_write\": \"" << isoTime << "\",\n";

    f << "  \"rva_LoadCars\": \"" << Hex32(addrs.rva_LoadCars) << "\",\n";
    f << "  \"rva_CupParse\": \"" << Hex32(addrs.rva_CupParse) << "\",\n";
    f << "  \"rva_BuildGrid\": \"" << Hex32(addrs.rva_BuildGrid) << "\",\n";
    f << "  \"rva_CarTablePtr\": \"" << Hex32(addrs.rva_CarTablePtr) << "\",\n";
    f << "  \"rva_CarCount\": \"" << Hex32(addrs.rva_CarCount) << "\",\n";
    f << "  \"rva_AISlot0\": \"" << Hex32(addrs.rva_AISlot0) << "\",\n";
    f << "  \"rva_ActiveCupPtr\": \"" << Hex32(addrs.rva_ActiveCupPtr) << "\",\n";
    f << "  \"rva_PlayersBase\": \"" << Hex32(addrs.rva_PlayersBase) << "\",\n";
    f << "  \"rva_PlayersCount\": \"" << Hex32(addrs.rva_PlayersCount) << "\",\n";
    f << "  \"rva_RaceResults\": \"" << Hex32(addrs.rva_RaceResults) << "\",\n";
    f << "  \"rva_CupFinalize\": \"" << Hex32(addrs.rva_CupFinalize) << "\",\n";
    f << "  \"rva_MenuState\": \"" << Hex32(addrs.rva_MenuState) << "\",\n";
    f << "  \"rva_BuiltinCupsBase\": \"" << Hex32(addrs.rva_BuiltinCupsBase) << "\",\n";
    f << "  \"rva_CustomCupsList\": \"" << Hex32(addrs.rva_CustomCupsList) << "\",\n";
    f << "  \"rva_FrontendInit\": \"" << Hex32(addrs.rva_FrontendInit) << "\",\n";

    f << "  \"rva_OppSlotIndex\": [\n";
    for (int i = 0; i < 16; ++i) {
        f << "    \"" << Hex32(addrs.rva_OppSlotIndex[i]) << "\"" << (i == 15 ? "\n" : ",\n");
    }
    f << "  ]\n";
    f << "}\n";

    return 0;
}
