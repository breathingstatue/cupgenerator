#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <vector>
#include <cwchar>
#include <shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

#include "signatures.h"

// ---------- tiny fs helpers ----------
static inline std::wstring DirName(const std::wstring& p) {
    wchar_t buf[MAX_PATH]; wcsncpy_s(buf, p.c_str(), _TRUNCATE);
    PathRemoveFileSpecW(buf);
    return std::wstring(buf);
}
static inline std::wstring Basename(const std::wstring& p) {
    const wchar_t* s = PathFindFileNameW(p.c_str());
    return s ? std::wstring(s) : std::wstring();
}
static inline std::wstring Join2(const std::wstring& a, const std::wstring& b) {
    wchar_t buf[MAX_PATH]; wcsncpy_s(buf, a.c_str(), _TRUNCATE);
    PathAppendW(buf, b.c_str());
    return std::wstring(buf);
}
static inline bool ExistsFile(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return (a != INVALID_FILE_ATTRIBUTES) && !(a & FILE_ATTRIBUTE_DIRECTORY);
}
static inline bool ExistsDir(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return (a != INVALID_FILE_ATTRIBUTES) && (a & FILE_ATTRIBUTE_DIRECTORY);
}
static inline bool EndsWith(const std::wstring& s, const wchar_t* suf) {
    const size_t n = s.size(), m = wcslen(suf);
    if (m > n) return false;
    return _wcsicmp(s.c_str() + (n - m), suf) == 0;
}

// ---------- path helpers (public) ----------

std::wstring DeriveRvglRootFromExe(const wchar_t* rvglExePath) {
    std::wstring exe = rvglExePath ? std::wstring(rvglExePath) : L"";
    std::wstring exeDir = DirName(exe);
    std::wstring parent = DirName(exeDir);      // maybe ...\packs
    std::wstring gparent = DirName(parent);     // maybe <root>

    // launcher layout: <root>\packs\rvgl_win64\rvgl.exe  (or win32)
    if (!parent.empty() && _wcsicmp(Basename(parent).c_str(), L"packs") == 0) {
        return DirName(parent);
    }
    if (!gparent.empty() && _wcsicmp(Basename(gparent).c_str(), L"packs") == 0) {
        return DirName(gparent);
    }
    // plain layout: <root>\rvgl.exe
    return exeDir;
}

std::wstring ComputeCupgenJsonPathFromRoot(const wchar_t* rvglRoot) {
    std::wstring root = rvglRoot ? std::wstring(rvglRoot) : L"";
    std::wstring p = root;

    // Create directory chain safely (no fancy nested Join that confuses IntelliSense)
    const wchar_t* chain[] = { L"packs", L"rvgl_assets", L"cups", L"cupgen" };
    for (auto seg : chain) {
        p = Join2(p, seg);
        if (!ExistsDir(p)) CreateDirectoryW(p.c_str(), nullptr);
    }
    return Join2(p, L"rvgl_addrs.json");
}

std::wstring ComputeCupgenJsonPathFromExe(const wchar_t* rvglExePath) {
    const std::wstring root = DeriveRvglRootFromExe(rvglExePath);
    return ComputeCupgenJsonPathFromRoot(root.c_str());
}

// ---------- JSON I/O (public) ----------

static bool parse_hex(const std::wstring& s, uint32_t& out) {
    unsigned v = 0;
    if (swscanf_s(s.c_str(), L"%x", &v) == 1) { out = (uint32_t)v; return true; }
    return false;
}
static bool extract_hex_field(const std::wstring& text, const wchar_t* key, uint32_t& out) {
    std::wstring find = std::wstring(L"\"") + key + L"\"";
    size_t p = text.find(find);
    if (p == std::wstring::npos) return false;
    size_t q = text.find(L"0x", p);
    if (q == std::wstring::npos) return false;
    size_t e = q + 2;
    while (e < text.size() && iswxdigit(text[e])) ++e;
    return parse_hex(text.substr(q + 2, e - (q + 2)), out);
}

bool LoadHookRVAsFromJson(const wchar_t* jsonPath, HookAddrs& out) {
    HANDLE h = CreateFileW(jsonPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    DWORD sz = GetFileSize(h, nullptr);
    std::string s; s.resize(sz);
    DWORD rd = 0;
    BOOL ok = ReadFile(h, s.data(), sz, &rd, nullptr);
    CloseHandle(h);
    if (!ok) return false;          // handle read error

    // UTF-8 first, ANSI fallback
    int wlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(), (int)rd, nullptr, 0);
    if (wlen <= 0) wlen = MultiByteToWideChar(CP_ACP, 0, s.data(), (int)rd, nullptr, 0);
    std::wstring w; w.resize(wlen);
    MultiByteToWideChar((wlen > 0 ? CP_UTF8 : CP_ACP),
        (wlen > 0 ? MB_ERR_INVALID_CHARS : 0),
        s.data(), (int)rd, w.data(), wlen);

    extract_hex_field(w, L"rva_LoadCars", out.rva_LoadCars);
    extract_hex_field(w, L"rva_CupParse", out.rva_CupParse);
    extract_hex_field(w, L"rva_BuildGrid", out.rva_BuildGrid);
    extract_hex_field(w, L"rva_CarTablePtr", out.rva_CarTablePtr);
    extract_hex_field(w, L"rva_CarCount", out.rva_CarCount);
    extract_hex_field(w, L"rva_AISlot0", out.rva_AISlot0);
    extract_hex_field(w, L"rva_ActiveCupPtr", out.rva_ActiveCupPtr);
    extract_hex_field(w, L"rva_PlayersBase", out.rva_PlayersBase);
    extract_hex_field(w, L"rva_PlayersCount", out.rva_PlayersCount);
    extract_hex_field(w, L"rva_RaceResults", out.rva_RaceResults);
    extract_hex_field(w, L"rva_CupFinalize", out.rva_CupFinalize);

    // Parse rva_OppSlotIndex as an array of "0x..." strings
    {
        const std::wstring key = L"\"rva_OppSlotIndex\"";
        size_t p = w.find(key);
        if (p != std::wstring::npos) {
            size_t lb = w.find(L'[', p);
            size_t rb = (lb != std::wstring::npos) ? w.find(L']', lb) : std::wstring::npos;
            if (lb != std::wstring::npos && rb != std::wstring::npos) {
                std::wstring arr = w.substr(lb + 1, rb - lb - 1);
                size_t pos = 0; int i = 0;
                while (i < 16) {
                    size_t q = arr.find(L"0x", pos);
                    if (q == std::wstring::npos) break;
                    size_t e = q + 2;
                    while (e < arr.size() && iswxdigit(arr[e])) ++e;
                    uint32_t v = 0;
                    parse_hex(arr.substr(q + 2, e - (q + 2)), v);
                    out.rva_OppSlotIndex[i++] = v;
                    pos = e;
                }
            }
        }
    }
    return true;
}

bool SaveHookRVAsToJson(const wchar_t* jsonPath,
    const HookAddrs& a,
    const wchar_t* rvglExePath,
    const FILETIME* exeWriteTimeUtc)
{
    SYSTEMTIME st{};
    if (exeWriteTimeUtc) FileTimeToSystemTime(exeWriteTimeUtc, &st);
    wchar_t timeIso[64] = L"";
    if (exeWriteTimeUtc) {
        swprintf_s(timeIso, L"%04u-%02u-%02uT%02u:%02u:%02uZ",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    }

    const std::wstring dir = DirName(jsonPath);
    if (!dir.empty()) CreateDirectoryW(dir.c_str(), nullptr);

    wchar_t head[1024];
    int w = swprintf_s(head, L"{\n"
        L"  \"schema_version\": 1,\n"
        L"  \"rvgl_path\": \"%s\",\n"
        L"  \"rvgl_last_write\": \"%s\",\n"
        L"  \"rva_LoadCars\": \"0x%08X\",\n"
        L"  \"rva_CupParse\": \"0x%08X\",\n"
        L"  \"rva_BuildGrid\": \"0x%08X\",\n"
        L"  \"rva_CarTablePtr\": \"0x%08X\",\n"
        L"  \"rva_CarCount\": \"0x%08X\",\n"
        L"  \"rva_AISlot0\": \"0x%08X\",\n"
        L"  \"rva_ActiveCupPtr\": \"0x%08X\",\n"
        L"  \"rva_PlayersBase\": \"0x%08X\",\n"
        L"  \"rva_PlayersCount\": \"0x%08X\",\n"
        L"  \"rva_RaceResults\": \"0x%08X\",\n"
        L"  \"rva_CupFinalize\": \"0x%08X\"",
        rvglExePath ? rvglExePath : L"", timeIso,
        a.rva_LoadCars, a.rva_CupParse, a.rva_BuildGrid,
        a.rva_CarTablePtr, a.rva_CarCount, a.rva_AISlot0,
        a.rva_ActiveCupPtr, a.rva_PlayersBase, a.rva_PlayersCount,
        a.rva_RaceResults, a.rva_CupFinalize);

    std::wstring out(head, (size_t)w);
    out += L",\n  \"rva_OppSlotIndex\": [\n    ";
    for (int i = 0; i < 16; ++i) {
        wchar_t item[32];
        swprintf_s(item, L"\"0x%08X\"", a.rva_OppSlotIndex[i]);
        out += item;
        if (i != 15) out += L", ";
    }
    out += L"\n  ]\n}\n";

    HANDLE h = CreateFileW(jsonPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    int u8len = WideCharToMultiByte(CP_UTF8, 0, out.c_str(), (int)out.size(), nullptr, 0, nullptr, nullptr);
    std::string u8; u8.resize(u8len);
    WideCharToMultiByte(CP_UTF8, 0, out.c_str(), (int)out.size(), u8.data(), u8len, nullptr, nullptr);
    DWORD wr = 0; WriteFile(h, u8.data(), (DWORD)u8.size(), &wr, nullptr);
    CloseHandle(h);
    return wr == u8.size();
}

bool ResolveHookRVAs(HMODULE /*hModule*/, HookAddrs& out, std::string* dbgLogOpt)
{
    wchar_t exe[MAX_PATH]{};
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    std::wstring jsonPath = ComputeCupgenJsonPathFromExe(exe);

    bool ok = LoadHookRVAsFromJson(jsonPath.c_str(), out);
    if (dbgLogOpt) *dbgLogOpt = ok ? "Loaded addresses from JSON." : "Failed to load addresses JSON.";
    return ok;
}