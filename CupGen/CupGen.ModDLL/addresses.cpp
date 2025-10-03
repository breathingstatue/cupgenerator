#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_WARNINGS
#include "addresses.h"
#include "signatures.h"   // JSON + path helpers
#include "CupGenGlobals.h"   // CupGen::CupGenDir()

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdio>
#include <string>
#include <cwchar>

// ======================================================================
// One and only definition of g_addrs in the MOD DLL
// ======================================================================
HookAddrs g_addrs{};

// ---------------- tiny updater JSON (mod folder) ----------------
extern "C" IMAGE_DOS_HEADER __ImageBase;

static bool LoadUpdateJson_ModFolder(HookAddrs& out) {
    wchar_t modPath[MAX_PATH]{};
    if (!GetModuleFileNameW((HMODULE)&__ImageBase, modPath, MAX_PATH))
        return false;

    std::wstring dir(modPath);
    const size_t slash = dir.find_last_of(L"\\/");
    if (slash != std::wstring::npos) dir.resize(slash);
    const std::wstring jsonPath = dir + L"\\update.json";

    FILE* fp = _wfopen(jsonPath.c_str(), L"rb");
    if (!fp) return false;
    fseek(fp, 0, SEEK_END);
    const long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz <= 0) { fclose(fp); return false; }

    std::string s((size_t)sz, '\0');
    fread(s.data(), 1, (size_t)sz, fp);
    fclose(fp);

    auto getHex = [&](const char* key, uint32_t& outVal)->bool {
        auto pos = s.find(key);
        if (pos == std::string::npos) return false;
        pos = s.find("0x", pos);
        if (pos == std::string::npos) return false;
        unsigned v = 0;
        if (sscanf_s(s.c_str() + pos, "0x%x", &v) == 1) { outVal = v; return true; }
        return false;
        };

    int ok = 0;
    ok += getHex("\"rva_LoadCars\"", out.rva_LoadCars);
    ok += getHex("\"rva_CupParse\"", out.rva_CupParse);
    ok += getHex("\"rva_BuildGrid\"", out.rva_BuildGrid);
    ok += getHex("\"rva_CarTablePtr\"", out.rva_CarTablePtr);
    ok += getHex("\"rva_CarCount\"", out.rva_CarCount);
    ok += getHex("\"rva_AISlot0\"", out.rva_AISlot0);
    ok += getHex("\"rva_ActiveCupPtr\"", out.rva_ActiveCupPtr);
    ok += getHex("\"rva_PlayersBase\"", out.rva_PlayersBase);
    ok += getHex("\"rva_PlayersCount\"", out.rva_PlayersCount);
    ok += getHex("\"rva_RaceResults\"", out.rva_RaceResults);
    ok += getHex("\"rva_CupFinalize\"", out.rva_CupFinalize);
    ok += getHex("\"rva_MenuState\"", out.rva_MenuState);
    ok += getHex("\"rva_BuiltinCupsBase\"", out.rva_BuiltinCupsBase);
    ok += getHex("\"rva_CustomCupsList\"", out.rva_CustomCupsList);
    ok += getHex("\"rva_FrontendInit\"", out.rva_FrontendInit);

    // Opp slots
    auto arr = s.find("\"rva_OppSlotIndex\"");
    if (arr != std::string::npos) {
        auto pos = s.find('[', arr);
        if (pos != std::string::npos) {
            for (int i = 0; i < 16; ++i) {
                pos = s.find("0x", pos);
                if (pos == std::string::npos) break;
                unsigned v = 0;
                if (sscanf_s(s.c_str() + pos, "0x%x", &v) == 1)
                    out.rva_OppSlotIndex[i] = v;
                pos += 2;
            }
        }
    }
    return ok > 0;
}

// ---------------- local helpers ----------------

static void ApplyFallbacks(HookAddrs& a) {
    // function RVAs (old 0x004xxxxx -> RVA 0x000xxxxx)
    if (!a.rva_LoadCars)     a.rva_LoadCars     = 0x0003FAC0;
    if (!a.rva_CupParse)     a.rva_CupParse     = 0x0004BB80;
    if (!a.rva_BuildGrid)    a.rva_BuildGrid    = 0x00049DC0;
    if (!a.rva_RaceResults)  a.rva_RaceResults  = 0x000604C0;
    if (!a.rva_CupFinalize)  a.rva_CupFinalize  = 0x00048500;

    // data RVAs
    if (!a.rva_CarTablePtr)  a.rva_CarTablePtr  = 0x002FAB50; // close to your JSON (may be off by +4)
    if (!a.rva_CarCount)     a.rva_CarCount     = 0x002FAB58; // close to your JSON (may be off by +4)
    if (!a.rva_AISlot0)      a.rva_AISlot0      = 0x002FBC90; // exact match to your JSON
    if (!a.rva_ActiveCupPtr) a.rva_ActiveCupPtr = 0x0025EC60; // exact match to your JSON

    // These two vary across builds; prefer scanner/JSON. Safer to leave 0 if not known:
    // if (!a.rva_PlayersBase)  a.rva_PlayersBase  = 0x002A7400; // only if you're sure
    // if (!a.rva_PlayersCount) a.rva_PlayersCount = 0x002A7408; // only if you're sure

    // Opp slots synthesized from AISlot0 if array is empty.
    if (!a.rva_OppSlotIndex[0] && a.rva_AISlot0) {
        constexpr size_t AI_SLOT_INTS = 0x25;
        constexpr size_t AI_SLOT_STRIDE = AI_SLOT_INTS * sizeof(int); // 0x94
        const uint32_t baseLegacy = a.rva_AISlot0 - static_cast<uint32_t>(AI_SLOT_STRIDE);
        for (int i = 0; i < 16; ++i)
            a.rva_OppSlotIndex[i] = baseLegacy + static_cast<uint32_t>(i * AI_SLOT_STRIDE);
    }
}

static std::wstring Widen(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(n ? n - 1 : 0, L'\0');
    if (n > 1) MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    return w;
}

static std::wstring GetExePathW() {
    wchar_t buf[MAX_PATH]{}; GetModuleFileNameW(nullptr, buf, MAX_PATH);
    return std::wstring(buf);
}

static FILETIME GetWriteTimeUtcW(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA fad{}; FILETIME ft{};
    if (GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad)) ft = fad.ftLastWriteTime;
    return ft;
}

bool InitAddresses() {
    // 1) updater's update.json next to the mod DLL (if present)
    bool loaded = LoadUpdateJson_ModFolder(g_addrs);

    // 2) canonical JSON under <root>\packs\rvgl_assets\cups\cupgen\
    //    Prefer CupGen::CupGenDir(); it creates the dir if missing.
    const std::string jsonUtf8 = CupGen::CupGenDir() + "\\rvgl_addrs.json";
    const std::wstring jsonPath = Widen(jsonUtf8);

    if (!loaded) {
        loaded = LoadHookRVAsFromJson(jsonPath.c_str(), g_addrs);
    }

    // 3) If still not loaded, persist *fallbacks* to JSON with exe metadata,
    //    so the user / scanner can see & update it later.
    if (!loaded) {
        ApplyFallbacks(g_addrs);
        const std::wstring exePath = GetExePathW();
        const FILETIME exeWriteUtc = GetWriteTimeUtcW(exePath);
        SaveHookRVAsToJson(jsonPath.c_str(), g_addrs, exePath.c_str(), &exeWriteUtc);
        return true;
    }

    // Always ensure safety defaults fill any missing fields
    ApplyFallbacks(g_addrs);
    return true;
}