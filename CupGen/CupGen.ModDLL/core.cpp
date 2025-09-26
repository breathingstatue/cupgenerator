// core.cpp — no debug windows, no file logging
#include "core.h"
#include <windows.h>
#include <Psapi.h>
#include <cstring>
#include <mutex>
#include <string>
#include "MinHook.h"

#pragma comment(lib, "Psapi.lib")

HMODULE     gModule = nullptr;
uintptr_t   gExeBase = 0;
size_t      gExeSize = 0;
std::string gTargetModuleName;

// ============================== ENV HELPER ==============================

std::string get_env(const char* name) {
    char* buf = nullptr;
    size_t len = 0;
    if (_dupenv_s(&buf, &len, name) != 0 || !buf) return {};
    std::string s(buf);
    free(buf);
    return s;
}

// ============================== ADDR HELPERS ============================

uintptr_t AbsFromMaybeRva(uintptr_t val) {
    if (!gExeBase || !gExeSize) {
        HMODULE h = GetModuleHandleA(nullptr);
        MODULEINFO mi{};
        if (h && GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof(mi))) {
            gExeBase = (uintptr_t)mi.lpBaseOfDll;
            gExeSize = (size_t)mi.SizeOfImage;
        }
    }
    if (!gExeBase || !gExeSize) return val;
    if (val >= gExeBase && val < gExeBase + gExeSize) return val;
    return gExeBase + val;
}

// Kept as stubs so callers compile, but do nothing.
static inline const char* prot_str(DWORD) { return ""; }

void LogMem(void* /*p*/) {
    // intentionally no-op
}

// ============================== MINHOOK WRAPPERS ========================

static bool EnsureMinHook() {
    static bool inited = false;
    static std::once_flag once;
    std::call_once(once, [] {
        auto st = MH_Initialize();
        inited = (st == MH_OK || st == MH_ERROR_ALREADY_INITIALIZED);
        });
    return inited;
}

bool HookFunction(uintptr_t absAddr, LPVOID detour, LPVOID* origOut) {
    if (!EnsureMinHook()) return false;
    if (!absAddr) return false;

    // No logging; just create & enable the hook
    MH_STATUS st = MH_CreateHook(reinterpret_cast<LPVOID>(absAddr), detour, origOut);
    if (st != MH_OK && st != MH_ERROR_ALREADY_CREATED) {
        return false;
    }
    st = MH_EnableHook(reinterpret_cast<LPVOID>(absAddr));
    if (st != MH_OK && st != MH_ERROR_ENABLED) {
        return false;
    }
    return true;
}

bool GetModuleInfoByName(const char* moduleName, uintptr_t& base, size_t& size) {
    HMODULE h = moduleName && *moduleName ? GetModuleHandleA(moduleName) : GetModuleHandleA(nullptr);
    if (!h) return false;
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), h, &mi, sizeof(mi))) return false;
    base = (uintptr_t)mi.lpBaseOfDll;
    size = (size_t)mi.SizeOfImage;
    return true;
}

void Core_OnAttach(HMODULE hModule) {
    gModule = hModule;
    GetModuleInfoByName(nullptr, gExeBase, gExeSize);
    (void)EnsureMinHook(); // initialize MinHook once
}

void Core_OnDetach() {
    MH_Uninitialize();
}