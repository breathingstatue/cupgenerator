#pragma once
#define NOMINMAX

#include <windows.h>
#include <psapi.h>
#include <cstdint>
#include <cstddef>
#include <string>
#include "MinHook.h"

// =================== Globals (owned by core.cpp) ===================
extern HMODULE     gModule;
extern uintptr_t   gExeBase;
extern size_t      gExeSize;
extern std::string gTargetModuleName;

// =================== Core lifecycle ================================
void Core_OnAttach(HMODULE hModule);
void Core_OnDetach();

// =================== Logging / utils ===============================
std::string get_env(const char* name);
uintptr_t   AbsFromMaybeRva(uintptr_t val);

// =================== Diagnostics ===================================
void        LogMem(void* p);
const char* mh_errstr(MH_STATUS st);

// =================== Hook helpers ==================================
// MinHook bootstrap
bool EnsureMinHook();

// Primary hook helper implemented in core.cpp (MinHook wrapper)
bool HookFunction(uintptr_t absAddr, LPVOID detour, LPVOID* origOut);

// Convenience overload when you already have a function pointer
inline bool HookFunctionPtr(void* absPtr, void* detour, void** origOut) {
    return HookFunction(reinterpret_cast<uintptr_t>(absPtr),
        reinterpret_cast<LPVOID>(detour),
        reinterpret_cast<LPVOID*>(origOut));
}

// =================== Module query ==================================
bool GetModuleInfoByName(const char* moduleName, uintptr_t& base, size_t& size);