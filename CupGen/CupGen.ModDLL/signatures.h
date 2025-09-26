// signatures.h
#pragma once
#include <string>
#include <windows.h>
#include "hook_addrs.h"

// Single canonical declaration (C++ linkage). Default arg here is OK.
bool ResolveHookRVAs(HMODULE hModule,
    HookAddrs& out,
    std::string* dbgLogOpt = nullptr);

// JSON I/O for canonical CupGen path
bool LoadHookRVAsFromJson(const wchar_t* jsonPath, HookAddrs& out);
bool SaveHookRVAsToJson(const wchar_t* jsonPath,
    const HookAddrs& addrs,
    const wchar_t* rvglExePath,
    const FILETIME* exeWriteTimeUtc);

// Path helpers
std::wstring DeriveRvglRootFromExe(const wchar_t* rvglExePath);
std::wstring ComputeCupgenJsonPathFromRoot(const wchar_t* rvglRoot);
std::wstring ComputeCupgenJsonPathFromExe(const wchar_t* rvglExePath);
