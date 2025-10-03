#pragma once
// RvglSigHelper/signatures_helper.h  (ON-DISK scan only)

#include <string>
#include <windows.h>       // for FILETIME
#include "hook_addrs.h"

// On-disk scan of rvgl.exe (or root) to produce HookAddrs.
// The 3rd param can be used for debug notes or to return a derived path if you want.
bool ResolveHookRVAsFromFile(const wchar_t* rvglExeOrRoot,
    HookAddrs& out,
    std::wstring* debugOutOpt = nullptr);

// (Optional) compatibility wrapper for legacy 2-arg callers.
// NOTE: Still requires the 3-arg implementation to be defined in the .cpp.
inline bool ResolveHookRVAsFromFile(const wchar_t* rvglExeOrRoot,
    HookAddrs& out)
{
    return ResolveHookRVAsFromFile(rvglExeOrRoot, out, nullptr);
}

// (Optionally) re-use the same JSON/path helper declarations:
bool LoadHookRVAsFromJson(const wchar_t* jsonPath, HookAddrs& out);

bool SaveHookRVAsToJson(const wchar_t* jsonPath,
    const HookAddrs& addrs,
    const wchar_t* rvglExePath,
    const FILETIME* exeWriteTimeUtc);

std::wstring ComputeCupgenJsonPathFromExe(const wchar_t* rvglExePath);
std::wstring ComputeCupgenJsonPathFromRoot(const wchar_t* rvglRoot);
std::wstring DeriveRvglRootFromExe(const wchar_t* rvglExePath);
