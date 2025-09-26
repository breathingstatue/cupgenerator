// dllmain.cpp — glue; Obtain owns StartCup hook; StartGrid invoked via OnStartCup()
// Build: x64, /std:c++17 (link Psapi.lib + MinHook)

#include <windows.h>      // for BOOL, HMODULE, Sleep, DisableThreadLibraryCalls
#include "core.h"
#include "opponentsmod.h"
#include "obtainmod.h"
#include "addresses.h"    // g_addrs + InitAddresses()

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    switch (reason) {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(hModule);
        Core_OnAttach(hModule);

        // tiny settle
        Sleep(50);

        // Figure out which module to hook (rvgl.exe by default)
        gTargetModuleName = get_env("RVGL_OPP_MODULE");
        if (gTargetModuleName.empty()) gTargetModuleName = "rvgl.exe";
        if (!GetModuleInfoByName(gTargetModuleName.c_str(), gExeBase, gExeSize)) {
            // Nothing to hook; keep process happy.
            return TRUE;
        }

        // 1) Load addresses (update.json → in-proc scan → fallbacks)
        if (!InitAddresses()) {
            // Couldn’t resolve RVAs; skip installing hooks but don’t crash host.
            return TRUE;
        }

        // 2) Install hooks (modules use AbsFromMaybeRva(g_addrs.*))
        (void)ObtainMod::InstallObtainSystem();     // StartCup + RaceResults + CupFinalize
        (void)OpponentsMod::InstallOpponentsHooks(); // LoadCars + BuildGrid
        break;
    }
    case DLL_PROCESS_DETACH:
        Core_OnDetach();
        break;
    }
    return TRUE;
}