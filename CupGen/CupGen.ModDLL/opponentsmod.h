#pragma once
namespace OpponentsMod {
    bool InstallOpponentsHooks();
    // Let ObtainMod know which cup is active (path and id). Implemented in obtainmod.
    void NotifyActiveCup(const char* cupPathResolved);
}