// obtainmod.h — ObtainCustom gate + temp championship tracker (public API)
#pragma once
#include <string>   // for std::string
#include <vector>   // for std::vector
#include <cstdint>  // for uint8_t

namespace ObtainMod {
    bool InstallObtainSystem();

    // New: immediate gate API (id/path already known)
    bool GateCupFileNow(const char* cupPath, const char* cupId, bool showDialog = true);

    // Existing utility you already have:
    bool EnsureGateForCurrentCupOnce();
    bool GetLaunchedCupPath(std::string& outPath, std::string& outId);

    // Already present:
    void SetActiveCupContext(const char* cupPath, const char* cupId);
    void SetActiveProfileName(const char* profileName);

    // StartGrid helper:
    bool ComputeAiGridOrder(int mode, std::vector<uint8_t>& outAiOrder, int& outNumDrivers, int& outPlayerSlot);
}