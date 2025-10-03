// obtainmod.h — ObtainCustom gate + temp championship tracker (public API)
#pragma once
#include <string>   // for std::string
#include <vector>   // for std::vector
#include <cstdint>  // for uint8_t

namespace ObtainMod {
    bool InstallObtainSystem();
    bool GateCupFileNow(const char* cupPath, const char* cupId, bool showDialog = true);
    bool EnsureGateForCurrentCupOnce();
    bool GetLaunchedCupPath(std::string& outPath, std::string& outId);
    void SetActiveCupContext(const char* cupPath, const char* cupId);
    void SetActiveProfileName(const char* profileName);
    bool ComputeAiGridOrder(int mode, std::vector<uint8_t>& outAiOrder, int& outNumDrivers, int& outPlayerSlot);
}