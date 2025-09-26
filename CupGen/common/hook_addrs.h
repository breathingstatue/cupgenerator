#pragma once
// common/hook_addrs.h
// Shared between RVGLCupOpponents (mod) and RvglSigHelper (scanner)

#include <cstdint>

struct HookAddrs {
    uint32_t rva_LoadCars{};
    uint32_t rva_CupParse{};
    uint32_t rva_BuildGrid{};
    uint32_t rva_CarTablePtr{};
    uint32_t rva_CarCount{};
    uint32_t rva_AISlot0{};
    uint32_t rva_ActiveCupPtr{};
    uint32_t rva_PlayersBase{};
    uint32_t rva_PlayersCount{};
    uint32_t rva_RaceResults{};
    uint32_t rva_CupFinalize{};
    uint32_t rva_OppSlotIndex[16]{};
};
