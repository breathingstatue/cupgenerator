#pragma once
// common/hook_addrs.h
// Shared between RVGLCupOpponents (mod) and RvglSigHelper (scanner)

#include <cstdint>

struct HookAddrs {
    uint32_t rva_LoadCars = 0;
    uint32_t rva_CupParse = 0;
    uint32_t rva_BuildGrid = 0;
    uint32_t rva_CarTablePtr = 0;
    uint32_t rva_CarCount = 0;
    uint32_t rva_AISlot0 = 0;
    uint32_t rva_ActiveCupPtr = 0;
    uint32_t rva_PlayersBase = 0;
    uint32_t rva_PlayersCount = 0;
    uint32_t rva_RaceResults = 0;
    uint32_t rva_CupFinalize = 0;
    uint32_t rva_OppSlotIndex[16]{};

    // already added by you:
    uint32_t rva_MenuState = 0;       // [*MenuState + 0x04] = selected index
    uint32_t rva_BuiltinCupsBase = 0; // builtin cups table base
    uint32_t rva_CustomCupsList = 0;  // ptr to custom cups array

    // add these two for the frontend handle:
    uint32_t rva_FrontendInit = 0;    // the frontend/menu bootstrap function (your target)
};
