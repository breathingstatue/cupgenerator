#pragma once
#include <cstdint>
#include "signatures.h"   // HookAddrs + ResolveHookRVAs declaration

// Single global with resolved RVAs (defined in signatures.cpp)
extern HookAddrs g_addrs;

// AI slot layout used by opponentsmod.cpp
static constexpr size_t AI_SLOT_INTS = 0x25;                       // 37 dwords
static constexpr size_t AI_SLOT_STRIDE = AI_SLOT_INTS * sizeof(int); // 0x94 bytes

// Initialize g_addrs (JSON -> in-proc signature scan -> hardcoded fallbacks)
bool InitAddresses();
