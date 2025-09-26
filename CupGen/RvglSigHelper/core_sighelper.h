#pragma once
// core_sighelper.h — minimal, MinHook-free dependencies for signatures.*
// Used ONLY by RvglSigHelper. Header-only API declared here, implemented in .cpp.

#define NOMINMAX
#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <cstdio>
#include <cstdarg>
#include <vector>
#include <string>

namespace RvglSigCore {

    // ============= Logging ============
    void logf(const char* fmt, ...);

    // ============= File IO ============
    bool ReadFileAllW(const wchar_t* path, std::vector<uint8_t>& out);

    // ============= PE (on-disk) parsing ============
    struct PeImage {
        const uint8_t* base = nullptr;
        size_t         size = 0;
        const IMAGE_DOS_HEADER* dos = nullptr;
        const IMAGE_NT_HEADERS* nt = nullptr;
        const IMAGE_SECTION_HEADER* sects = nullptr;
        uint16_t num_sects = 0;

        bool init(const uint8_t* bytes, size_t len);
        const IMAGE_SECTION_HEADER* find_section(const char name8[8]) const;
        bool get_section_data(const char name8[8],
            const uint8_t*& outPtr, size_t& outLen, uint32_t& outRva) const;
        const uint8_t* rva_to_ptr(uint32_t rva, size_t minBytes = 1) const;
    };

    // ============= Signature parsing & scanning ============
    bool ParseSignature(const char* spec,
        std::vector<uint8_t>& bytes,
        std::vector<uint8_t>& mask);

    size_t ScanBytes(const uint8_t* hay, size_t hayLen,
        const std::vector<uint8_t>& pat,
        const std::vector<uint8_t>& msk);

    const uint8_t* ScanSignature(const uint8_t* hay, size_t hayLen,
        const char* spec, size_t& outOffset);

    // ============= RVA/VA helpers ============
    uintptr_t AbsFromMaybeRva(uintptr_t moduleBaseVA, uint32_t maybeRvaOrVa);
    bool      rva_is_probably_va(uint32_t v);

    // ============= No-op hook stub (keeps shared code happy) ============
    template <typename T>
    inline bool HookFunction(void*, void*, T*) { return false; }

} // namespace RvglSigCore

// ----- Thin, project-local "using" layer so signatures.* can call plain names -----
// If your signatures.cpp uses these unqualified names, route them here:
using RvglSigCore::logf;
using RvglSigCore::ReadFileAllW;
using RvglSigCore::PeImage;
using RvglSigCore::ParseSignature;
using RvglSigCore::ScanBytes;
using RvglSigCore::ScanSignature;
using RvglSigCore::AbsFromMaybeRva;
using RvglSigCore::rva_is_probably_va;
