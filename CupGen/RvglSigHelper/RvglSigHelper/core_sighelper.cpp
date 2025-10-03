// RvglSigHelper/core.cpp
#include "core_sighelper.h"
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace RvglSigCore {

    // ---------------- Logging ----------------
    void logf(const char* fmt, ...)
    {
        char buf[2048];
        va_list ap; va_start(ap, fmt);
        int n = vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        if (n < 0) return;
        fwrite(buf, 1, (size_t)std::min(n, (int)sizeof(buf)), stderr);
        fputc('\n', stderr);
        OutputDebugStringA(buf);
        OutputDebugStringA("\n");
    }

    // ---------------- File IO ----------------
    bool ReadFileAllW(const wchar_t* path, std::vector<uint8_t>& out)
    {
        out.clear();
        if (!path || !*path) return false;

        HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;

        LARGE_INTEGER li{};
        if (!GetFileSizeEx(h, &li) || li.QuadPart <= 0 || li.QuadPart > (LONGLONG)SIZE_MAX) {
            CloseHandle(h);
            return false;
        }

        const size_t want = (size_t)li.QuadPart;
        out.resize(want);

        size_t total = 0;
        while (total < want) {
            DWORD chunk = 0;
            const DWORD ask = (DWORD)std::min<size_t>(want - total, 1 << 20); // read in chunks (1 MB)
            if (!ReadFile(h, out.data() + total, ask, &chunk, nullptr)) {
                CloseHandle(h);
                out.clear();
                return false;
            }
            if (chunk == 0) break; // EOF
            total += chunk;
        }

        CloseHandle(h);
        if (total != want) {
            out.clear();
            return false;
        }
        return true;
    }

    // ---------------- PE parsing ----------------
    bool PeImage::init(const uint8_t* bytes, size_t len)
    {
        base = bytes; size = len; dos = nullptr; nt = nullptr; sects = nullptr; num_sects = 0;
        if (!bytes || len < sizeof(IMAGE_DOS_HEADER)) return false;

        dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > len) return false;
        nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(bytes + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        if (nt->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER)) return false;

        num_sects = nt->FileHeader.NumberOfSections;
        size_t sect_off = (size_t)dos->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER) + nt->FileHeader.SizeOfOptionalHeader;
        if (sect_off + (size_t)num_sects * sizeof(IMAGE_SECTION_HEADER) > len) return false;

        sects = reinterpret_cast<const IMAGE_SECTION_HEADER*>(bytes + sect_off);
        return true;
    }

    const IMAGE_SECTION_HEADER* PeImage::find_section(const char name8[8]) const
    {
        if (!sects || !name8) return nullptr;
        for (uint16_t i = 0; i < num_sects; ++i) {
            char nm[9] = { 0 };
            memcpy(nm, sects[i].Name, 8);
            // Compare either exact 8 or null-terminated
            if (strncmp(nm, name8, 8) == 0 || strcmp(nm, name8) == 0)
                return &sects[i];
        }
        return nullptr;
    }

    bool PeImage::get_section_data(const char name8[8],
        const uint8_t*& outPtr, size_t& outLen, uint32_t& outRva) const
    {
        outPtr = nullptr; outLen = 0; outRva = 0;
        auto s = find_section(name8);
        if (!s) return false;

        if ((size_t)s->PointerToRawData + s->SizeOfRawData > size) return false;

        outPtr = base + s->PointerToRawData;
        outLen = (size_t)s->SizeOfRawData;
        outRva = s->VirtualAddress;
        return true;
    }

    const uint8_t* PeImage::rva_to_ptr(uint32_t rva, size_t minBytes) const
    {
        if (!sects) return nullptr;
        for (uint16_t i = 0; i < num_sects; ++i) {
            const auto& s = sects[i];
            uint32_t start = s.VirtualAddress;
            uint32_t end = start + std::max<uint32_t>(s.Misc.VirtualSize, s.SizeOfRawData);
            if (rva >= start && rva + minBytes <= end) {
                size_t offs = (size_t)(rva - start);
                if ((size_t)s.PointerToRawData + offs + minBytes <= size)
                    return base + s.PointerToRawData + offs;
            }
        }
        return nullptr;
    }

    // ---------------- Signature parsing & scanning ----------------
    static inline bool ishex(char c) {
        return (c >= '0' && c <= '9') ||
            (c >= 'A' && c <= 'F') ||
            (c >= 'a' && c <= 'f');
    }

    bool ParseSignature(const char* spec,
        std::vector<uint8_t>& bytes,
        std::vector<uint8_t>& mask)
    {
        bytes.clear(); mask.clear();
        if (!spec) return false;

        const char* p = spec;
        while (*p) {
            // skip spaces
            while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') ++p;
            if (!*p) break;

            if (*p == '?') {
                // accept '?' or '??'
                ++p; if (*p == '?') ++p;
                bytes.push_back(0x00);
                mask.push_back(0x00); // wildcard
                continue;
            }

            if (!ishex(*p)) return false;
            char h1 = *p++;
            // skip spaces between nibbles (rare in specs)
            while (*p == ' ') ++p;
            if (!ishex(*p)) return false;
            char h2 = *p++;

            auto hexval = [](char c)->uint8_t {
                if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
                if (c >= 'A' && c <= 'F') return (uint8_t)(c - 'A' + 10);
                return (uint8_t)(c - 'a' + 10);
                };
            uint8_t b = (uint8_t)((hexval(h1) << 4) | hexval(h2));
            bytes.push_back(b);
            mask.push_back(0xFF); // exact
        }

        return !bytes.empty() && bytes.size() == mask.size();
    }

    size_t ScanBytes(const uint8_t* hay, size_t hayLen,
        const std::vector<uint8_t>& pat,
        const std::vector<uint8_t>& msk)
    {
        if (!hay || hayLen == 0 || pat.empty() || pat.size() != msk.size() || pat.size() > hayLen)
            return SIZE_MAX;

        const size_t n = pat.size();
        for (size_t i = 0; i + n <= hayLen; ++i) {
            const uint8_t* h = hay + i;
            size_t j = 0;
            for (; j < n; ++j) {
                if (msk[j] == 0x00) continue; // wildcard
                if ((h[j] & msk[j]) != (pat[j] & msk[j])) break;
            }
            if (j == n) return i;
        }
        return SIZE_MAX;
    }

    const uint8_t* ScanSignature(const uint8_t* hay, size_t hayLen,
        const char* spec, size_t& outOffset)
    {
        std::vector<uint8_t> pat, msk;
        if (!ParseSignature(spec, pat, msk)) return nullptr;
        size_t off = ScanBytes(hay, hayLen, pat, msk);
        if (off == SIZE_MAX) return nullptr;
        outOffset = off;
        return hay + off;
    }

    // ---------------- RVA/VA helpers ----------------
    uintptr_t AbsFromMaybeRva(uintptr_t moduleBaseVA, uint32_t maybeRvaOrVa)
    {
        // Heuristic: treat large values as VA, small as RVA (good enough for our helper use).
        if (maybeRvaOrVa >= 0x01000000u) return (uintptr_t)maybeRvaOrVa;
        return moduleBaseVA + (uintptr_t)maybeRvaOrVa;
    }

    bool rva_is_probably_va(uint32_t v)
    {
        return v >= 0x01000000u;
    }

} // namespace RvglSigCore