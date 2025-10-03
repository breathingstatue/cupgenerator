// RvglSigHelper/signatures_helper.cpp
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>
#include <unordered_map>

#include "signatures_helper.h"   // defines HookAddrs
#include "core_sighelper.h"      // RvglSigCore::PeImage, ParseSignature, ScanSignature, ReadFileAllW, ...

#ifndef RVGLSIGHELPER_NO_LOG
#define RVGLSIGHELPER_NO_LOG 0
#endif

using RvglSigCore::PeImage;
using RvglSigCore::ScanSignature;

// ============================ fwd decls ============================
static bool RVAIsInExec_UsingPe(const PeImage& pe, uint32_t rva);
static inline bool RVAIsInData_UsingPe(const PeImage& pe, uint32_t rva);

// ============================ signatures ===========================
// Leave these empty; paste your own long byte lines.
static const char* SIG_LoadCars_EXACT =
    "41 57 41 56 41 55 41 54 55 57 56 53 48 81 EC 48 03 00 00 48 8B 05 F6 75 26 00 "
    "C7 05 74 B0 2B 00 31 00 00 00 80 38 00 74 17 48 81 C4 48 03 00 00 5B 5E 5F 5D "
    "41 5C 41 5D 41 5E 41 5F C3 0F 1F 00 4C 8D A4 24 20 01 00 00 45 31 C0 48 8D 15 "
    "B6 01 23 00 48 BF 00 00 00 00 00 00 01 00 4C 89 E1 48 8D 35 02 27 23 00 48 8D "
    "2D 33 B0 2B 00 E8 EE 75 0F 00 84 C0 0F 84 70 03 00 00 66 0F 1F 44 00 00 4C 89 "
    "E1 E8 08 77 0F 00 48 85 C0 0F 84 57 02 00 00 81 3D FD AF 2B 00 FF FF FF 7F 0F "
    "84 47 02 00 00 80 78 08 2E 4C 8D 68 08 75 07 41 80 7D 01 00 74 CE 80 78 08 2E "
    "75 18 41 80 7D 01 2E 75 11 41 80 7D 02 00 74 BA 66 2E 0F 1F 84 00 00 00 00 00 "
    "4C 8D 74 24 20 BA 00 01 00 00 4D 89 E9 4C 89 F1 4C 8D 05 48 01 23 00 E8 F4 39 "
    "0F 00 31 D2 4C 89 F1 E8 2A 75 0F 00 84 C0 74 86 48 8D 1D DF 24 23 00 0F 1F 80 "
    "00 00 00 00 4C 89 E9 E8 A0 71 17 00 4C 89 E9 49 89 C0 48 8B 03 48 8D 50 05 E8 "
    "9E 3C 0F 00 85 C0 0F 84 56 FF FF FF 48 83 C3 08 48 39 DE 75 D5 4D 89 E9 4C 8D "
    "05 0F FD 22 00 BA 00 01 00 00 4C 89 F1 E8 96 39 0F 00 45 31 C9 41 B8 01 00 00 "
    "00 4C 89 F1 48 8D 15 06 FD 22 00 E8 5E 53 0F 00 48 89 C3 48 85 C0 0F 84 12 FF "
    "FF FF 8B 05 24 AF 2B 00 48 8B 0D 15 AF 2B 00 83 C0 01 48 98 48 89 C2 48 C1 E2 "
    "04 48 01 C2 48 C1 E2 04 E8 8D 71 17 00 48 89 C2 48 85 C0 0F 84 7A 02 00 00 4C "
    "63 3D F2 AE 2B 00 48 89 05 E3 AE 2B 00 41 B9 01 00 00 00 41 B8 3F 00 00 00 4C "
    "89 F8 4C 89 F9 48 C1 E0 04 83 C1 01 49 01 C7 89 0D C9 AE 2B 00 4C 89 F8 48 C1 "
    "E0 04 4C 8D 3C 02 4C 89 EA 49 8D 4F 14 E8 4A 38 0F 00 41 C6 47 53 00 48 8D 15 "
    "ED FF 22 00 4C 89 F9 E8 D6 D8 17 00 41 C6 47 54 00 31 D2 48 89 D9 48 8B 05 65 "
    "25 23 00 41 C6 87 94 00 00 00 00 4D 8D 87 04 01 00 00 49 89 AF D8 00 00 00 49 "
    "89 87 E8 00 00 00 B8 FF FF FF FF 49 89 87 F0 00 00 00 31 C0 49 89 BF E0 00 00 "
    "00 49 C7 87 F8 00 00 00 00 00 00 00 41 C7 87 00 01 00 00 00 00 00 00 66 41 89 "
    "87 08 01 00 00 E8 C0 73 FC FF 4C 89 F1 45 31 C9 49 89 D8 83 F0 01 48 8D 15 1A "
    "FC 22 00 41 88 87 08 01 00 00 E8 01 54 0F 00 4C 8B 2D 02 BA A6 0A 49 89 C6 48 "
    "85 C0 75 0F E9 72 01 00 00 0F 1F 44 00 00 83 FB FF 74 23 4C 89 F1 E8 73 71 17 "
    "00 89 C3 89 C1 41 FF D5 85 C0 75 E8 83 FB 7B 75 0B 4C 89 F2 4C 89 F9 E8 40 B9 "
    "FF FF 4C 89 F9 E8 C8 BC FF FF 4C 89 F1 E8 60 71 17 00 4C 89 E1 E8 B8 74 0F 00 "
    "48 85 C0 0F 85 B0 FD FF FF 0F 1F 80 00 00 00 00 4C 89 E1 E8 F0 77 0F 00 8B 05 "
    "A2 AD 2B 00 44 8D 60 FF 41 83 FC 31 0F 8E 25 FD FF FF 49 63 C4 49 89 C5 49 C1 "
    "E5 04 49 01 C5 49 C1 E5 04 0F 1F 00 BB 10 34 00 00 BD 31 00 00 00 EB 19 0F 1F "
    "40 00 0F 84 92 00 00 00 83 C5 01 48 81 C3 10 01 00 00 44 39 E5 7D 67 48 8B 15 "
    "4C AD 2B 00 4E 8D 0C 2A 48 01 DA 8B 82 EC 00 00 00 41 39 81 EC 00 00 00 7D CE "
    "48 8D BC 24 30 02 00 00 B9 22 00 00 00 4C 89 CE 83 C5 01 F3 48 A5 B9 22 00 00 "
    "00 4C 89 CF 48 89 D6 F3 48 A5 48 8D B4 24 30 02 00 00 B9 22 00 00 00 48 8B 3D "
    "FE AC 2B 00 48 01 DF 48 81 C3 10 01 00 00 F3 48 A5 44 39 E5 7C 99 41 83 EC 01 "
    "49 81 ED 10 01 00 00 41 83 FC 31 0F 85 5F FF FF FF E9 6B FC FF FF 66 90 49 C7 "
    "C0 FF FF FF FF 4C 89 C9 E8 F1 39 0F 00 85 C0 0F 89 57 FF FF FF 48 8B 15 B2 AC "
    "2B 00 4E 8D 0C 2A 48 01 DA E9 70 FF FF FF 48 8D 0D 1F FE 22 00 E8 6A B7 FF FF "
    "48 8B 05 23 64 26 00 C6 00 01 E9 24 FC FF FF 31 C9 E8 24 70 17 00 41 C6 87 09 "
    "01 00 00 01 E9 67 FC FF FF 48 8D 0D 18 FE 22 00 E8 3B B7 FF FF 48 89 D9 E8 03 "
    "70 17 00 E9 B6 FE FF FF 66 66 2E 0F 1F 84 00 00 00 00 00 0F 1F 00";

static const char* SIG_CupParse_EXACT =
    "41 56 41 55 41 54 55 57 56 53 48 81 EC E0 02 00 00 0F 11 B4 24 D0 02 00 00 "
    "48 8B 05 40 B5 25 00 80 38 00 74 1B 0F 10 B4 24 D0 02 00 00 48 81 C4 E0 02 00 "
    "00 5B 5E 5F 5D 41 5C 41 5D 41 5E C3 90 4C 8D 6C 24 20 45 31 C0 48 8D 15 3D 7E "
    "22 00 4C 89 E9 E8 49 B5 0E 00 84 C0 74 CA F3 0F 6F 35 8D 7E 22 00 48 8D 35 CE "
    "40 21 00 48 BD 03 00 00 00 01 00 00 00 0F 1F 40 00 4C 89 E9 E8 50 B6 0E 00 48 "
    "85 C0 0F 84 C7 01 00 00 81 3D AD FF 2A 00 FF FF FF 7F 0F 84 B7 01 00 00 80 78 "
    "08 2E 48 8D 58 08 75 06 80 7B 01 00 74 CF 80 78 08 2E 75 11 80 7B 01 2E 75 0B "
    "80 7B 02 00 74 BD 0F 1F 44 00 00 4C 8D A4 24 30 01 00 00 BA 00 01 00 00 49 89 "
    "D9 4C 89 E1 4C 8D 05 B7 7D 22 00 E8 41 79 0E 00 31 D2 4C 89 E1 E8 37 B4 0E 00 "
    "84 C0 74 8B 49 89 D9 4C 8D 05 A2 7D 22 00 BA 00 01 00 00 4C 89 E1 E8 1C 79 0E "
    "00 BA 2E 00 00 00 4C 89 E1 E8 C7 B0 16 00 48 89 C3 48 85 C0 0F 84 5B FF FF FF "
    "49 C7 C0 FF FF FF FF 48 8D 15 71 7D 22 00 48 89 C1 E8 CD 7B 0E 00 85 C0 0F 85 "
    "3D FF FF FF C6 03 00 48 8D 3D FB 2F 21 00 48 8D 1D F4 37 21 00 49 C7 C0 FF FF "
    "FF FF 48 89 DA 4C 89 E1 E8 A2 7B 0E 00 85 C0 0F 84 12 FF FF FF 49 C7 C0 FF FF "
    "FF FF 48 89 FA 4C 89 E1 E8 88 7B 0E 00 85 C0 0F 84 F8 FE FF FF 48 81 C3 98 01 "
    "00 00 48 81 C7 98 01 00 00 48 39 DE 75 B9 8B 05 A7 FE 2A 00 48 8B 0D A8 FE 2A "
    "00 8D 50 01 48 63 D2 48 69 D2 98 01 00 00 E8 AE B0 16 00 48 85 C0 0F 84 A7 01 "
    "00 00 48 63 1D 7E FE 2A 00 48 89 05 7F FE 2A 00 4C 89 E2 B9 33 00 00 00 41 B9 "
    "01 00 00 00 41 B8 3F 00 00 00 48 69 DB 98 01 00 00 4C 8D 34 18 31 C0 4C 89 F7 "
    "F3 48 AB 49 8D 4E 20 E8 77 77 0E 00 31 C0 49 89 6E 70 4C 89 F1 F3 0F 6F 05 F6 "
    "2E 21 00 F3 0F 6F 0D FE 2E 21 00 66 41 89 86 94 01 00 00 41 0F 11 76 60 41 0F "
    "11 86 54 01 00 00 41 0F 11 8E 64 01 00 00 83 05 0A FE 2A 00 01 E8 45 C7 FF FF "
    "4C 89 E9 E8 8D B4 0E 00 48 85 C0 0F 85 3D FE FF FF 0F 1F 40 00 4C 89 E9 E8 C8 "
    "B7 0E 00 8B 05 E2 FD 2A 00 8D 68 FF 85 ED 0F 8E BC FD FF FF 48 63 DD 48 69 DB "
    "98 01 00 00 0F 1F 44 00 00 45 31 E4 45 31 ED 66 90 48 8B 0D C1 FD 2A 00 49 C7 "
    "C0 FF FF FF FF 4A 8D 14 21 48 01 D9 E8 66 7A 0E 00 85 C0 0F 89 97 00 00 00 48 "
    "8B 15 9F FD 2A 00 48 8D BC 24 30 01 00 00 B9 33 00 00 00 48 8D 04 1A 48 89 C6 "
    "F3 48 A5 4A 8D 34 22 48 8D 78 08 48 83 E7 F8 48 8B 16 48 89 10 48 8B 96 90 01 "
    "00 00 48 89 90 90 01 00 00 48 29 F8 48 29 C6 05 98 01 00 00 C1 E8 03 89 C1 F3 "
    "48 A5 48 8D B4 24 30 01 00 00 48 8B 0D 46 FD 2A 00 48 8B 84 24 30 01 00 00 4C "
    "01 E1 48 89 01 48 8D 79 08 48 8B 84 24 C0 02 00 00 48 83 E7 F8 48 89 81 90 01 "
    "00 00 48 29 F9 48 29 CE 81 C1 98 01 00 00 C1 E9 03 F3 48 A5 41 83 C5 01 49 81 "
    "C4 98 01 00 00 41 39 ED 0F 8C 33 FF FF FF 48 81 EB 98 01 00 00 83 ED 01 0F 85 "
    "1B FF FF FF E9 C3 FC FF FF 48 8D 0D 3F 7B 22 00 E8 A2 C5 FF FF E9 DD FE FF FF "
    "66 66 2E 0F 1F 84 00 00 00 00 00 66 90";

static const char* SIG_BuildGrid_EXACT =
    "57 56 53 48 83 EC 40 48 63 05 16 1E 2B 00 48 8B 15 8B 4E 21 00 48 8B 35 04 C7 "
    "25 00 48 8B 3D 2D DB 25 00 48 8D 04 40 48 8D 04 82 C7 07 07 00 00 00 48 83 C7 "
    "28 8B 80 94 00 00 00 C7 06 07 00 00 00 89 46 08 E8 47 55 00 00 48 63 05 D4 1D "
    "2B 00 48 8B 0D 49 4E 21 00 48 8B 1D 52 D9 25 00 48 8D 04 40 48 8D 04 81 8B 4E "
    "08 C7 43 0C 07 00 00 00 0F B6 90 9C 00 00 00 88 56 31 89 53 14 0F B6 90 9D 00 "
    "00 00 8B 80 98 00 00 00 88 56 30 89 46 18 89 43 10 0F B6 47 76 89 53 18 88 46 "
    "32 89 43 20 8B 46 14 89 43 28 48 8B 05 E3 BF 25 00 0F B6 00 89 43 34 E8 B8 82 "
    "00 00 41 B9 01 00 00 00 41 B8 10 00 00 00 48 8D 4B 40 48 89 C2 E8 60 96 0E 00 "
    "48 89 7C 24 30 31 D2 44 8B 0D 62 1D 2B 00 C7 44 24 28 01 00 00 00 44 8B 05 4F "
    "1D 2B 00 B9 01 00 00 00 C7 44 24 20 01 00 00 00 E8 B1 54 00 00 48 8B 05 9A 4D "
    "21 00 83 78 68 01 7E 69 48 8B 3D AD BE 25 00 48 8D 35 B6 1D 2B 00 BB 01 00 00 "
    "00 90 48 63 16 41 89 DA 83 C3 01 B9 03 00 00 00 48 81 C6 94 00 00 00 48 89 D0 "
    "49 89 D0 48 C1 E0 04 48 01 D0 44 89 D2 48 C1 E0 04 48 03 07 89 5C 24 28 48 89 "
    "44 24 30 C7 44 24 20 02 00 00 00 44 8B 8E 70 FF FF FF E8 47 54 00 00 48 8B 05 "
    "30 4D 21 00 39 58 68 7F AB 48 83 C4 40 5B 5E 5F E9 3F 5A 00 00 66 66 2E 0F 1F "
    "84 00 00 00 00 00 0F 1F 40 00";

static const char* SIG_RaceResults_EXACT =
    "41 57 41 56 41 55 41 54 55 57 56 53 48 83 EC 38 48 8B 05 09 61 24 00 44 8B 18 "
    "48 89 CF 45 85 DB 0F 85 3A 02 00 00 4C 8B 25 83 72 24 00 49 8D 4C 24 40 E8 89 "
    "22 FF FF 45 8B 54 24 18 41 8B 74 24 04 89 C1 45 85 D2 0F 85 F4 01 00 00 45 8B "
    "44 24 14 48 8D 1D 76 4C 21 00 4C 8D 0D 9B 4B 21 00 45 85 C0 49 0F 44 D9 4C 8D "
    "05 6B 4C 21 00 83 F9 FF 74 09 E8 F9 1B FF FF 4C 8D 40 10 89 74 24 20 49 89 D9 "
    "48 8D 15 57 4C 21 00 31 F6 48 89 F9 41 BE 89 88 88 88 4C 8D 2D F5 4B 21 00 E8 "
    "00 D0 15 00 48 8D 15 51 4C 21 00 48 89 F9 E8 F1 CF 15 00 41 8B 44 24 04 48 8B "
    "1D 85 6E 24 00 85 C0 7F 15 E9 65 01 00 00 0F 1F 40 00 48 83 C3 10 39 C6 0F 8D "
    "55 01 00 00 8B 53 08 83 C6 01 85 D2 74 EA 48 8B 2B 41 89 F0 48 8D 15 3A 4C 21 "
    "00 48 89 F9 E8 AD CF 15 00 48 8D 15 89 4B 21 00 48 89 F9 4C 8D 3D 87 4B 21 00 "
    "4C 8D 85 70 6A 00 00 E8 90 CF 15 00 48 63 45 48 48 8D 15 68 4B 21 00 48 89 F9 "
    "49 89 C0 49 C1 E0 04 49 01 C0 48 8B 05 91 57 24 00 49 C1 E0 04 4C 03 00 E8 65 "
    "CF 15 00 44 8B 43 08 4D 69 C8 D3 4D 62 10 4C 89 C2 4D 69 C0 73 B2 E7 45 49 C1 "
    "E9 26 44 89 C8 41 69 C9 E8 03 00 00 49 C1 E8 2E 49 0F AF C6 29 CA 48 89 F9 48 "
    "C1 E8 25 89 54 24 20 48 8D 15 B1 4B 21 00 6B C0 3C 41 29 C1 E8 1B CF 15 00 44 "
    "8B 85 4C 0F 00 00 4D 69 C8 D3 4D 62 10 4C 89 C2 4D 69 C0 73 B2 E7 45 49 C1 E9 "
    "26 44 89 C8 41 69 C9 E8 03 00 00 49 C1 E8 2E 49 0F AF C6 29 CA 48 89 F9 48 C1 "
    "E8 25 89 54 24 20 48 8D 15 64 4B 21 00 6B C0 3C 41 29 C1 E8 CE CE 15 00 80 7B "
    "0C 00 4D 89 F8 48 89 F9 4D 0F 45 C5 48 8D 15 9C 4A 21 00 E8 B4 CE 15 00 80 BD "
    "81 6A 00 00 00 48 8D 15 89 4A 21 00 48 89 F9 4D 0F 44 FD 48 83 C3 10 4D 89 F8 "
    "E8 93 CE 15 00 48 8D 15 75 4A 21 00 48 89 F9 E8 84 CE 15 00 41 8B 44 24 04 39 "
    "C6 0F 8C AB FE FF FF 48 83 C4 38 5B 5E 5F 5D 41 5C 41 5D 41 5E 41 5F C3 66 0F "
    "1F 44 00 00 45 8B 4C 24 14 48 8D 1D 85 4A 21 00 45 85 C9 4C 8D 0D 7F 4A 21 00 "
    "49 0F 44 D9 E9 07 FE FF FF 90 E8 CB 9B FE FF E9 BC FD FF FF 66 0F 1F 44 00 00";

static const char* SIG_CupFinalize_EXACT =
    "41 56 41 55 41 54 55 57 56 53 48 81 EC 30 01 00 00 4C 8D 05 79 B3 22 00 BA 00 "
    "01 00 00 48 8D 5C 24 30 4C 8D 49 20 48 89 CE 48 89 D9 E8 6F B0 0E 00 45 31 C9 "
    "41 B8 01 00 00 00 48 89 D9 48 8D 15 59 B3 22 00 E8 37 CA 0E 00 49 89 C4 48 85 "
    "C0 0F 84 AE 00 00 00 45 31 C0 31 D2 48 89 C1 E8 7E EB FB FF 4D 89 E0 45 31 C9 "
    "48 89 D9 83 F0 01 48 8D 15 2B B3 22 00 88 86 95 01 00 00 E8 C0 CB 0E 00 49 89 "
    "C4 48 85 C0 74 7B 48 8D 7C 24 28 4C 8D 6C 24 2C 48 8D 6C 24 26 66 0F 1F 84 00 "
    "00 00 00 00 4C 89 E2 48 89 D9 E8 B5 B9 0E 00 84 C0 74 4B 48 8D 15 EC B2 22 00 "
    "48 89 D9 E8 32 B9 0E 00 84 C0 74 56 45 31 C0 4C 89 E2 48 89 D9 E8 A0 BD 0E 00 "
    "48 89 DA 48 89 F1 41 B9 01 00 00 00 41 B8 1F 00 00 00 E8 09 AF 0E 00 C6 46 1F "
    "00 4C 89 E2 48 89 D9 E8 6A B9 0E 00 84 C0 75 B5 4C 89 E1 E8 EE E8 16 00 90 48 "
    "81 C4 30 01 00 00 5B 5E 5F 5D 41 5C 41 5D 41 5E C3 0F 1F 00 48 8D 15 88 B2 22 "
    "00 48 89 D9 E8 C9 B8 0E 00 84 C0 74 1D 4C 89 E2 48 89 F9 E8 AA C0 0E 00 8B 44 "
    "24 28 89 46 64 E9 5E FF FF FF 66 0F 1F 44 00 00 48 8D 15 63 B2 22 00 48 89 D9 "
    "E8 99 B8 0E 00 84 C0 74 1D 4C 89 E2 48 89 F9 E8 7A C0 0E 00 8B 44 24 28 89 46 "
    "60 E9 2E FF FF FF 66 0F 1F 44 00 00 48 8D 15 3A B2 22 00 48 89 D9 E8 69 B8 0E "
    "00 84 C0 74 1D 4C 89 E2 48 89 F9 E8 4A C0 0E 00 8B 44 24 28 89 46 68 E9 FE FE "
    "FF FF 66 0F 1F 44 00 00 48 8D 15 12 B2 22 00 48 89 D9 E8 39 B8 0E 00 84 C0 75 "
    "2D 48 8D 15 08 B2 22 00 48 89 D9 E8 26 B8 0E 00 84 C0 74 32 4C 89 E2 48 89 F9 "
    "E8 07 C0 0E 00 8B 44 24 28 89 46 70 E9 BB FE FF FF 0F 1F 00 4C 89 E2 48 89 F9 "
    "E8 ED BF 0E 00 8B 44 24 28 89 46 6C E9 A1 FE FF FF 90 48 8D 15 CE B1 22 00 48 "
    "89 D9 E8 E1 B7 0E 00 84 C0 75 29 48 8D 15 C5 B1 22 00 48 89 D9 E8 CE B7 0E 00 "
    "84 C0 74 2D 48 8D 4E 7C 4D 89 E0 BA 06 00 00 00 E8 F9 C0 0E 00 E9 64 FE FF FF "
    "4C 89 E2 48 89 F9 E8 99 BF 0E 00 8B 44 24 28 89 46 74 E9 4D FE FF FF 48 8D 15 "
    "8D B1 22 00 48 89 D9 E8 8E B7 0E 00 84 C0 74 19 48 8D 8E 54 01 00 00 4D 89 E0 "
    "BA 10 00 00 00 E8 B6 C0 0E 00 E9 21 FE FF FF 48 8D 15 68 B1 22 00 48 89 D9 E8 "
    "62 B7 0E 00 84 C0 0F 84 0A FE FF FF 4C 89 E2 48 89 F9 E8 3F BF 0E 00 41 B8 01 "
    "00 00 00 4C 89 E2 48 89 D9 E8 BE BB 0E 00 4C 89 E2 4C 89 E9 E8 23 BF 0E 00 4C "
    "89 E2 48 89 E9 E8 F8 BB 0E 00 48 8D 4C 24 27 4C 89 E2 E8 EB BB 0E 00 44 8B 74 "
    "24 28 41 83 FE 0F 0F 87 BC FD FF FF 8B 56 78 41 8D 46 01 48 89 D9 39 D0 0F 4C "
    "C2 89 46 78 E8 85 9F 00 00 8B 54 24 2C 0F B6 4C 24 27 41 89 C0 49 63 C6 48 6B "
    "C0 0C 44 89 84 06 94 00 00 00 48 63 44 24 28 48 6B C0 0C 89 94 06 98 00 00 00 "
    "31 D2 8A 54 24 26 88 CE 66 89 94 06 9C 00 00 00 E9 65 FD FF FF 0F 1F 44 00 00";

// Optional loose masks (you can leave as-is or replace)
static const char* SIG_LoadCars_LOOSE = "48 89 5C 24 ?? 57 48 83 EC ?? 48 8B F9";
static const char* SIG_CupParse_LOOSE = "48 89 5C 24 ?? 57 48 83 EC ?? 48 8B DA 48 8B F9";
static const char* SIG_BuildGrid_LOOSE = "48 89 5C 24 ?? 48 89 6C 24 ?? 56 48 83 EC ??";

// Frontend/menu init (masked, x64): prologue + three calls + a couple of RIP loads + tail store.
// NOTE: all disp32 are masked with ??; immediate addresses masked too.
static const char* SIG_FrontendInit =
"48 89 45 00 48 29 f9 48 8b 86 e0 03 00 00 48 29 ce 81 c1 e8 03 00 00 48 89 85"
"e0 03 00 00 c1 e9 03 f3 48 a5 48 8d 0d 5c 2e 14 00";


// ========================= tiny file reader ========================
static bool ReadFileAll(const wchar_t* path, std::vector<uint8_t>& out) {
	out.clear();
	HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (h == INVALID_HANDLE_VALUE) return false;

	LARGE_INTEGER sz{};
	if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 0 || sz.QuadPart > 0x7fffffff) {
		CloseHandle(h);
		return false;
	}
	out.resize(static_cast<size_t>(sz.QuadPart));

	DWORD rd = 0, total = 0;
	while (total < out.size()) {
		if (!ReadFile(h, out.data() + total, static_cast<DWORD>(out.size() - total), &rd, nullptr)) {
			CloseHandle(h);
			out.clear();
			return false;
		}
		if (rd == 0) break;
		total += rd;
	}
	CloseHandle(h);
	return total == out.size();
}

// ============================ helpers ==============================
static inline uint8_t* ModuleBase() {
	return reinterpret_cast<uint8_t*>(GetModuleHandleA(nullptr));
}

struct Section { uint8_t* beg{}; uint32_t size{}, rva{}, chr{}; };

// PE section view (dual-arch)
struct PESections {
	Section text{};
	struct S { uint32_t va{}, vsz{}, chr{}; } sec[32]{}; // zero-init
	int n = 0;

	bool load_from_module_base(uint8_t* base) {
		auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
		if (!dos || dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

		auto nth = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
		if (!nth || nth->Signature != IMAGE_NT_SIGNATURE) return false;

		WORD magic = *reinterpret_cast<WORD*>(
			reinterpret_cast<uint8_t*>(&nth->OptionalHeader) + 0
			);
		if (magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
			magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;

		auto s = IMAGE_FIRST_SECTION(nth);
		n = (std::min<int>)(nth->FileHeader.NumberOfSections, 32);

		for (int i = 0; i < n; ++i) {
			uint32_t va = s[i].VirtualAddress;
			uint32_t sz = s[i].Misc.VirtualSize ? s[i].Misc.VirtualSize : s[i].SizeOfRawData;
			uint32_t ch = s[i].Characteristics;
			sec[i] = { va, sz, ch };
			if (std::memcmp(s[i].Name, ".text", 5) == 0) {
				text.beg = base + va;
				text.size = sz;
				text.rva = va;
				text.chr = ch;
			}
		}
		return text.beg && text.size;
	}

	bool rva_in_range(uint32_t rva, uint32_t& out_idx) const {
		for (int i = 0; i < n; ++i) {
			uint32_t va = sec[i].va, ve = va + sec[i].vsz;
			if (rva >= va && rva < ve) { out_idx = i; return true; }
		}
		return false;
	}
	bool rva_in_exec(uint32_t rva) const { uint32_t idx; return rva_in_range(rva, idx) && (sec[idx].chr & IMAGE_SCN_MEM_EXECUTE); }
	bool rva_in_data(uint32_t rva) const { uint32_t idx; return rva_in_range(rva, idx) && !(sec[idx].chr & IMAGE_SCN_MEM_EXECUTE); }
};

static inline uintptr_t RVAtoVA(uint32_t rva) { return reinterpret_cast<uintptr_t>(ModuleBase()) + rva; }
static inline bool IsExecRVA(const PESections& s, uint32_t rva) { return s.rva_in_exec(rva); }
static inline bool IsDataRVA(const PESections& s, uint32_t rva) { return s.rva_in_data(rva); }

// x64 RIP helpers used for classification/scoring only
static inline bool IsRex(uint8_t b) { return (b & 0xF0) == 0x40; }
static inline bool IsRexW(uint8_t b) { return IsRex(b) && (b & 0x08); }
static inline bool IsRipModRM(uint8_t m) { return (m & 0xC7) == 0x05; }

static inline bool IsMovRipStoreQword(uint8_t* p, size_t n) { return n >= 4 && IsRexW(p[0]) && p[1] == 0x89 && IsRipModRM(p[2]); }
static inline bool IsMovRipLoadQword(uint8_t* p, size_t n) { return n >= 4 && IsRexW(p[0]) && p[1] == 0x8B && IsRipModRM(p[2]); }
static inline bool IsLeaRipQword(uint8_t* p, size_t n) { return n >= 4 && IsRexW(p[0]) && p[1] == 0x8D && IsRipModRM(p[2]); }
static inline bool IsMovqRipStoreXmm(uint8_t* p, size_t n) { return n >= 5 && p[0] == 0x66 && p[1] == 0x0F && p[2] == 0xD6 && IsRipModRM(p[3]); }
static inline bool IsMovRipLoadDword(uint8_t* p, size_t n) { return n >= 2 && p[0] == 0x8B && IsRipModRM(p[1]); }
static inline bool IsMovsxdRipLoad(uint8_t* p, size_t n) { return n >= 4 && IsRexW(p[0]) && p[1] == 0x63 && IsRipModRM(p[2]); }
static inline bool IsCmpRipDwordImm8(uint8_t* p, size_t n) { return n >= 3 && p[0] == 0x83 && p[1] == 0x3D && IsRipModRM(p[1]); }

static constexpr size_t kMaxInstrLen = 15;

// -------------- x64 RIP target decoder (runtime, in-memory) ---------------
#if defined(_WIN64)
static inline bool RipTargetRVA_Generic(uint8_t* textBeg, uint32_t textRVA,
	uint8_t* q, uint32_t& out_rva, size_t& out_len) {
	uintptr_t base = reinterpret_cast<uintptr_t>(textBeg) - textRVA;
	if (IsMovRipLoadQword(q, 7) || IsMovRipStoreQword(q, 7) || IsLeaRipQword(q, 7)) {
		int32_t rel = *reinterpret_cast<int32_t*>(q + 3);
		uintptr_t ip = reinterpret_cast<uintptr_t>(q) + 7;
		out_rva = (uint32_t)((ip + rel) - base); out_len = 7; return true;
	}
	if (IsMovqRipStoreXmm(q, 8)) {
		int32_t rel = *reinterpret_cast<int32_t*>(q + 4);
		uintptr_t ip = reinterpret_cast<uintptr_t>(q) + 8;
		out_rva = (uint32_t)((ip + rel) - base); out_len = 8; return true;
	}
	if (IsMovRipLoadDword(q, 6)) {
		int32_t rel = *reinterpret_cast<int32_t*>(q + 2);
		uintptr_t ip = reinterpret_cast<uintptr_t>(q) + 6;
		out_rva = (uint32_t)((ip + rel) - base); out_len = 6; return true;
	}
	if (IsMovsxdRipLoad(q, 7)) {
		int32_t rel = *reinterpret_cast<int32_t*>(q + 3);
		uintptr_t ip = reinterpret_cast<uintptr_t>(q) + 7;
		out_rva = (uint32_t)((ip + rel) - base); out_len = 7; return true;
	}
	if (IsCmpRipDwordImm8(q, 7)) {
		int32_t rel = *reinterpret_cast<int32_t*>(q + 2);
		uintptr_t ip = reinterpret_cast<uintptr_t>(q) + 7;
		out_rva = (uint32_t)((ip + rel) - base); out_len = 7; return true;
	}
	return false;
}
#else
// -------------- x86 absolute [imm32] decoder (runtime, in-memory) ----------
static inline bool IsMovAbs_Gpr_FromImm32(const uint8_t* p, size_t n) {
	if (n < 5) return false;
	if (p[0] == 0xA1) return true;                 // MOV EAX, [imm32]
	if (p[0] == 0x8B && (p[1] & 0xC7) == 0x05) return true; // MOV r32, [imm32] (mod=00 r/m=101)
	return false;
}

static inline bool DecodeImm32TargetRVA_Mem(uint8_t* moduleBase,
	const uint8_t* q,
	uint32_t& outRva,
	size_t& outLen) {
	if (!IsMovAbs_Gpr_FromImm32(q, 5)) return false;
	uint32_t abs = *reinterpret_cast<const uint32_t*>(q + 1);
	uintptr_t base = reinterpret_cast<uintptr_t>(moduleBase);
	if (abs < base) return false;                     // rough sanity
	outRva = static_cast<uint32_t>(abs - base);       // VA -> RVA
	outLen = 5;
	return true;
}
#endif

// Unified runtime decoder wrapper
static inline bool TryDecodeTarget(uint8_t* textBeg, uint32_t textRVA,
	uint8_t* p, uint32_t& outRva, size_t& outLen) {
#if defined(_WIN64)
	return RipTargetRVA_Generic(textBeg, textRVA, p, outRva, outLen);
#else
	(void)textRVA;
	return DecodeImm32TargetRVA_Mem(ModuleBase(), p, outRva, outLen);
#endif
}

// ============= small RIP decoders for ON-DISK (file bytes) =================
static inline bool MovRipStoreQ(const uint8_t* p, size_t n) { return n >= 4 && IsRexW(p[0]) && p[1] == 0x89 && IsRipModRM(p[2]); }
static inline bool MovRipLoadQ(const uint8_t* p, size_t n) { return n >= 4 && IsRexW(p[0]) && p[1] == 0x8B && IsRipModRM(p[2]); }
static inline bool LeaRipQ(const uint8_t* p, size_t n) { return n >= 4 && IsRexW(p[0]) && p[1] == 0x8D && IsRipModRM(p[2]); }
static inline bool MovqStoreXmm(const uint8_t* p, size_t n) { return n >= 5 && p[0] == 0x66 && p[1] == 0x0F && p[2] == 0xD6 && IsRipModRM(p[3]); }

static bool DecodeRipTargetRVA_File(const uint8_t* textRaw, size_t textLen, uint32_t textRVA,
	const uint8_t* q, uint32_t& outRva, size_t& outLen) {
	auto inside = [&](const uint8_t* p, size_t need) {
		size_t ofs = (size_t)(p - textRaw);
		return ofs + need <= textLen;
		};
	if (inside(q, 7) && (MovRipLoadQ(q, 7) || MovRipStoreQ(q, 7) || LeaRipQ(q, 7))) {
		int32_t rel = *(const int32_t*)(q + 3);
		size_t ipOff = (size_t)(q - textRaw) + 7;
		outRva = textRVA + (uint32_t)(ipOff + rel);
		outLen = 7; return true;
	}
	if (inside(q, 8) && MovqStoreXmm(q, 8)) {
		int32_t rel = *(const int32_t*)(q + 4);
		size_t ipOff = (size_t)(q - textRaw) + 8;
		outRva = textRVA + (uint32_t)(ipOff + rel);
		outLen = 8; return true;
	}
	return false;
}

// ======================== signature scan helpers ===========================
static bool FindFuncRVA_InText(const uint8_t* textRaw, size_t textLen, uint32_t textRVA,
	const char* sigSpec, uint32_t& outRva) {
	if (!sigSpec || !*sigSpec) return false;
	size_t off = 0;
	const uint8_t* hit = ScanSignature(textRaw, textLen, sigSpec, off);
	if (!hit) return false;
	outRva = textRVA + (uint32_t)off;
	return true;
}

// ======================== pattern-specific helpers ========================
// store imm32 to [rip+disp32] and the imm matches
static bool RipStoreImm32_Target_At(const uint8_t* textRaw, size_t textLen, size_t pos,
	uint32_t textRVA, uint32_t imm32, uint32_t& outRva) {
	if (pos + 10 > textLen) return false;
	if (textRaw[pos] != 0xC7 || textRaw[pos + 1] != 0x05) return false;  // C7 05
	uint32_t imm = *(const uint32_t*)(textRaw + pos + 6);
	if (imm != imm32) return false;
	int32_t rel = *(const int32_t*)(textRaw + pos + 2);
	size_t ipOff = pos + 10;
	outRva = textRVA + (uint32_t)(ipOff + rel);
	return true;
}

static bool RipLoad_Target_At(const uint8_t* textRaw, size_t textLen, size_t pos,
	uint32_t textRVA, uint8_t a, uint8_t b, uint8_t c,
	uint32_t& outRva) {
	if (pos + 7 > textLen) return false;
	if (textRaw[pos] != a || textRaw[pos + 1] != b || textRaw[pos + 2] != c) return false;
	int32_t rel = *(const int32_t*)(textRaw + pos + 3);
	size_t ipOff = pos + 7;
	outRva = textRVA + (uint32_t)(ipOff + rel);
	return true;
}

// LEA RSI,[rip+disp32] + later MOVSXD RDX,[RSI] → find base of AISlot array
static bool Find_AISlot0_From_BuildGrid(const uint8_t* textRaw, size_t textLen, uint32_t textRVA,
	size_t funcOff, size_t funcSpan, uint32_t& outRva) {
	size_t end = std::min(textLen, funcOff + funcSpan);
	for (size_t i = funcOff; i + 7 <= end; ++i) {
		if (textRaw[i] == 0x48 && textRaw[i + 1] == 0x8D && textRaw[i + 2] == 0x35) {
			int32_t rel = *(const int32_t*)(textRaw + i + 3);
			size_t ip = i + 7;
			uint32_t candidate = textRVA + (uint32_t)(ip + rel);
			// look forward a bit for 48 63 16 (MOVSXD RDX, [RSI])
			size_t jEnd = std::min(textLen, i + 128);
			for (size_t j = i + 3; j + 3 <= jEnd; ++j) {
				if (textRaw[j] == 0x48 && textRaw[j + 1] == 0x63 && textRaw[j + 2] == 0x16) {
					outRva = candidate;
					return true;
				}
			}
		}
	}
	return false;
}

// helper (file-scope)
static bool FindRipStoreTarget_InFuncTail(const RvglSigCore::PeImage& pe,
	const uint8_t* textRaw, size_t textLen, uint32_t textRVA,
	uint32_t funcRva, size_t maxSpan, uint32_t& outDataRva)
{
	outDataRva = 0;
	const size_t off = (size_t)(funcRva - textRVA);
	const size_t end = std::min(textLen, off + maxSpan);

	for (size_t i = off; i + 8 <= end; ++i) {
		const uint8_t* q = textRaw + i;

		// MOV [RIP+disp32], r64  → 4? 89 0D disp32
		if ((q[0] & 0xF0) == 0x40 && q[1] == 0x89 && (q[2] & 0xC7) == 0x05) {
			uint32_t tgt; size_t il;
			if (DecodeRipTargetRVA_File(textRaw, textLen, textRVA, q, tgt, il) &&
				RVAIsInData_UsingPe(pe, tgt)) {
				outDataRva = tgt; return true;
			}
		}

		// MOV [RIP+disp32], imm32  → C7 05 disp32 imm32
		if (q[0] == 0xC7 && q[1] == 0x05) {
			int32_t rel = *(const int32_t*)(q + 2);
			size_t ip = i + 10; // C7 05 + disp32 + imm32
			uint32_t tgt = textRVA + (uint32_t)(ip + rel);
			if (RVAIsInData_UsingPe(pe, tgt)) { outDataRva = tgt; return true; }
		}
	}
	return false;
}

// =========================== PE RVA tests (file) ===========================
static bool RVAIsInExec_UsingPe(const PeImage& pe, uint32_t rva) {
	for (uint16_t i = 0; i < pe.num_sects; ++i) {
		const auto& s = pe.sects[i];
		uint32_t va = s.VirtualAddress;
		uint32_t ve = va + std::max<uint32_t>(s.Misc.VirtualSize, s.SizeOfRawData);
		if (rva >= va && rva < ve) return (s.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
	}
	return false;
}
static inline bool RVAIsInData_UsingPe(const PeImage& pe, uint32_t rva) { return !RVAIsInExec_UsingPe(pe, rva); }

#if defined(_WIN64)
// Scan the whole .text for: MOV r64,[RIP+disp32] then a nearby use of [reg+0x04].
// Returns the DATA RVA of the menu-state global (whose +4 holds the selected index).
static uint32_t FindMenuState_GlobalAny(const RvglSigCore::PeImage& pe,
	const uint8_t* textRaw, size_t textLen, uint32_t textRVA)
{
	for (size_t i = 0; i + 8 < textLen; ++i) {
		const uint8_t* q = textRaw + i;

		// MOV r64, [RIP+disp32]  -> 48 8B 0D ?? ?? ?? ??  (or 4C 8B 0D ...)
		if (!((q[0] == 0x48 || q[0] == 0x4C) && q[1] == 0x8B && (q[2] & 0xC7) == 0x05))
			continue;

		uint32_t tgtRva; size_t ilen = 0;
		if (!DecodeRipTargetRVA_File(textRaw, textLen, textRVA, q, tgtRva, ilen)) continue;
		if (!RVAIsInData_UsingPe(pe, tgtRva)) continue;

		// which register received the global? (ModRM.reg)
		const uint8_t reg = (q[2] >> 3) & 0x07;

		// look ahead a little for an access to [reg + 0x04] (selected index)
		const size_t lookEnd = std::min(textLen, i + ilen + 64);
		for (size_t j = i + ilen; j + 3 < lookEnd; ++j) {
			const uint8_t b0 = textRaw[j + 0], b1 = textRaw[j + 1], b2 = textRaw[j + 2];
			const bool d8 = ((b1 & 0xC0) == 0x40) && ((b1 & 0x07) == reg) && (b2 == 0x04);
			if ((b0 == 0x8B && d8) || (b0 == 0x39 && d8) || (b0 == 0x83 && d8) || (b0 == 0xF7 && d8)) {
				return tgtRva; // FOUND: menu-state global
			}
		}
		if (ilen) i += (ilen - 1);
	}
	return 0;
}
#endif

static inline bool ascii_eq_icase(const char* s, const char* t) {
	if (!s || !t) return false;
	for (; *s && *t; ++s, ++t) {
		char a = *s, b = *t;
		if (a >= 'A' && a <= 'Z') a = (char)(a - 'A' + 'a');
		if (b >= 'A' && b <= 'Z') b = (char)(b - 'A' + 'a');
		if (a != b) return false;
	}
	return *s == 0 && *t == 0;
}

// Look for: F3 48 A5 ; 48 8D 0D ?? ?? ?? ??     (REP MOVSQ ; LEA RCX,[RIP+..])
// Verify the RIP target bytes equal "frontend.txt" in DATA.
// Return the RVA **of the LEA** (the hook site you care about).
static bool FindFrontendTxtLEA(const RvglSigCore::PeImage& pe,
	const uint8_t* textRaw, size_t textLen, uint32_t textRVA,
	uint32_t& outLeaRva)
{
	outLeaRva = 0;
	const uint8_t pat[] = { 0xF3, 0x48, 0xA5, 0x48, 0x8D, 0x0D }; // rep movsq ; lea rcx,[rip+..]

	for (size_t i = 0; i + sizeof(pat) + 4 <= textLen; ++i) {
		if (memcmp(textRaw + i, pat, sizeof(pat)) != 0) continue;

		// Decode RIP of the LEA (the rel32 follows 48 8D 0D)
		uint32_t ripTargetRva = 0; size_t il = 0;
		if (!DecodeRipTargetRVA_File(textRaw, textLen, textRVA, textRaw + i + 3, ripTargetRva, il)) continue;
		if (!RVAIsInData_UsingPe(pe, ripTargetRva)) continue;

		// Check the pointed string equals "frontend.txt"
		const char* str = (const char*)pe.rva_to_ptr(ripTargetRva, 12);
		if (!str) continue;
		if (!ascii_eq_icase(str, "frontend.txt")) continue;

		// Return the RVA of the LEA (start of 48 8D 0D ...)
		outLeaRva = textRVA + (uint32_t)(i + 3);
		return true;
	}
	return false;
}

static bool FindFuncStart_Backscan(const uint8_t* text, size_t textLen, uint32_t textRVA,
	uint32_t insideRva, uint32_t& outStartRva)
{
	size_t off = size_t(insideRva - textRVA);
	const size_t limit = (off > 0x2000 ? off - 0x2000 : 0);
	for (size_t i = off; i-- > limit; ) {
		const uint8_t* p = text + i;

		// match pushes (41 57 41 56 41 55 41 54 55 57 56 53)
		if (i + 12 + 7 <= textLen &&
			p[0] == 0x41 && p[1] == 0x57 && p[2] == 0x41 && p[3] == 0x56 &&
			p[4] == 0x41 && p[5] == 0x55 && p[6] == 0x41 && p[7] == 0x54 &&
			p[8] == 0x55 && p[9] == 0x57 && p[10] == 0x56 && p[11] == 0x53 &&
			p[12] == 0x48 && p[13] == 0x81 && p[14] == 0xEC)
		{
			outStartRva = uint32_t(textRVA + i);
			return true;
		}
	}
	return false;
}

// Find custom cups list global (DAT_006FBBC8) from inside CupParse body
// --- helper: derive custom-cups list global from inside CupParse (x64 file scan) ---
static bool Derive_CustomCupsList_From_CupParse(
	const RvglSigCore::PeImage& pe,
	const uint8_t* textRaw, size_t textLen, uint32_t textRVA,
	uint32_t cupParseFuncRva,
	uint32_t& outListRva,
	uint32_t* outCountRvaOpt /*=nullptr*/)
{
	outListRva = 0;
	if (outCountRvaOpt) *outCountRvaOpt = 0;

	const size_t off = (size_t)(cupParseFuncRva - textRVA);
	const size_t span = std::min(textLen - off, (size_t)0x2000);

	// Pass A: look for zeroing write: C7 05 disp32 00 00 00 00
	for (size_t i = off; i + 10 <= off + span; ++i) {
		const uint8_t* q = textRaw + i;
		if (q[0] == 0xC7 && q[1] == 0x05) {
			const uint32_t imm = *(const uint32_t*)(q + 6);
			if (imm != 0) continue;
			const int32_t  rel = *(const int32_t*)(q + 2);
			const size_t   ip = i + 10;
			const uint32_t tgt = textRVA + (uint32_t)(ip + rel);
			if (!RVAIsInData_UsingPe(pe, tgt)) continue;

			outListRva = tgt;

			// Optional: nearby MOV r32,[rip+disp32] used as count
			if (outCountRvaOpt) {
				const size_t lo = (i > 0x40 ? i - 0x40 : off);
				const size_t hi = std::min(textLen, i + 0x40);
				for (size_t k = lo; k + 6 <= hi; ++k) {
					const uint8_t* p = textRaw + k;
					if (p[0] == 0x8B && (p[1] & 0xC7) == 0x05) {
						const int32_t rel2 = *(const int32_t*)(p + 2);
						const size_t  ip2 = k + 6;
						const uint32_t tgt2 = textRVA + (uint32_t)(ip2 + rel2);
						if (RVAIsInData_UsingPe(pe, tgt2)) { *outCountRvaOpt = tgt2; break; }
					}
				}
			}
			return true;
		}
	}

	// Pass B: pair a MOV r64,[RIP+..] with a MOV [RIP+..],r64 to the same target
	uint32_t candidate = 0;
	for (size_t i = off; i + 7 <= off + span; ++i) {
		const uint8_t* q = textRaw + i;
		if (!((q[0] == 0x48 || q[0] == 0x4C) && q[1] == 0x8B && (q[2] & 0xC7) == 0x05))
			continue;

		uint32_t tgt; size_t il = 0;
		if (!DecodeRipTargetRVA_File(textRaw, textLen, textRVA, q, tgt, il)) continue;
		if (!RVAIsInData_UsingPe(pe, tgt)) continue;

		const size_t lookEnd = std::min(textLen, i + il + 0x80);
		for (size_t j = i + il; j + 7 <= lookEnd; ++j) {
			const uint8_t* z = textRaw + j;
			if (((z[0] & 0xF0) == 0x40) && z[1] == 0x89 && (z[2] & 0xC7) == 0x05) {
				uint32_t tgt2; size_t il2 = 0;
				if (DecodeRipTargetRVA_File(textRaw, textLen, textRVA, z, tgt2, il2) &&
					tgt2 == tgt && RVAIsInData_UsingPe(pe, tgt2)) {
					candidate = tgt2;
					break;
				}
			}
		}
		if (candidate) break;
	}

	if (candidate) { outListRva = candidate; return true; }
	return false;
}

// ============================== Disk scan ================================
static bool DiskScan_UsingCore(const std::wstring& exePath, HookAddrs& out)
{
	std::vector<uint8_t> bytes;
	if (!ReadFileAll(exePath.c_str(), bytes) || bytes.size() < 4096) return false;

	PeImage pe{};
	if (!pe.init(bytes.data(), bytes.size())) return false;

	const uint8_t* textRaw = nullptr; size_t textLen = 0; uint32_t textRVA = 0;
	if (!pe.get_section_data(".text", textRaw, textLen, textRVA)) return false;

	auto try_sig = [&](const char* exact, const char* loose, uint32_t& dst) {
		uint32_t rva = 0;
		if (exact && *exact && FindFuncRVA_InText(textRaw, textLen, textRVA, exact, rva)) { dst = rva; return true; }
		if (loose && *loose && FindFuncRVA_InText(textRaw, textLen, textRVA, loose, rva)) { dst = rva; return true; }
		return false;
		};

	// Primary functions
	(void)try_sig(SIG_LoadCars_EXACT, SIG_LoadCars_LOOSE, out.rva_LoadCars);
	(void)try_sig(SIG_CupParse_EXACT, SIG_CupParse_LOOSE, out.rva_CupParse);
	(void)try_sig(SIG_BuildGrid_EXACT, SIG_BuildGrid_LOOSE, out.rva_BuildGrid);
	(void)try_sig(SIG_RaceResults_EXACT, nullptr, out.rva_RaceResults);
	(void)try_sig(SIG_CupFinalize_EXACT, nullptr, out.rva_CupFinalize);

#if defined(_WIN64)
	// NEW: Prefer deriving CustomCupsList directly from CupParse function body
	if (out.rva_CupParse && !out.rva_CustomCupsList) {
		uint32_t listRva = 0, countRva = 0;
		if (Derive_CustomCupsList_From_CupParse(pe, textRaw, textLen, textRVA,
			out.rva_CupParse, listRva, &countRva))
		{
			out.rva_CustomCupsList = listRva;
			// Optional: if you keep a separate count RVA, store it too:
			// if (!out.rva_CustomCupsCount) out.rva_CustomCupsCount = countRva;
		}
	}
#endif

	// -------- Frontend/menu init: prefer the "frontend.txt" LEA anchor --------
	{
		uint32_t leaRva = 0;
		if (FindFrontendTxtLEA(pe, textRaw, textLen, textRVA, leaRva)) {
			uint32_t startRva = 0;
			if (FindFuncStart_Backscan(textRaw, textLen, textRVA, leaRva, startRva)) {
				out.rva_FrontendInit = startRva;        // <-- hook THIS (function entry)
			}
			else {
				out.rva_FrontendInit = 0;               // don’t hook mid-function
			}
		}
		else {
			(void)try_sig(/*exact*/nullptr, SIG_FrontendInit, out.rva_FrontendInit);
		}
	}

	// Derivations from LoadCars (CarCount & CarTablePtr)
	if (out.rva_LoadCars) {
		size_t off = (size_t)(out.rva_LoadCars - textRVA);
		size_t span = std::min(textLen - off, (size_t)0x700);

		// CarCount via C7 05 .. .. .. .. 31 00 00 00
		for (size_t i = off; i + 10 <= off + span; ++i) {
			uint32_t tgt = 0;
			if (RipStoreImm32_Target_At(textRaw, textLen, i, textRVA, 0x31u, tgt) &&
				RVAIsInData_UsingPe(pe, tgt))
			{
				out.rva_CarCount = tgt;
				break;
			}
		}

		// CarTablePtr via CarCount-8 or first MOV [rip+]
		if (out.rva_CarCount && RVAIsInData_UsingPe(pe, out.rva_CarCount - 8)) {
			out.rva_CarTablePtr = out.rva_CarCount - 8;
		}
		else {
			size_t span2 = std::min(textLen - off, (size_t)0x400);
			for (size_t i = off; i + 7 <= off + span2; ++i) {
				uint32_t tgt = 0;
				if (RipLoad_Target_At(textRaw, textLen, i, textRVA, 0x48, 0x8B, 0x0D, tgt) &&
					RVAIsInData_UsingPe(pe, tgt))
				{
					out.rva_CarTablePtr = tgt;
					break;
				}
			}
		}
	}

	// From BuildGrid
	if (out.rva_BuildGrid) {
		size_t off = (size_t)(out.rva_BuildGrid - textRVA);
		size_t span = std::min(textLen - off, (size_t)0x800);

		// ActiveCupPtr via MOV RDX,[rip+..] near top
		if (!out.rva_ActiveCupPtr) {
			for (size_t i = off; i + 7 <= off + 0x100; ++i) {
				uint32_t tgt = 0;
				if (RipLoad_Target_At(textRaw, textLen, i, textRVA, 0x48, 0x8B, 0x15, tgt) &&
					RVAIsInData_UsingPe(pe, tgt))
				{
					out.rva_ActiveCupPtr = tgt;
					break;
				}
			}
		}

		// PlayersCount via 44 8B 0D disp32
		if (!out.rva_PlayersCount) {
			for (size_t i = off; i + 7 <= off + span; ++i) {
				uint32_t tgt = 0;
				if (RipLoad_Target_At(textRaw, textLen, i, textRVA, 0x44, 0x8B, 0x0D, tgt) &&
					RVAIsInData_UsingPe(pe, tgt))
				{
					out.rva_PlayersCount = tgt;
					break;
				}
			}
		}

		// AISlot0 base via LEA RSI,[rip+..] + MOVSXD RDX,[RSI]
		if (!out.rva_AISlot0) {
			uint32_t baseRva = 0;
			if (Find_AISlot0_From_BuildGrid(textRaw, textLen, textRVA, off, span, baseRva) &&
				RVAIsInData_UsingPe(pe, baseRva))
			{
				out.rva_AISlot0 = baseRva;

				// Synth OppSlotIndex[16]
				const uint32_t stride = 0x25u * 4u; // 0x94 bytes per slot
				for (int i = 0; i < 16; ++i) {
					const uint32_t rva_i = baseRva + (uint32_t)(i * stride);
					if (RVAIsInData_UsingPe(pe, rva_i)) out.rva_OppSlotIndex[i] = rva_i;
				}
			}
		}
	}

#if defined(_WIN64)
	// --- Menu state (selected index lives at [*MenuState + 4]) ---
	if (!out.rva_MenuState) {
		uint32_t m = FindMenuState_GlobalAny(pe, textRaw, textLen, textRVA);
		if (m && RVAIsInData_UsingPe(pe, m)) out.rva_MenuState = m;
	}

	// --- From CupFinalize: builtin base via LEA [RIP+..], custom list via MOV [RIP+..] ---
	if (out.rva_CupFinalize) {
		size_t off = (size_t)(out.rva_CupFinalize - textRVA);
		size_t span = std::min(textLen - off, (size_t)0x2000);

		// 1) Builtin cups base
		if (!out.rva_BuiltinCupsBase) {
			for (size_t i = off; i + 7 <= off + span; ++i) {
				const uint8_t* q = textRaw + i;
				if (q[0] == 0x48 && q[1] == 0x8D && q[2] == 0x15) {
					uint32_t tgt; size_t il = 0;
					if (DecodeRipTargetRVA_File(textRaw, textLen, textRVA, q, tgt, il) &&
						RVAIsInData_UsingPe(pe, tgt)) {
						out.rva_BuiltinCupsBase = tgt;
						break;
					}
				}
			}
		}

		// 2) Custom cups list pointer (fallback if CupParse pass didn't set it)
		if (!out.rva_CustomCupsList) {
			for (size_t i = off; i + 7 <= off + span; ++i) {
				const uint8_t* q = textRaw + i;
				if ((q[0] == 0x48 || q[0] == 0x4C) && q[1] == 0x8B && q[2] == 0x15) {
					uint32_t tgt; size_t il = 0;
					if (DecodeRipTargetRVA_File(textRaw, textLen, textRVA, q, tgt, il) &&
						RVAIsInData_UsingPe(pe, tgt)) {
						out.rva_CustomCupsList = tgt;
						break;
					}
				}
			}
		}
	}
#else
	// x86 note: file-time scan can’t resolve abs [imm32] to RVA safely.
	// Let your existing runtime fixups handle these (like other x86 paths).
#endif

	return (out.rva_LoadCars | out.rva_CupParse | out.rva_BuildGrid |
		out.rva_ActiveCupPtr | out.rva_RaceResults | out.rva_CupFinalize) != 0;
}

// ======================== AISlot stride validator ==========================
static constexpr size_t AI_SLOT_INTS = 0x25;
static constexpr size_t AI_SLOT_STRIDE = AI_SLOT_INTS * 4;

static bool GoodSlotBaseStride(const PESections& secs, uint32_t rva) {
	uint32_t idx0;
	if (!secs.rva_in_range(rva, idx0)) return false;
	for (int k = 1; k < 16; ++k) {
		uint32_t rva_k = rva + (uint32_t)(k * AI_SLOT_STRIDE);
		uint32_t idxK;
		if (!secs.rva_in_range(rva_k, idxK) || idxK != idx0) return false;
	}
	return true;
}

// ======================== Runtime fixups (in-memory) =======================

bool SH_FixActiveCupPtr(HookAddrs& out) {
	PESections secs; if (!secs.load_from_module_base(ModuleBase())) return false;
	auto& T = secs.text; if (!T.beg || !T.size) return false;

	uint8_t* scanStart = T.beg;
	size_t   scanLen = T.size;

	uint32_t best = 0; int bestScore = -1;

	for (size_t i = 0; i + 8 <= scanLen; ++i) {
		uint8_t* q = scanStart + i;
		uint32_t tgt; size_t ilen;
		if (!TryDecodeTarget(T.beg, T.rva, q, tgt, ilen)) continue;
		if (!IsDataRVA(secs, tgt)) continue;

		const bool isStore = IsMovRipStoreQword(q, ilen) || IsMovqRipStoreXmm(q, ilen);
		if (!isStore) continue;

		int score = 1;
		for (int d = 1; d <= 0x40 && i + (size_t)d + 8 <= scanLen; ++d) {
			uint8_t* z = q + d;
			uint32_t t2; size_t l2;
			if (!TryDecodeTarget(T.beg, T.rva, z, t2, l2)) continue;
			if (t2 == tgt && (IsMovRipLoadQword(z, l2) || IsLeaRipQword(z, l2))) ++score;
		}
		if (score > bestScore) { bestScore = score; best = tgt; }
		if (ilen) i += (ilen - 1);
	}

	if (best) out.rva_ActiveCupPtr = best;
	return best != 0;
}

bool SH_FixAISlot0(HookAddrs& out) {
	if (!out.rva_BuildGrid) return false;

	PESections secs; if (!secs.load_from_module_base(ModuleBase())) return false;
	auto& T = secs.text; if (!T.beg || !T.size) return false;

	uint8_t* pGrid = reinterpret_cast<uint8_t*>(RVAtoVA(out.rva_BuildGrid));
	if (pGrid < T.beg || pGrid >= T.beg + T.size) return false;

	const size_t maxScan = 0x800;
	size_t remain = static_cast<size_t>(T.beg + T.size - pGrid);
	size_t n = (remain < maxScan) ? remain : maxScan;

	struct Cand {
		uint32_t rva{ 0 };
		int hits{ 0 };
		int nearby{ 0 };
	};

	std::unordered_map<uint32_t, Cand> map;

	for (size_t i = 0; i + 5 <= n; ++i) {
		uint8_t* q = pGrid + i;
		uint32_t tgt; size_t ilen;
		if (!TryDecodeTarget(T.beg, T.rva, q, tgt, ilen)) continue;
		if (!IsDataRVA(secs, tgt)) continue;

		const bool qwordy =
			IsLeaRipQword(q, ilen) || IsMovRipLoadQword(q, ilen) ||
			IsMovRipStoreQword(q, ilen) || IsMovqRipStoreXmm(q, ilen);
		if (!qwordy) continue;

		Cand& c = map[tgt];
		c.rva = tgt;
		c.hits += 1;

		for (int d = -0x40; d <= 0x40; ++d) {
			uint8_t* z = q + d;
			if (z < T.beg) continue;
			if (z + kMaxInstrLen > T.beg + T.size) continue;

			uint32_t t2; size_t l2;
			if (TryDecodeTarget(T.beg, T.rva, z, t2, l2) && t2 == tgt) {
				c.nearby += 1;
			}
		}

		if (ilen) i += (ilen - 1);
	}

	uint32_t best = 0;
	int bestScore = -1;

	for (auto& kv : map) {
		if (!GoodSlotBaseStride(secs, kv.second.rva)) continue;
		int score = kv.second.nearby * 4 + kv.second.hits;
		if (score > bestScore) { bestScore = score; best = kv.second.rva; }
	}

	if (best) {
		out.rva_AISlot0 = best;
		const uint32_t stride = (uint32_t)(AI_SLOT_INTS * 4); // 0x94
		for (int i = 0; i < 16; ++i) out.rva_OppSlotIndex[i] = best + (uint32_t)(i * stride);
	}
	return best != 0;
}

static inline bool IsMovEDX_From_RBX_plus8(uint8_t* p, size_t n) {
	if (n < 3) return false;
	if (p[0] != 0x8B) return false;              // MOV r32, r/m32
	uint8_t modrm = p[1];
	if ((modrm & 0xC0) != 0x40) return false;    // mod=01 (disp8)
	if ((modrm & 0x38) != 0x10) return false;    // reg=010 (EDX)
	if ((modrm & 0x07) != 0x03) return false;    // r/m=011 (RBX)
	if (p[2] != 0x08) return false;              // +8
	return true;
}
static inline bool IsMovR64_From_RBX(uint8_t* p, size_t n) {
	if (n < 3) return false;
	if (!IsRexW(p[0]) || p[1] != 0x8B) return false; // MOV r64, r/m64
	uint8_t modrm = p[2];
	if ((modrm & 0xC0) != 0x00) return false;   // mod=00
	if ((modrm & 0x07) != 0x03) return false;   // r/m=RBX
	return true;
}
static inline bool IsLeaMovRBX_FromRip(uint8_t* p, size_t n) {
	if (n < 4) return false;
	if (!IsRexW(p[0])) return false;
	if (p[1] != 0x8D && p[1] != 0x8B) return false; // LEA/MOV r64,[mem]
	return IsRipModRM(p[2]) && ((p[2] & 0x38) == 0x18); // reg=011 (RBX)
}

bool SH_FixPlayersBaseAndCount(HookAddrs& out) {
	PESections secs; if (!secs.load_from_module_base(ModuleBase())) return false;
	auto& T = secs.text; if (!T.beg || !T.size) return false;

	bool setBase = false, setCount = false;

	// Prefer walking RaceResults
	if (out.rva_RaceResults) {
		uint8_t* pRes = reinterpret_cast<uint8_t*>(RVAtoVA(out.rva_RaceResults));
		if (pRes >= T.beg && pRes < T.beg + T.size) {
			const size_t scanMax = 0x900;
			size_t remain = (size_t)(T.beg + T.size - pRes);
			size_t n = (remain < scanMax) ? remain : scanMax;

			size_t block_off = (size_t)-1;
			for (size_t i = 0; i + 6 < n; ++i) {
				if (!IsMovEDX_From_RBX_plus8(pRes + i, 3)) continue;
				bool ok_mov_rbx = false;
				for (size_t k = 1; k <= 0x30 && i + k + 3 < n; ++k) {
					if (IsMovR64_From_RBX(pRes + i + k, 3)) { ok_mov_rbx = true; break; }
				}
				if (ok_mov_rbx) { block_off = i; break; }
			}

			if (block_off != (size_t)-1) {
				uint8_t* start = (pRes + (block_off > 0x80 ? block_off - 0x80 : 0));
				uint8_t* stop = pRes + block_off;

				for (uint8_t* q = stop; q > start; ) {
					--q;
					if (IsLeaMovRBX_FromRip(q, 7)) {
						int32_t rel = *reinterpret_cast<int32_t*>(q + 3);
						uintptr_t ip = reinterpret_cast<uintptr_t>(q) + 7;
						uintptr_t base = reinterpret_cast<uintptr_t>(T.beg) - T.rva;
						uint32_t rva = (uint32_t)((ip + rel) - base);
						if (IsDataRVA(secs, rva)) {
							out.rva_PlayersBase = rva;
							out.rva_PlayersCount = rva + 0x8;
							setBase = setCount = true;
							break;
						}
					}
				}
			}
		}
	}

	// Fallback: guess PlayersCount from BuildGrid
	if (!setCount && out.rva_BuildGrid) {
		uint8_t* pGrid = reinterpret_cast<uint8_t*>(RVAtoVA(out.rva_BuildGrid));
		if (pGrid >= T.beg && pGrid < T.beg + T.size) {
			const size_t maxScan = 0x1400;
			size_t remain = (size_t)(T.beg + T.size - pGrid);
			size_t n = (remain < maxScan) ? remain : maxScan;

			uint32_t best = 0;
			for (size_t i = 0; i + 7 <= n; ++i) {
				uint8_t* q = pGrid + i;
				uint32_t tgt; size_t ilen;
				if (!TryDecodeTarget(T.beg, T.rva, q, tgt, ilen)) continue;
				if (!IsDataRVA(secs, tgt)) continue;

				if (!(IsMovRipLoadDword(q, ilen) || IsMovsxdRipLoad(q, ilen) || IsCmpRipDwordImm8(q, ilen)))
					continue;

				if (!best) best = tgt;
			}
			if (best) { out.rva_PlayersCount = best; setCount = true; }
		}
	}

	return setBase || setCount;
}

// ============================ path helpers ================================
static std::wstring Join2(const std::wstring& a, const std::wstring& b) {
	if (a.empty()) return b;
	if (a.back() == L'\\' || a.back() == L'/') return a + b;
	return a + L"\\" + b;
}
static bool FileExistsW(const std::wstring& p) {
	return GetFileAttributesW(p.c_str()) != INVALID_FILE_ATTRIBUTES;
}
static std::wstring ResolveRvglExeFromRoot_Any(const wchar_t* rvglExeOrRoot) {
	if (!rvglExeOrRoot || !*rvglExeOrRoot) return L"";
	std::wstring p(rvglExeOrRoot);

	// direct exe?
	if (p.size() > 4) {
		auto tail = p.substr(p.size() - 4);
		for (auto& ch : tail) ch = (wchar_t)towlower(ch);
		if (tail == L".exe" && FileExistsW(p)) return p;
	}

	const std::wstring cands[] = {
		Join2(p, L"rvgl.exe"),
		Join2(p, L"packs\\rvgl_win64\\rvgl.exe"),
		Join2(p, L"packs\\rvgl_win32\\rvgl.exe"),
		Join2(p, L"packs\\game_files\\rvgl.exe")
	};
	for (auto& c : cands) if (FileExistsW(c)) return c;
	return L"";
}

static std::wstring CupgenJsonFromRoot(const std::wstring& root) {
	return Join2(Join2(Join2(Join2(root, L"packs"), L"rvgl_assets"), L"cups\\cupgen"), L"rvgl_addrs.json");
}

static std::wstring CupgenJsonFromExe(const std::wstring& exePath) {
	std::wstring dir = exePath;
	size_t slash = dir.find_last_of(L"\\/");
	if (slash != std::wstring::npos) dir.resize(slash);

	auto ends_with_icase = [](const std::wstring& s, const std::wstring& suf) {
		if (s.size() < suf.size()) return false;
		for (size_t i = 0; i < suf.size(); ++i) {
			wchar_t a = (wchar_t)towlower(s[s.size() - suf.size() + i]);
			wchar_t b = (wchar_t)towlower(suf[i]);
			if (a != b) return false;
		}
		return true;
		};

	std::wstring root = dir;
	if (ends_with_icase(dir, L"\\packs\\rvgl_win64") ||
		ends_with_icase(dir, L"/packs/rvgl_win64") ||
		ends_with_icase(dir, L"\\packs\\rvgl_win32") ||
		ends_with_icase(dir, L"/packs/rvgl_win32") ||
		ends_with_icase(dir, L"\\packs\\game_files") ||
		ends_with_icase(dir, L"/packs/game_files"))
	{
		size_t s1 = root.find_last_of(L"\\/");
		if (s1 != std::wstring::npos) root.resize(s1);
		size_t s2 = root.find_last_of(L"\\/");
		if (s2 != std::wstring::npos) root.resize(s2);
	}

	return CupgenJsonFromRoot(root);
}

// ===================== Load addresses from CupGen JSON =====================
static bool LoadHookRVAsFromJson_Tiny(const std::wstring& jsonPath, HookAddrs& out) {
	std::vector<uint8_t> bytes;
	if (!ReadFileAllW(jsonPath.c_str(), bytes)) return false;
	std::string s(reinterpret_cast<const char*>(bytes.data()), bytes.size());

	// Use the ACTUAL module base so we’re ASLR-safe.
	const uint32_t imageBase = static_cast<uint32_t>(reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr)));

	auto grab_hex_as_va = [&](const char* key, uint32_t& dst)->void {
		std::string pat = std::string("\"") + key + "\":";
		size_t p = s.find(pat);
		if (p == std::string::npos) return;
		p = s.find('"', p);
		if (p == std::string::npos) return;
		size_t q = s.find('"', p + 1);
		if (q == std::string::npos) return;
		std::string v = s.substr(p + 1, q - (p + 1));

		// Parse hex/decimal into a raw number (RVA)
		uint32_t raw = 0;
		if (v.size() > 2 && (v[0] == '0') && (v[1] == 'x' || v[1] == 'X')) {
			raw = static_cast<uint32_t>(strtoul(v.c_str() + 2, nullptr, 16));
		}
		else {
			char* endp = nullptr;
			unsigned long x = strtoul(v.c_str(), &endp, 16);   // try hex first
			if (endp && *endp == 0) raw = static_cast<uint32_t>(x);
			else                     raw = static_cast<uint32_t>(strtoul(v.c_str(), nullptr, 10));
		}

		// Convert RVA -> VA using the CURRENT module base (ASLR-safe).
		dst = raw ? (imageBase + raw) : 0u;
		};

	grab_hex_as_va("rva_LoadCars", out.rva_LoadCars);
	grab_hex_as_va("rva_CupParse", out.rva_CupParse);
	grab_hex_as_va("rva_BuildGrid", out.rva_BuildGrid);
	grab_hex_as_va("rva_CarTablePtr", out.rva_CarTablePtr);
	grab_hex_as_va("rva_CarCount", out.rva_CarCount);
	grab_hex_as_va("rva_AISlot0", out.rva_AISlot0);
	grab_hex_as_va("rva_ActiveCupPtr", out.rva_ActiveCupPtr);
	grab_hex_as_va("rva_PlayersBase", out.rva_PlayersBase);
	grab_hex_as_va("rva_PlayersCount", out.rva_PlayersCount);
	grab_hex_as_va("rva_RaceResults", out.rva_RaceResults);
	grab_hex_as_va("rva_CupFinalize", out.rva_CupFinalize);
	grab_hex_as_va("rva_MenuState", out.rva_MenuState);
	grab_hex_as_va("rva_BuiltinCupsBase", out.rva_BuiltinCupsBase);
	grab_hex_as_va("rva_CustomCupsList", out.rva_CustomCupsList);
	grab_hex_as_va("rva_FrontendInit", out.rva_FrontendInit);

	// Opp array: convert each RVA -> VA as well
	size_t pos = s.find("\"rva_OppSlotIndex\"");
	if (pos != std::string::npos) {
		for (int i = 0; i < 16; ++i) {
			pos = s.find("0x", pos);
			if (pos == std::string::npos) break;
			char* endp = nullptr;
			unsigned long val = strtoul(s.c_str() + pos + 2, &endp, 16);
			out.rva_OppSlotIndex[i] = val ? (imageBase + static_cast<uint32_t>(val)) : 0u;
			if (!endp) break;
			pos = static_cast<size_t>(endp - s.c_str());
		}
	}

	return true;
}

// =========================== PUBLIC ENTRY =================================
bool ResolveHookRVAsFromFile(const wchar_t* rvglExeOrRoot,
	HookAddrs& out,
	std::wstring* debugOutOpt)
{
	(void)debugOutOpt;
	std::memset(&out, 0, sizeof(out));

	// 1) Resolve path
	std::wstring exe = ResolveRvglExeFromRoot_Any(rvglExeOrRoot);
	if (exe.empty()) return false;

	// 2) Try CupGen JSON first
	std::wstring jsonPath = CupgenJsonFromExe(exe);
	if (FileExistsW(jsonPath)) {
		if (LoadHookRVAsFromJson_Tiny(jsonPath, out)) {
			// OK even if zeros; caller can inspect
			return true;
		}
	}

	// 3) Real on-disk scan
	if (DiskScan_UsingCore(exe, out)) {
		return true;
	}

	// 4) Fallback: still succeed (zeros) so schema writes out if you serialize later
	return true;
}