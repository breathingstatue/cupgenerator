#pragma once
#include <string>

#if defined(_WIN32)
#if defined(CUPGEN_BUILDING_DLL)
#define CUPGEN_API __declspec(dllexport)
#else
#define CUPGEN_API __declspec(dllimport)
#endif
#else
#define CUPGEN_API
#endif

// Existing globals
extern int gParsedStartGridMode;
extern std::string gParsedPointsCsv;

namespace CupGen {
    // Set by the injector/EXE once per run (absolute path, no trailing slash).
    CUPGEN_API void SetRvglRoot(const char* rootAbs);

    // Optional convenience export (same as SetRvglRoot).
    extern "C" CUPGEN_API void CupGen_SetRvglRoot(const char* rootAbs);

    // Readback + derived folders (always absolute, normalized, no trailing slash)
    CUPGEN_API const std::string& RvglRoot();
    CUPGEN_API const std::string& ProfilesBase();
    CUPGEN_API const std::string& CupsDir();
    CUPGEN_API const std::string& CupGenDir();
    CUPGEN_API const std::string& CupGenLogsDir();
}