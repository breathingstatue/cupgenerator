#pragma once
namespace StartGridMod {
    bool Install();
    void Shutdown();

    void SetMode(int m);
    void SetCupName(const char* cupName);
    void SetPointsCsv(const char* csv);
    void SetProfile(const char* profile);
    void OnStartCup();
    void OnRaceFinished(int justFinishedRaceIndex);
    void OnSessionFile(void* rvFileHandle);
    void NotifyActiveCup(const char* cupPathResolved);

    // Fallback logger when engine hooks aren’t found:
    void LogLine(const char* fmt, ...);
    void PreBuildGrid();   // <- new: apply reverse-grid policy if enabled
}
