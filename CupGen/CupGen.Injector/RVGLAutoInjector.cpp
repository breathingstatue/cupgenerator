// RVGLAutoInjector.cpp  (build as /SUBSYSTEM:WINDOWS)
#include <windows.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <string>
#include <set>
#include <fstream>

#pragma comment(lib, "shlwapi.lib")

#define _CRT_SECURE_NO_WARNINGS

static std::string GetDllPathFromArgsOrExeDir() {
    // 1) first CLI arg (if provided)
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv && argc >= 2) {
        char dllA[MAX_PATH]{};
        WideCharToMultiByte(CP_ACP, 0, argv[1], -1, dllA, MAX_PATH, nullptr, nullptr);
        LocalFree(argv);
        if (GetFileAttributesA(dllA) != INVALID_FILE_ATTRIBUTES) return dllA;
    }
    else if (argv) {
        LocalFree(argv);
    }
    // 2) RVGLCupOpponents.dll next to this EXE
    char exePath[MAX_PATH]{};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    PathRemoveFileSpecA(exePath);
    char dllPath[MAX_PATH]{};
    wsprintfA(dllPath, "%s\\RVGLCupOpponents.dll", exePath);
    if (GetFileAttributesA(dllPath) != INVALID_FILE_ATTRIBUTES) return dllPath;
    // 3) fallback: empty -> will never inject
    return {};
}

static DWORD FindProcessIdExact(const wchar_t* name) {
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

static void FindAllRvglPids(std::set<DWORD>& out) {
    out.clear();
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"rvgl.exe") == 0) out.insert(pe.th32ProcessID);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
}

static bool InjectDLL(DWORD pid, const std::string& dllPath) {
    HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProc)
        return false;

    SIZE_T len = dllPath.size() + 1;
    LPVOID remote = VirtualAllocEx(hProc, nullptr, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote) { CloseHandle(hProc); return false; }

    if (!WriteProcessMemory(hProc, remote, dllPath.c_str(), len, nullptr)) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    if (!k32) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    auto loadA = reinterpret_cast<LPTHREAD_START_ROUTINE>(
        GetProcAddress(k32, "LoadLibraryA"));
    if (!loadA) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    HANDLE hTh = CreateRemoteThread(hProc, nullptr, 0, loadA, remote, 0, nullptr);
    if (!hTh) {
        VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return false;
    }

    WaitForSingleObject(hTh, INFINITE);
    DWORD remoteHMODULE = 0;
    GetExitCodeThread(hTh, &remoteHMODULE);
    CloseHandle(hTh);
    VirtualFreeEx(hProc, remote, 0, MEM_RELEASE);
    CloseHandle(hProc);
    return remoteHMODULE != 0;
}

#include <sal.h>   // usually pulled in by <windows.h>, but harmless to include

int WINAPI WinMain(
    _In_     HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_     LPSTR     lpCmdLine,
    _In_     int       nShowCmd)
{
    HANDLE mtx = CreateMutexA(nullptr, FALSE, "RVGL_AutoInjector_Singleton");
    if (!mtx || GetLastError() == ERROR_ALREADY_EXISTS) return 0;

    const std::string dllPath = GetDllPathFromArgsOrExeDir();
    if (dllPath.empty())
        return 0;

    std::set<DWORD> injected;
    for (;;) {
        std::set<DWORD> pids;
        FindAllRvglPids(pids);
        for (DWORD pid : pids) {
            if (injected.count(pid)) continue;
            if (InjectDLL(pid, dllPath)) {
                injected.insert(pid);
            }
        }
        // prune dead PIDs
        for (auto it = injected.begin(); it != injected.end(); ) {
            if (FindProcessIdExact(L"rvgl.exe") != *it) it = injected.erase(it);
            else ++it;
        }
        Sleep(1000);
    }
}
