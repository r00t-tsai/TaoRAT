#ifdef UNICODE
#undef UNICODE
#endif
#ifdef _UNICODE
#undef _UNICODE
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winioctl.h>
#include <ntddstor.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <algorithm>
#include <shlobj.h>
#include <winternl.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <setupapi.h>
#include <devguid.h>
#include <fstream>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "ntdll.lib")

#define VM_EXIT_THRESHOLD 4
#define VM_SUSPICIOUS_THRESHOLD 3

HMODULE g_hModule = NULL;
std::string g_moduleDirectory;
std::string g_loaderProcessName;

std::string GetAppDataPath() {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path))) {
        return std::string(path);
    }
    return "";
}

bool DirectoryExists(const std::string& path) {
    DWORD attrib = GetFileAttributesA(path.c_str());
    return (attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_DIRECTORY));
}

bool CreateCleanDirectory() {
    std::string cleanCPath = GetAppDataPath() + "\\clean.c";
    if (DirectoryExists(cleanCPath)) return true;

    if (CreateDirectoryA(cleanCPath.c_str(), NULL)) {
        SetFileAttributesA(cleanCPath.c_str(), FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM);
        return true;
    }
    return false;
}

std::string ToLower(const std::string& str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}

std::string GetModuleDirectory(HMODULE hModule) {
    char path[MAX_PATH];
    GetModuleFileNameA(hModule, path, MAX_PATH);
    std::string pathStr(path);
    size_t lastSlash = pathStr.find_last_of("\\");
    if (lastSlash != std::string::npos) {
        return pathStr.substr(0, lastSlash);
    }
    return "";
}

std::string GetLoaderProcessName() {
    DWORD processId = GetCurrentProcessId();
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return "tao.exe";
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == processId) {
                CloseHandle(hSnapshot);
#ifdef UNICODE
                char exeName[MAX_PATH];
                WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, exeName, MAX_PATH, NULL, NULL);
                return std::string(exeName);
#else
                return std::string(pe32.szExeFile);
#endif
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    return "tao.exe";
}

bool CreateSelfDestructBatch(const std::string& loaderProcessName) {
    std::string currentPath = g_moduleDirectory;
    std::string rootPath = currentPath;

    for (int i = 0; i < 3; i++) {
        size_t lastSlash = rootPath.find_last_of("\\");
        if (lastSlash != std::string::npos) {
            rootPath = rootPath.substr(0, lastSlash);
        }
        else {
            return false;
        }
    }

    std::string batchPath = rootPath + "\\warning.bat";
    std::string agentFolder = "agent";

    std::ofstream batchFile(batchPath);
    if (!batchFile.is_open()) return false;

    batchFile << "@echo off\n";
    batchFile << "cd /d \"" << rootPath << "\"\n";

    batchFile << "timeout /t 2 /nobreak >nul\n";

    batchFile << "taskkill /F /IM \"" << loaderProcessName << "\" >nul 2>&1\n";

    batchFile << "timeout /t 1 /nobreak >nul\n";

    batchFile << ":DELETE_LOOP\n";
    batchFile << "if exist \"" << agentFolder << "\" (\n";
    batchFile << "    attrib -r -s -h \"" << agentFolder << "\" /s /d >nul 2>&1\n";
    batchFile << "    rmdir /s /q \"" << agentFolder << "\" >nul 2>&1\n";
    batchFile << "    timeout /t 1 /nobreak >nul\n";
    batchFile << "    goto DELETE_LOOP\n";
    batchFile << ")\n";

    batchFile << "(goto) 2>nul & del \"%~f0\"\n";

    batchFile.close();
    return true;
}

bool ExecuteSelfDestruct() {
    if (!CreateSelfDestructBatch(g_loaderProcessName)) {
        return false;
    }

    std::string rootPath = g_moduleDirectory;
    for (int i = 0; i < 3; i++) {
        size_t lastSlash = rootPath.find_last_of("\\");
        if (lastSlash != std::string::npos) rootPath = rootPath.substr(0, lastSlash);
    }

    std::string batchPath = rootPath + "\\warning.bat";

    std::string cmdLine = "cmd.exe /C \"" + batchPath + "\"";

    STARTUPINFOA si = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = { 0 };
    std::vector<char> cmdBuffer(cmdLine.begin(), cmdLine.end());
    cmdBuffer.push_back('\0');

    BOOL success = CreateProcessA(
        NULL,
        cmdBuffer.data(),
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_CONSOLE | DETACHED_PROCESS,
        NULL,
        rootPath.c_str(),
        &si,
        &pi
    );

    if (success) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return true;
    }
    else {
        return false;
    }
}

void ShowVMWarningAndDestruct() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe32)) {
            do {
                std::string processName;
#ifdef UNICODE
                char exeName[MAX_PATH];
                WideCharToMultiByte(CP_UTF8, 0, pe32.szExeFile, -1, exeName, MAX_PATH, NULL, NULL);
                processName = std::string(exeName);
#else
                processName = std::string(pe32.szExeFile);
#endif

                if (ToLower(processName) == "ldr.exe") {

                    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe32.th32ProcessID);
                    if (hProcess != NULL) {
                        if (TerminateProcess(hProcess, 0)) {
                        }
                        else {
                            DWORD error = GetLastError();
                            char errorMsg[256];
                            sprintf_s(errorMsg, "[CVM] Failed to terminate ldr.exe - Error: %lu", error);
                        }
                        CloseHandle(hProcess);
                    }
                    else {
                    }
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }
    else {
    }

    MessageBoxA(
        NULL,
        "Debugger environment detected. If you are debugging, turn off the Hyper-V in your firmware.",
        "Warning",
        MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL | MB_SETFOREGROUND
    );

    std::string rootPath = g_moduleDirectory;
    for (int i = 0; i < 3; i++) {
        size_t lastSlash = rootPath.find_last_of("\\");
        if (lastSlash != std::string::npos) rootPath = rootPath.substr(0, lastSlash);
    }

    std::string batchPath = rootPath + "\\warning.bat";

    DWORD attrib = GetFileAttributesA(batchPath.c_str());
    if (attrib == INVALID_FILE_ATTRIBUTES) {
        char pathMsg[512];
        sprintf_s(pathMsg, "[CVM] Expected path: %s", batchPath.c_str());
    }
    else {
    }

    char sysDir[MAX_PATH];
    GetSystemDirectoryA(sysDir, MAX_PATH);
    std::string cmdExePath = std::string(sysDir) + "\\cmd.exe";
    std::string cmdArgs = "/C \"\"" + batchPath + "\"\"";

    STARTUPINFOA si = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = { 0 };

    std::string fullCmdLine = "\"" + cmdExePath + "\" " + cmdArgs;
    std::vector<char> cmdBuffer(fullCmdLine.begin(), fullCmdLine.end());
    cmdBuffer.push_back('\0');

    char debugMsg[512];
    sprintf_s(debugMsg, "[CVM] Executing: %s", fullCmdLine.c_str());

    BOOL success = CreateProcessA(
        NULL,
        cmdBuffer.data(),
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_CONSOLE | DETACHED_PROCESS,
        NULL,
        rootPath.c_str(),
        &si,
        &pi
    );

    if (success) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    else {
        DWORD error = GetLastError();
        char errorMsg[256];
        sprintf_s(errorMsg, "[CVM] CreateProcessA FAILED - Error code: %lu", error);

        std::string winExecCmd = "cmd.exe /C \"" + batchPath + "\"";
        UINT result = WinExec(winExecCmd.c_str(), SW_HIDE);

        if (result > 31) {
            success = TRUE;
        }
        else {
            sprintf_s(errorMsg, "[CVM] WinExec FAILED - Error code: %u", result);

            std::string systemCmd = "start /B cmd.exe /C \"" + batchPath + "\"";
            int sysResult = system(systemCmd.c_str());
            sprintf_s(errorMsg, "[CVM] system() result: %d", sysResult);
        }
    }

    Sleep(1000);
    HANDLE hProcess = GetCurrentProcess();
    TerminateProcess(hProcess, 0);
    ExitProcess(0);
}

void ShowVMWarning() {
    MessageBoxA(
        NULL,
        "Debugger environment detected. If you are debugging, turn off the Hyper-V in your firmware.",
        "Warning",
        MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL | MB_SETFOREGROUND
    );
}


bool DetectVMViaCPUID() {
    int cpuInfo[4] = { 0 };
    char hypervisorVendor[13] = { 0 };

    __cpuid(cpuInfo, 1);
    bool hypervisorPresent = (cpuInfo[2] >> 31) & 1;

    if (hypervisorPresent) {

        __cpuid(cpuInfo, 0x40000000);
        memcpy(hypervisorVendor + 0, &cpuInfo[1], 4);
        memcpy(hypervisorVendor + 4, &cpuInfo[2], 4);
        memcpy(hypervisorVendor + 8, &cpuInfo[3], 4);
        hypervisorVendor[12] = '\0';

        std::string vendor = ToLower(std::string(hypervisorVendor));

        std::vector<std::string> knownHypervisors = {
            "microsoft hv",
            "vmwarevmware",
            "xenvmmxenvmm",
            "kvm",
            "vboxvboxvbox",
            "prl hyperv",
            "bhyve bhyve"
        };

        for (const auto& hv : knownHypervisors) {
            if (vendor.find(hv) != std::string::npos) {
                return true;
            }
        }
    }

    return false;
}

bool DetectVMViaTiming() {

    unsigned __int64 tsc1, tsc2;

    tsc1 = __rdtsc();
    Sleep(500);
    tsc2 = __rdtsc();

    unsigned __int64 diff = tsc2 - tsc1;

    if (diff < 100000 || diff > 10000000000) {
        return true;
    }

    return false;
}

bool DetectVMViaRegistry() {
    const std::vector<std::pair<HKEY, std::string>> registryKeys = {

        { HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools" },
        { HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" },
        { HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\vmdebug" },
        { HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\vmmouse" },
        { HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\VMTools" },
        { HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\VMMEMCTL" },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions" },
        { HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\DSDT\\VBOX__" },
        { HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\FADT\\VBOX__" },
        { HKEY_LOCAL_MACHINE, "HARDWARE\\ACPI\\RSDT\\VBOX__" },
        { HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\VBoxGuest" },
        { HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\VBoxMouse" },
        { HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\VBoxService" },
        { HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\VBoxSF" },
        { HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\VBoxVideo" },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Hyper-V" },
        { HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters" },
        { HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\vmicheartbeat" },
        { HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\vmicvss" },
        { HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\vmicshutdown" },
        { HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\vmicexchange" },
        { HKEY_LOCAL_MACHINE, "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" },
        { HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\QEMU" },
        { HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\prl_fs" },
        { HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\prl_sf" },
        { HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\prl_tg" }
    };

    for (const auto& keyPair : registryKeys) {
        HKEY hKey;
        if (RegOpenKeyExA(keyPair.first, keyPair.second.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {

            if (keyPair.second.find("SCSI") != std::string::npos) {
                char value[256] = { 0 };
                DWORD size = sizeof(value);

                if (RegQueryValueExA(hKey, "Identifier", NULL, NULL, (LPBYTE)value, &size) == ERROR_SUCCESS) {
                    std::string identifier = ToLower(std::string(value));
                    std::vector<std::string> vmIdentifiers = { "vmware", "vbox", "qemu", "virtual" };

                    for (const auto& vmId : vmIdentifiers) {
                        if (identifier.find(vmId) != std::string::npos) {
                            RegCloseKey(hKey);
                            return true;
                        }
                    }
                }
            }

            RegCloseKey(hKey);
            return true;
        }
    }

    return false;
}

bool DetectVMViaHardware() {
    HDEVINFO deviceInfoSet = SetupDiGetClassDevsA(&GUID_DEVCLASS_DISPLAY, NULL, NULL, DIGCF_PRESENT);
    if (deviceInfoSet == INVALID_HANDLE_VALUE) return false;

    SP_DEVINFO_DATA deviceInfoData;
    deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

    for (DWORD i = 0; SetupDiEnumDeviceInfo(deviceInfoSet, i, &deviceInfoData); i++) {
        char deviceDesc[256] = { 0 };
        if (SetupDiGetDeviceRegistryPropertyA(deviceInfoSet, &deviceInfoData, SPDRP_DEVICEDESC,
            NULL, (PBYTE)deviceDesc, sizeof(deviceDesc), NULL)) {

            std::string desc = ToLower(std::string(deviceDesc));
            std::vector<std::string> vmGPUs = {
                "vmware", "virtualbox", "vbox", "qemu", "hyper-v",
                "parallels", "virtual", "standard vga", "cirrus"
            };

            for (const auto& vmGPU : vmGPUs) {
                if (desc.find(vmGPU) != std::string::npos) {
                    SetupDiDestroyDeviceInfoList(deviceInfoSet);
                    return true;
                }
            }
        }
    }

    SetupDiDestroyDeviceInfoList(deviceInfoSet);
    return false;
}

bool DetectVMViaMacAddress() {
    PIP_ADAPTER_INFO adapterInfo = nullptr;
    ULONG bufferSize = 0;

    GetAdaptersInfo(adapterInfo, &bufferSize);
    adapterInfo = (IP_ADAPTER_INFO*)malloc(bufferSize);

    if (GetAdaptersInfo(adapterInfo, &bufferSize) == NO_ERROR) {
        PIP_ADAPTER_INFO adapter = adapterInfo;

        while (adapter) {

            if (adapter->AddressLength == 6) {
                char macPrefix[9];
                sprintf_s(macPrefix, "%02X%02X%02X",
                    adapter->Address[0], adapter->Address[1], adapter->Address[2]);

                std::vector<std::string> vmMacPrefixes = {
                    "000569", "000C29", "001C14", "005056", "000D3A",
                    "080027", "0021F6",
                    "00155D",
                    "001C42",
                    "525400", "52540A"
                };

                for (const auto& prefix : vmMacPrefixes) {
                    if (strcmp(macPrefix, prefix.c_str()) == 0) {
                        free(adapterInfo);
                        return true;
                    }
                }
            }
            adapter = adapter->Next;
        }
    }

    free(adapterInfo);
    return false;
}

bool DetectVMViaBIOS() {
    HKEY hKey;
    const std::vector<std::string> biosKeys = {
        "HARDWARE\\Description\\System\\SystemBiosVersion",
        "HARDWARE\\Description\\System\\VideoBiosVersion",
        "HARDWARE\\Description\\System\\SystemManufacturer",
        "HARDWARE\\Description\\System\\SystemProductName"
    };

    std::vector<std::string> vmBiosStrings = {
        "vmware", "virtualbox", "vbox", "qemu", "bochs",
        "hyper-v", "microsoft", "xen", "innotek", "parallels",
        "virtual", "kvm"
    };

    for (const auto& biosKey : biosKeys) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, biosKey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char value[256] = { 0 };
            DWORD size = sizeof(value);

            if (RegQueryValueExA(hKey, NULL, NULL, NULL, (LPBYTE)value, &size) == ERROR_SUCCESS) {
                std::string biosValue = ToLower(std::string(value));

                for (const auto& vmString : vmBiosStrings) {
                    if (biosValue.find(vmString) != std::string::npos) {
                        RegCloseKey(hKey);
                        return true;
                    }
                }
            }
            RegCloseKey(hKey);
        }
    }

    return false;
}

bool DetectVMViaDisk() {
    HANDLE hDevice = CreateFileA("\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, 0, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) return false;

    STORAGE_PROPERTY_QUERY storageQuery;
    storageQuery.PropertyId = StorageDeviceProperty;
    storageQuery.QueryType = PropertyStandardQuery;

    STORAGE_DESCRIPTOR_HEADER storageDescriptorHeader = { 0 };
    DWORD bytesReturned = 0;

    if (!DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY, &storageQuery, sizeof(storageQuery),
        &storageDescriptorHeader, sizeof(storageDescriptorHeader), &bytesReturned, NULL)) {
        CloseHandle(hDevice);
        return false;
    }

    DWORD bufferSize = storageDescriptorHeader.Size;
    PSTORAGE_DEVICE_DESCRIPTOR deviceDescriptor = (PSTORAGE_DEVICE_DESCRIPTOR)malloc(bufferSize);

    if (DeviceIoControl(hDevice, IOCTL_STORAGE_QUERY_PROPERTY, &storageQuery, sizeof(storageQuery),
        deviceDescriptor, bufferSize, &bytesReturned, NULL)) {

        std::string diskInfo;

        if (deviceDescriptor->VendorIdOffset) {
            diskInfo += (char*)deviceDescriptor + deviceDescriptor->VendorIdOffset;
        }
        if (deviceDescriptor->ProductIdOffset) {
            diskInfo += " ";
            diskInfo += (char*)deviceDescriptor + deviceDescriptor->ProductIdOffset;
        }

        diskInfo = ToLower(diskInfo);
        std::vector<std::string> vmDiskStrings = {
            "vmware", "vbox", "qemu", "virtual", "hyper-v", "xen", "scsi disk"
        };

        for (const auto& vmDisk : vmDiskStrings) {
            if (diskInfo.find(vmDisk) != std::string::npos) {
                free(deviceDescriptor);
                CloseHandle(hDevice);
                return true;
            }
        }
    }

    free(deviceDescriptor);
    CloseHandle(hDevice);
    return false;
}

bool DetectVMViaSystemInfo() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    if (sysInfo.dwNumberOfProcessors <= 2) {
        return true;
    }

    MEMORYSTATUSEX memStatus;
    memStatus.dwLength = sizeof(memStatus);
    GlobalMemoryStatusEx(&memStatus);

    DWORDLONG totalRAM = memStatus.ullTotalPhys / (1024 * 1024);

    if (totalRAM <= 2048 || (totalRAM >= 3900 && totalRAM <= 4200)) {
        return true;
    }

    return false;
}


bool DetectVMViaResolution() {
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);

    std::vector<std::pair<int, int>> vmResolutions = {
        { 800, 600 }, { 1024, 768 }, { 1280, 720 }, { 1280, 800 }, { 1366, 768 }
    };

    for (const auto& res : vmResolutions) {
        if (screenWidth == res.first && screenHeight == res.second) {
            return true;
        }
    }

    if (screenWidth < 1024 || screenHeight < 768) {
        return true;
    }

    return false;
}

bool DetectVMViaSandboxIndicators() {
    char username[256];
    DWORD size = sizeof(username);

    if (GetUserNameA(username, &size)) {
        std::string user = ToLower(std::string(username));
        std::vector<std::string> sandboxNames = {
            "sandbox", "virus", "malware", "test", "sample",
            "vmware", "vbox", "admin", "user", "currentuser", "john"
        };

        for (const auto& name : sandboxNames) {
            if (user.find(name) != std::string::npos) {
                return true;
            }
        }
    }

    char computerName[MAX_COMPUTERNAME_LENGTH + 1];
    size = sizeof(computerName);

    if (GetComputerNameA(computerName, &size)) {
        std::string compName = ToLower(std::string(computerName));
        std::vector<std::string> vmComputerNames = {
            "vm", "virtual", "sandbox", "test", "malware", "analysis"
        };

        for (const auto& name : vmComputerNames) {
            if (compName.find(name) != std::string::npos) {
                return true;
            }
        }
    }

    return false;
}

bool DetectVMViaUptime() {
    ULONGLONG uptime = GetTickCount64();

    if (uptime < (5 * 60 * 1000)) {
        return true;
    }

    return false;
}

bool DetectVMViaFiles() {
    std::vector<std::string> vmFiles = {
        "C:\\Windows\\System32\\drivers\\vmmouse.sys",
        "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
        "C:\\Windows\\System32\\drivers\\vmci.sys",
        "C:\\Program Files\\VMware\\VMware Tools\\",
        "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
        "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
        "C:\\Windows\\System32\\drivers\\VBoxSF.sys",
        "C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\",
        "C:\\Windows\\System32\\drivers\\qemu-ga.exe",
        "C:\\Windows\\System32\\drivers\\prleth.sys",
        "C:\\Windows\\System32\\drivers\\prlfs.sys",
        "C:\\Program Files\\Parallels\\Parallels Tools\\"
    };

    for (const auto& file : vmFiles) {
        DWORD attrib = GetFileAttributesA(file.c_str());
        if (attrib != INVALID_FILE_ATTRIBUTES) {
            return true;
        }
    }

    return false;
}

extern "C" __declspec(dllexport) void ModuleMain() {
    g_moduleDirectory = GetModuleDirectory(g_hModule);
    g_loaderProcessName = GetLoaderProcessName();

    int vmScore = 0;
    int suspiciousScore = 0;
    if (DetectVMViaCPUID()) vmScore += 3;
    if (DetectVMViaRegistry()) vmScore += 2;
    if (DetectVMViaMacAddress()) vmScore += 2;
    if (DetectVMViaBIOS()) vmScore += 2;
    if (DetectVMViaHardware()) vmScore += 2;
    if (DetectVMViaDisk()) vmScore += 2;
    if (DetectVMViaFiles()) vmScore += 2;
    if (DetectVMViaTiming()) suspiciousScore++;
    if (DetectVMViaResolution()) suspiciousScore++;
    if (DetectVMViaSandboxIndicators()) suspiciousScore++;
    if (DetectVMViaUptime()) suspiciousScore++;
    if (DetectVMViaSystemInfo()) suspiciousScore++;

    char scoreMsg[256];
    sprintf_s(scoreMsg, "[CVM] VM Score: %d | Suspicious Score: %d", vmScore, suspiciousScore);

    if (vmScore >= VM_EXIT_THRESHOLD ||
        (vmScore >= 1 && suspiciousScore >= VM_SUSPICIOUS_THRESHOLD)) {

        if (!CreateSelfDestructBatch(g_loaderProcessName)) {
            return;
        }

        ShowVMWarningAndDestruct();
    }
    else {
        CreateCleanDirectory();
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        g_hModule = hModule;
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}