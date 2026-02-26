#include <iostream>
#include <winsock2.h>
#include <iphlpapi.h>
#include <miniupnpc/miniupnpc.h>
#include <miniupnpc/upnpcommands.h>
#include <miniupnpc/upnperrors.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "miniupnpc.lib")

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return 1;

    int error = 0;
    struct UPNPDev* devlist = upnpDiscover(2000, nullptr, nullptr, 0, 0, 2, &error);

    if (devlist) {
        struct UPNPUrls urls;
        struct IGDdatas data;
        char lanaddr[64];
        char externalIP[40] = { 0 };

        int status = UPNP_GetValidIGD(devlist, &urls, &data, lanaddr, sizeof(lanaddr), externalIP, sizeof(externalIP));

        if (status == 1 || status == 2) {
            std::cout << "[SUCCESS] Router is capable of Port Forwarding!" << std::endl;
            std::cout << "Local LAN IP: " << lanaddr << std::endl;

            if (externalIP[0] != '\0') {
                std::cout << "External IP: " << externalIP << std::endl;
            }
        }
        else {
            std::cout << "[FAIL] No valid Internet Gateway Device found. Status: " << status << std::endl;
        }

        FreeUPNPUrls(&urls);
        freeUPNPDevlist(devlist);
    }
    else {
        std::cout << "[FAIL] No UPnP devices detected. Error: " << error << std::endl;
    }

    WSACleanup();
    return 0;
}