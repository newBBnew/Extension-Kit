#pragma once

#include <windows.h>
#include <winspool.h>

// Parser structure (must be defined before Beacon API declarations)
typedef struct {
    char* original;
    char* buffer;
    int length;
    int size;
} datap;

// Beacon API
DECLSPEC_IMPORT WINBASEAPI void __cdecl BeaconDataParse(datap* parser, char* buffer, int size);
DECLSPEC_IMPORT WINBASEAPI int __cdecl BeaconDataInt(datap* parser);
DECLSPEC_IMPORT WINBASEAPI short __cdecl BeaconDataShort(datap* parser);
DECLSPEC_IMPORT WINBASEAPI int __cdecl BeaconDataLength(datap* parser);
DECLSPEC_IMPORT WINBASEAPI char* __cdecl BeaconDataExtract(datap* parser, int* size);
DECLSPEC_IMPORT WINBASEAPI void __cdecl BeaconPrintf(int type, char* fmt, ...);
DECLSPEC_IMPORT WINBASEAPI BOOL __cdecl BeaconUseToken(HANDLE token);
DECLSPEC_IMPORT WINBASEAPI void __cdecl BeaconRevertToken(void);
DECLSPEC_IMPORT WINBASEAPI BOOL __cdecl BeaconIsAdmin(void);

// Beacon output types
#define CALLBACK_OUTPUT 0x0
#define CALLBACK_OUTPUT_OEM 0x1e
#define CALLBACK_ERROR 0x0d
#define CALLBACK_OUTPUT_UTF8 0x20

// Windows API - KERNEL32
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateNamedPipeA(LPCSTR lpName, DWORD dwOpenMode, DWORD dwPipeMode, DWORD nMaxInstances, DWORD nOutBufferSize, DWORD nInBufferSize, DWORD nDefaultTimeOut, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$ConnectNamedPipe(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetCurrentThread(VOID);
DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(VOID);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds);
DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR lpLibFileName);
DECLSPEC_IMPORT WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE hModule, LPCSTR lpProcName);

// Windows API - ADVAPI32
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$OpenThreadToken(HANDLE ThreadHandle, DWORD DesiredAccess, BOOL OpenAsSelf, PHANDLE TokenHandle);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$GetTokenInformation(HANDLE TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, LPVOID TokenInformation, DWORD TokenInformationLength, PDWORD ReturnLength);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$ConvertSidToStringSidW(PSID Sid, LPWSTR* StringSid);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$ImpersonateNamedPipeClient(HANDLE hNamedPipe);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$RevertToSelf(VOID);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$DuplicateTokenEx(HANDLE hExistingToken, DWORD dwDesiredAccess, LPSECURITY_ATTRIBUTES lpTokenAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLevel, TOKEN_TYPE TokenType, PHANDLE phNewToken);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$SetThreadToken(PHANDLE Thread, HANDLE Token);
DECLSPEC_IMPORT WINADVAPI BOOL WINAPI ADVAPI32$CreateProcessWithTokenW(HANDLE hToken, DWORD dwLogonFlags, LPCWSTR lpApplicationName, LPWSTR lpCommandLine, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
DECLSPEC_IMPORT WINADVAPI BOOLEAN WINAPI ADVAPI32$SystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength);

// Windows API - MSVCRT
DECLSPEC_IMPORT int __cdecl MSVCRT$strcmp(const char* str1, const char* str2);
DECLSPEC_IMPORT int __cdecl MSVCRT$wcscmp(const wchar_t* str1, const wchar_t* str2);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char* str);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$wcslen(const wchar_t* str);
DECLSPEC_IMPORT int __cdecl MSVCRT$sprintf(char* buffer, const char* format, ...);
DECLSPEC_IMPORT int __cdecl MSVCRT$swprintf(wchar_t* buffer, size_t count, const wchar_t* format, ...);
DECLSPEC_IMPORT size_t __cdecl MSVCRT$mbstowcs(wchar_t* wcstr, const char* mbstr, size_t count);

// Note: WINSPOOL functions are loaded dynamically in printspoofer.c using LoadLibrary/GetProcAddress

