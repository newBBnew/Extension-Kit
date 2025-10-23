#include <windows.h>
#include "bofdefs.h"
#include "base.c"
#include "queue.c"

void listDirW(wchar_t *path, unsigned short subdirs) {

	WIN32_FIND_DATAW fd = {0};
	HANDLE hand = NULL;
	LARGE_INTEGER fileSize;
	LONGLONG totalFileSize = 0;
	int nFiles = 0;
	int nDirs = 0;
	Pqueue dirQueue = queueInit();
	wchar_t * uncIndex;
	wchar_t * curitem;
	wchar_t * nextPath;
	int pathlen = KERNEL32$lstrlenW(path);

	// Per MSDN: "On network shares ... you cannot use an lpFileName that points to the share itself; for example, "\\Server\Share" is not valid."
	// Workaround: If we're using a UNC Path, there'd better be at least 4 backslashes
	// This breaks the convention, but a `cmd /c dir \\hostname\admin$` will work, so let's replicate that functionality.
	if (MSVCRT$_wcsnicmp(path, L"\\\\", 2) == 0) {
		uncIndex = MSVCRT$wcsstr(path + 2, L"\\");
		if (uncIndex != NULL && MSVCRT$wcsstr(uncIndex + 1, L"\\") == NULL) {
			MSVCRT$wcscat(path, L"\\");
			pathlen = pathlen + 1;
		}
	}

	// If the file ends in \ or is a drive (C:), throw a * on there
	if (MSVCRT$wcscmp(path + pathlen - 1, L"\\") == 0) {
		MSVCRT$wcscat(path, L"*");
	} else if (MSVCRT$wcscmp(path + pathlen - 1, L":") == 0) {
		MSVCRT$wcscat(path, L"\\*");
	}

	// Query the first file
	(hand = KERNEL32$FindFirstFileW(path, &fd));
	if (hand == INVALID_HANDLE_VALUE) {
		char* pathUtf8 = Utf16ToUtf8(path);
		internal_printf("Couldn't open %s: Error %u\n", pathUtf8, KERNEL32$GetLastError());
		intFree(pathUtf8);
		KERNEL32$FindClose(hand);
		return;
	}
	// If it's a single directory without a wildcard, re-run it with a \*
	if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY && MSVCRT$wcsstr(path, L"*") == NULL) {
		MSVCRT$wcscat(path, L"\\*");
		listDirW(path, subdirs);
		KERNEL32$FindClose(hand);
		return;
	}

	// Convert path to UTF-8 for display
	char* pathUtf8 = Utf16ToUtf8(path);
	internal_printf("Contents of %s:\n", pathUtf8);
	intFree(pathUtf8);

	do {
		// Get file write time
		SYSTEMTIME stUTC, stLocal;
		KERNEL32$FileTimeToSystemTime(&(fd.ftLastWriteTime), &stUTC);
		KERNEL32$SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

		internal_printf("\t%02d/%02d/%02d %02d:%02d",
				stLocal.wMonth, stLocal.wDay, stLocal.wYear, stLocal.wHour, stLocal.wMinute);

		// Convert filename to UTF-8 for display
		char* fileNameUtf8 = Utf16ToUtf8(fd.cFileName);

		// File size (or just print dir)
		if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
				internal_printf("%16s %s\n", "<junction>", fileNameUtf8);
			} else {
				internal_printf("%16s %s\n", "<dir>", fileNameUtf8);
			}
			nDirs++;
			// ignore . and ..
			if (MSVCRT$wcscmp(fd.cFileName, L".") == 0 || MSVCRT$wcscmp(fd.cFileName, L"..") == 0) {
				intFree(fileNameUtf8);
				continue;
			}
			// Queue subdirectory for recursion
			if (subdirs) {
				int pathLenW = KERNEL32$lstrlenW(path);
				int fileNameLenW = KERNEL32$lstrlenW(fd.cFileName);
				nextPath = (wchar_t*)intAlloc((pathLenW + fileNameLenW + 3) * sizeof(wchar_t) * 2);
				MSVCRT$wcsncpy(nextPath, path, pathLenW - 1);
				nextPath[pathLenW - 1] = L'\0';
				MSVCRT$wcscat(nextPath, fd.cFileName);
				dirQueue->push(dirQueue, nextPath);
			}
		} else {
			fileSize.LowPart = fd.nFileSizeLow;
			fileSize.HighPart = fd.nFileSizeHigh;
			internal_printf("%16lld %s\n", fileSize.QuadPart, fileNameUtf8);

			nFiles++;
			totalFileSize += fileSize.QuadPart;
		}

		intFree(fileNameUtf8);

	} while(KERNEL32$FindNextFileW(hand, &fd));
	internal_printf("\t%32lld Total File Size for %d File(s)\n", totalFileSize, nFiles);
	internal_printf("\t%55d Dir(s)\n", nDirs);

	// A single error (ERROR_NO_MORE_FILES) is normal
	DWORD err = KERNEL32$GetLastError();
	if (err != ERROR_NO_MORE_FILES) {
		BeaconPrintf(CALLBACK_ERROR, "Error fetching files: %u\n", err);
		KERNEL32$FindClose(hand);
		return;
	}

	KERNEL32$FindClose(hand);
	while((curitem = (wchar_t*)dirQueue->pop(dirQueue)) != NULL) {
		listDirW(curitem, subdirs);
		intFree(curitem);
	}
	dirQueue->free(dirQueue);

}

VOID go(
	IN PCHAR Buffer,
	IN ULONG Length
)
{
	datap parser;
	const wchar_t * targetpath = NULL;
	BeaconDataParse(&parser, Buffer, Length);
	targetpath = (const wchar_t*) BeaconDataExtract(&parser, NULL);
	SIZE_T targetpathLen = KERNEL32$lstrlenW(targetpath);
	unsigned short subdirs = BeaconDataShort(&parser);

	// Allocate buffer for wide string path
	// At worst, we will append \* so give it extra space
	wchar_t * realPath = (wchar_t*)intAlloc(2048 * sizeof(wchar_t));
	MSVCRT$wcsncpy(realPath, targetpath, 1023);
	realPath[1023] = L'\0';

	// Convert to UTF-8 for initial output
	char* pathUtf8 = Utf16ToUtf8(targetpath);
	BeaconPrintf(CALLBACK_OUTPUT, "Listing directory: %s\n", pathUtf8);
	intFree(pathUtf8);

	if(!bofstart())
	{
		intFree(realPath);
		return;
	}

	listDirW(realPath, subdirs);
	intFree(realPath);
	printoutput(TRUE);
};
