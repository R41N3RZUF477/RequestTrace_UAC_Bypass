# RequestTrace UAC Bypass

Windows 11 24H2 introduced new default scheduled tasks. One is RequestTrace, which can be started by pressing SHIFT+CTRL+WIN+T ... and can be used to bypass UAC. On startup the task looks for *%SystemRoot%\System32\PerformanceTraceHandler.dll*, but a user can change it's own *SystemRoot* environment variable for his own profile. Allowing a user to load a custom DLL and bypassing UAC, because the task runs elevated ... just by pressing a few keys.

![Press SHIFT+CTRL+WIN+T to bypass UAC](meme.jpg)

**Only works on Windows 11 24H2 (and maybe newer Windows 11 versions?)**

    Usage: RequestTrace_UAC_Bypass.exe [bypass|cleanup] [dll path]
    
    Example: RequestTrace_UAC_Bypass.exe bypass startcmd.dll

***Note: If the RequestTrace scheduled task is already running the UAC bypass fails. In this case the process (taskhostw.exe) running the task needs to be terminated. Terminating elevated processes of the same user by an unelevated process is still allowed in Windows.***

![RequestTrace_UAC_Bypass.exe bypasses UAC on highest setting](win11_uac_bypass.png)
