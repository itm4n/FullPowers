
#include <Windows.h>
#include <taskschd.h>
#include <iostream>
#include <comdef.h>

#pragma comment(lib, "taskschd.lib")

BOOL CreateScheduledTask(LPCWSTR pwszTaskName, LPCWSTR pwszExecutable, LPCWSTR pwszArguments, LPCWSTR pwszUsername, BOOL bExtendedPrivSet)
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
		wprintf(L"[-] CoInitializeEx() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		return bRes;
	}

	hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
	if (FAILED(hr))
	{
		wprintf(L"[-] CoInitializeSecurity() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
	if (FAILED(hr))
	{
		wprintf(L"[-] CoCreateInstance(ITaskService) failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pService->Connect(VARIANT(), VARIANT(), VARIANT(), VARIANT());
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskService::Connect() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pService->GetFolder(BSTR(L"\\"), &pRootFolder);
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskService::GetFolder() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	pRootFolder->DeleteTask(BSTR(pwszTaskName), 0);

	hr = pService->NewTask(0, &pTask);
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskService::NewTask() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pTask->get_RegistrationInfo(&pRegInfo);
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskDefinition::get_RegistrationInfo() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	//hr = pRegInfo->put_Author(BSTR(m_pwszCurrentUsername));
	//if (FAILED(hr))
	//{
	//	wprintf(L"[-] IRegistrationInfo::put_Author() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
	//	goto cleanup;
	//}

	hr = pTask->get_Principal(&pPrincipal);
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskDefinition::get_Principal() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pPrincipal->put_UserId(BSTR(pwszUsername));
	if (FAILED(hr))
	{
		wprintf(L"[-] IPrincipal::put_Id() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pPrincipal->put_LogonType(TASK_LOGON_SERVICE_ACCOUNT);
	if (FAILED(hr))
	{
		wprintf(L"[-] IPrincipal::put_LogonType() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pPrincipal->QueryInterface(IID_IPrincipal2, (void**)&pPrincipal2);
	if (FAILED(hr))
	{
		wprintf(L"[-] IPrincipal::QueryInterface() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	// By default, the task scheduler creates a new process with a token which contains the 
	// default set of privileges of the account without SeImpersonate. Therefore, we must add it
	// manually. But, doing so, it will reset the default set of privileges so, in the end, we must
	// add every single privilege manually.
	if (bExtendedPrivSet)
	{
		for (int i = 0; i < (sizeof(ppwszRequiredPrivilegesExtended) / sizeof(*ppwszRequiredPrivilegesExtended)); i++)
		{
			hr = pPrincipal2->AddRequiredPrivilege(BSTR(ppwszRequiredPrivilegesExtended[i]));
			if (FAILED(hr))
			{
				wprintf(L"[-] IPrincipal2::AddRequiredPrivilege('%ws') failed (Err: 0x%x - %ws)\n", ppwszRequiredPrivilegesExtended[i], hr, _com_error(hr).ErrorMessage());
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
				wprintf(L"[-] IPrincipal2::AddRequiredPrivilege('%ws') failed (Err: 0x%x - %ws)\n", ppwszRequiredPrivileges[i], hr, _com_error(hr).ErrorMessage());
				goto cleanup;
			}
		}
	}

	hr = pTask->get_Actions(&pActionCollection);
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskDefinition::get_Actions() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
	if (FAILED(hr))
	{
		wprintf(L"[-] IActionCollection::Create() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
	if (FAILED(hr))
	{
		wprintf(L"[-] IAction::QueryInterface() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pExecAction->put_Path(BSTR(pwszExecutable));
	if (FAILED(hr))
	{
		wprintf(L"[-] IExecAction::put_Path() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pExecAction->put_Arguments(BSTR(pwszArguments));
	if (FAILED(hr))
	{
		wprintf(L"[-] IExecAction::put_Arguments() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pRootFolder->RegisterTaskDefinition(_bstr_t(pwszTaskName), pTask, TASK_CREATE_OR_UPDATE, _variant_t(), _variant_t(), TASK_LOGON_SERVICE_ACCOUNT, _variant_t(L""), &pRegisteredTask);
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskFolder::RegisterTaskDefinition() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
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

BOOL StartScheduledTask(LPCWSTR pwszTaskName, LPDWORD pdwTaskPid)
{
	BOOL bRes = FALSE;
	DWORD dwTaskPid = 0;
	HRESULT hr = S_OK;
	ITaskService* pService = NULL;
	ITaskFolder* pRootFolder = NULL;
	IRegisteredTask* pRegisteredTask = NULL;
	IRunningTask* pRunningTask = NULL;

	hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr))
	{
		wprintf(L"[-] CoInitializeEx() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		return bRes;
	}

	hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
	if (FAILED(hr))
	{
		wprintf(L"[-] CoInitializeSecurity() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
	if (FAILED(hr))
	{
		wprintf(L"[-] CoCreateInstance(ITaskService) failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pService->Connect(VARIANT(), VARIANT(), VARIANT(), VARIANT());
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskService::Connect() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pService->GetFolder(BSTR(L"\\"), &pRootFolder);
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskService::GetFolder() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pRootFolder->GetTask(BSTR(pwszTaskName), &pRegisteredTask);
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskFolder::GetTask() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pRegisteredTask->Run(_variant_t(_bstr_t(L"")), &pRunningTask);
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskRegisteredTask::Run() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pRunningTask->get_EnginePID(&dwTaskPid);
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskRegisteredTask::get_EnginePID() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	*pdwTaskPid = dwTaskPid;
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

BOOL DeleteScheduledTask(LPCWSTR pwszTaskName)
{
	BOOL bRes = FALSE;
	HRESULT hr = S_OK;
	ITaskService* pService = NULL;
	ITaskFolder* pRootFolder = NULL;

	hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
	if (FAILED(hr))
	{
		wprintf(L"[-] CoInitializeEx() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		return bRes;
	}

	hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
	if (FAILED(hr))
	{
		wprintf(L"[-] CoInitializeSecurity() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
	if (FAILED(hr))
	{
		wprintf(L"[-] CoCreateInstance(ITaskService) failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pService->Connect(VARIANT(), VARIANT(), VARIANT(), VARIANT());
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskService::Connect() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pService->GetFolder(BSTR(L"\\"), &pRootFolder);
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskService::GetFolder() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
		goto cleanup;
	}

	hr = pRootFolder->DeleteTask(BSTR(pwszTaskName), 0);
	if (FAILED(hr))
	{
		wprintf(L"[-] ITaskFolder::DeleteTask() failed (Err: 0x%x - %ws)\n", hr, _com_error(hr).ErrorMessage());
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

BOOL GetCurrentUsername(LPWSTR pwszCurrentUsername, LPDWORD pdwUsernameLen)
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
