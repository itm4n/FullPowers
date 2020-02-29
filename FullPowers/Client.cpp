
#include <iostream>
#include "Client.h"
#include "Common.h"

Client::Client(DWORD dwThreadId)
{
	m_dwThreadId = dwThreadId;
}

Client::~Client()
{
	if (m_hImpersonationToken)
		CloseHandle(m_hImpersonationToken);
}

void Client::SetVerbose(BOOL bVerbose)
{
	m_bVerbose = bVerbose;
}

void Client::SetTimeout(DWORD dwTimeout)
{
	m_dwTimeout = dwTimeout;
}

BOOL Client::Run()
{
	// 1) Tell the server that we started 
	if (m_bVerbose)
		wprintf(L"[*] Process start, tell the server.\n");
	if (!SignalEvent(EventType::EVT_TASK_STARTED))
		return FALSE;

	// 2) Duplicate our access token 
	if (!CreateImpersonationToken())
		return FALSE;

	wprintf(L"[+] Successfully duplicated current token.\n");

	// 3) Apply token to the server's dummy thread
	if (!SetServerThreadToken())
		return FALSE;

	wprintf(L"[+] Successfully set duplicated token on server's thread.\n");

	if (!SignalEvent(EventType::EVT_TASK_COMPLETED))
		return FALSE;

	return TRUE;
}

BOOL Client::SignalEvent(EventType type)
{
	BOOL bRet = FALSE;
	HANDLE hEvent = INVALID_HANDLE_VALUE;
	LPCWSTR pwszEventName;

	switch (type)
	{
	case EventType::EVT_TASK_STARTED:
		pwszEventName = EVT_TASK_STARTED_NAME;
		break;
	case EventType::EVT_TASK_COMPLETED:
		pwszEventName = EVT_TASK_COMPLETED_NAME;
		break;
	default:
		wprintf(L"[-] SignalEvent() failed. Unknown event type.\n");
		return FALSE;
	}

	hEvent = OpenEvent(EVENT_MODIFY_STATE, FALSE, pwszEventName);
	if (hEvent == NULL)
	{
		wprintf(L"[-] OpenEvent() failed (Err: %d)\n", GetLastError());
		goto cleanup;
	}

	if (!SetEvent(hEvent))
	{
		wprintf(L"[-] SetEvent() failed (Err: %d)\n", GetLastError());
		goto cleanup;
	}

	bRet = TRUE;

cleanup:
	if (hEvent)
		CloseHandle(hEvent);

	return bRet;
}

BOOL Client::CreateImpersonationToken()
{
	BOOL bRet = FALSE;
	HANDLE hCurrentProcess = INVALID_HANDLE_VALUE;
	HANDLE hCurrentToken = INVALID_HANDLE_VALUE;

	hCurrentProcess = GetCurrentProcess();

	if (!OpenProcessToken(hCurrentProcess, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &hCurrentToken))
	{
		wprintf(L"[-] OpenProcessToken() failed (Err: %d)\n", GetLastError());
		goto cleanup;
	}

	if (m_bVerbose)
		wprintf(L"[*] OpenProcessToken() OK\n");

	if (!DuplicateTokenEx(hCurrentToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &m_hImpersonationToken))
	{
		wprintf(L"[-] DuplicateTokenEx() failed (Err: %d)\n", GetLastError());
		goto cleanup;
	}

	if (m_bVerbose)
		wprintf(L"[*] DuplicateTokenEx() OK\n");

	bRet = TRUE;

cleanup:
	if (hCurrentToken)
		CloseHandle(hCurrentToken);

	return bRet;
}

BOOL Client::SetServerThreadToken()
{
	BOOL bRes = FALSE;
	HANDLE hServerThread = INVALID_HANDLE_VALUE;

	hServerThread = OpenThread(THREAD_SET_THREAD_TOKEN, FALSE, m_dwThreadId);
	if (!hServerThread)
	{
		wprintf(L"[-] OpenThread() failed (Err: %d)\n", GetLastError());
		goto cleanup;
	}

	if (m_bVerbose)
		wprintf(L"[*] OpenThread() OK\n");

	if (!SetThreadToken(&hServerThread, m_hImpersonationToken))
	{
		wprintf(L"[-] SetThreadToken() failed (Err: %d)\n", GetLastError());
		goto cleanup;
	}

	if (m_bVerbose)
		wprintf(L"[*] SetThreadToken() OK\n");

	bRes = TRUE;

cleanup:
	if (hServerThread)
		CloseHandle(hServerThread);

	return bRes;
}
