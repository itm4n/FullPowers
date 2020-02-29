#pragma once

#include <Windows.h>
#include "Common.h"

typedef struct DummyThreadData {
	BOOL bVerbose;
	PHANDLE hTargetThread;
} DUMMYTHREADDATA, * PDUMMYTHREADDATA;

class Server
{
private:
	BOOL m_bVerbose = FALSE;
	BOOL m_bInteract = TRUE; // Can be set to FALSE with option -z
	DWORD m_dwTimeout = 60000;
	DWORD m_dwDummyThreadId = 0;
	LPCWSTR m_pwszTaskName = L"FullPowersTask";
	LPWSTR m_pwszCustomCommand = NULL; // Provided as a command line argument (-c)
	LPWSTR m_pwszCurrentUsername = NULL;
	LPWSTR m_pwszCurrentExecutable = NULL;
	HANDLE m_hDummyThread = INVALID_HANDLE_VALUE;
	HANDLE m_hMainThread = INVALID_HANDLE_VALUE;
	HANDLE m_hTaskStartedEvent = INVALID_HANDLE_VALUE;
	HANDLE m_hTaskCompletedEvent = INVALID_HANDLE_VALUE;

public:
	Server();
	~Server();
	void SetVerbose(BOOL bVerbose);
	void SetInteract(BOOL bInteract);
	void SetTimeout(DWORD dwTimeout);
	void SetCustomCommand(LPWSTR pwszCustomCommand);
	BOOL Run();

private:
	BOOL InitiliazeClass();
	BOOL GetCurrentUsername(LPWSTR pwszCurrentUsername, LPDWORD pdwUsernameLen);
	BOOL StartDummyThread();
	BOOL TerminateDummyThread();
	BOOL WaitForEvent(EventType type);
	BOOL CreateCustomEvent(EventType type);
	DWORD ResumeWaitDummyThread();
	BOOL CreateProcessWithNewToken();
	BOOL IsPrivilegePresent(HANDLE hToken, LPCWSTR pwszPrivName);
	BOOL CreateScheduledTask(LPCWSTR pwszTaskName, LPCWSTR pwszExecutable, LPCWSTR pwszArguments, LPCWSTR pwszUsername);
	BOOL StartScheduledTask(LPCWSTR pwszTaskName);
	BOOL DeleteScheduledTask(LPCWSTR pwszTaskName);
};

