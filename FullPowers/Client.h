#pragma once

#include <Windows.h>
#include "Common.h"

class Client
{
private:
	BOOL m_bVerbose = FALSE;
	DWORD m_dwTimeout = 60000;
	DWORD m_dwThreadId = -1;
	HANDLE m_hImpersonationToken = INVALID_HANDLE_VALUE;

public:
	Client(DWORD dwThreadId);
	~Client();
	void SetVerbose(BOOL bVerbose);
	void SetTimeout(DWORD dwTimeout);
	BOOL Run();

private:
	BOOL SignalEvent(EventType type);
	BOOL CreateImpersonationToken();
	BOOL SetServerThreadToken();
};

