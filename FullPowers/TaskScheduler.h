#pragma once

BOOL CreateScheduledTask(LPCWSTR pwszTaskName, LPCWSTR pwszExecutable, LPCWSTR pwszArguments, LPCWSTR pwszUsername, BOOL bExtendedPrivSet);
BOOL StartScheduledTask(LPCWSTR pwszTaskName, LPDWORD pdwTaskPid);
BOOL DeleteScheduledTask(LPCWSTR pwszTaskName);
BOOL GetCurrentUsername(LPWSTR pwszCurrentUsername, LPDWORD pdwUsernameLen);
