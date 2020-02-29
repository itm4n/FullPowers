
#include <iostream>
#include <Windows.h>
#include "Client.h"
#include "Server.h"

#define TIMEOUT 5000
#define VERSION L"0.1"

// Global variables
BOOL g_bVerbose = FALSE;
BOOL g_bClientMode = FALSE;
BOOL g_bInteract = TRUE;
int g_iThreadId = 0;
LPWSTR g_pwszCustomCommand = NULL;

// Function declarations 
void PrintUsage();

int wmain(int argc, wchar_t** argv)
{
    while ((argc > 1) && (argv[1][0] == '-'))
    {
        switch (argv[1][1])
        {
        case 'h':
            PrintUsage();
            return 0;
        case 'v':
            g_bVerbose = TRUE;
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
        case 't':
            ++argv;
            --argc;
            if (argc > 1 && argv[1][0] != '-')
            {
                g_iThreadId = wcstol(argv[1], NULL, 10);
            }
            else
            {
                wprintf(L"[-] Missing value for option: -t\n");
                PrintUsage();
                return -1;
            }
            g_bClientMode = TRUE;
            break;
        default:
            wprintf(L"[-] Invalid argument: %ls\n", argv[1]);
            PrintUsage();
            return -1;
        }

        ++argv;
        --argc;
    }

    if (g_bClientMode)
    {
        if (g_bVerbose)
            wprintf(L"[*] Running in 'CLIENT' mode.\n");
        
        if (!g_iThreadId)
        {
            wprintf(L"[-] Invalid argument: thread id\n");
            PrintUsage();
            return -1;
        }

        if (g_bVerbose)
            wprintf(L"[*] Target thread id is: %i\n", g_iThreadId);

        Client client = Client(g_iThreadId);
        client.SetVerbose(g_bVerbose);
        client.SetTimeout(TIMEOUT);
        client.Run();
    }
    else
    {
        if (g_bVerbose)
            wprintf(L"[*] Running in 'SERVER' mode.\n");

        Server server = Server();
        server.SetCustomCommand(g_pwszCustomCommand);
        server.SetInteract(g_bInteract);
        server.SetVerbose(g_bVerbose);
        server.SetTimeout(TIMEOUT);
        server.Run();
    }

    return 0;
}

void PrintUsage()
{
    wprintf(
        L"\n"
        "FullPowers v%ls (by @itm4n)\n"
        "\n"
        "  This tool leverages the Task Scheduler to recover the default privilege set of a service account.\n"
        "  For more information: https://itm4n.github.io/localservice-privileges/\n"
        "\n", 
        VERSION
    );

    wprintf(
        L"Optional arguments:\n"
        "  -v              Verbose mode, used for debugging essentially\n"
        "  -c <CMD>        Custom command line to execute (default is 'C:\\Windows\\System32\\cmd.exe')\n"
        "  -z              Non-interactive, create a new process and exit (default is 'interact with the new process')\n"
        "\n"
    );
}
