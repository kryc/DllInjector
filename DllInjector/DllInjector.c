#include <stdio.h>
#include <string.h>
#include <Windows.h>
#include <winerror.h>
#include "Injection.h"

typedef enum _mode
{
    MODE_NONE =     0x0,
    MODE_PID =      0x1,
    MODE_LAUNCH =   0x2,
    MODE_IMAGE =    0x4,
    MODE_COMMAND =  0x8
} MODE;

int
GetErrorMessage(
    _In_ int Error,
    _Out_ WCHAR **Message
)
{
    int status;
    WCHAR* buffer;

    buffer = calloc(1024, sizeof(WCHAR));
    if (buffer == NULL)
    {
        status = ERROR_INSUFFICIENT_BUFFER;
        goto Cleanup;
    }

    DWORD cchMsg = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,  /* (not used with FORMAT_MESSAGE_FROM_SYSTEM) */
        Error,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        buffer,
        1024,
        NULL);
    if (cchMsg == 0)
    {
        status = GetLastError();
        goto Cleanup;
    }

    *Message = buffer;
    status = ERROR_SUCCESS;

Cleanup:

    if (status != ERROR_SUCCESS)
    {
        free(buffer);
        *Message = NULL;
    }

    return status;

}

int
wmain(
    _In_ int argc,
    _In_ WCHAR* argv[]
)
{
    int ret;
    MODE mode;
    int pid;
    WCHAR* imageName;
    WCHAR* commandLine;
    WCHAR* launchPath;
    WCHAR* launchArgs;
    WCHAR* dll;
    WCHAR* errorMessage;
    BOOL debugPrivs;

    if (argc < 2)
    {
        printf("[+] Usage: %ls <args>* [DLL File]\n", argv[0]);
        return 0;
    }

    mode = MODE_NONE;
    pid = -1;
    dll = NULL;
    imageName = NULL;
    commandLine = NULL;
    launchArgs = NULL;
    launchPath = NULL;
    errorMessage = NULL;
    debugPrivs = FALSE;

    //
    // DLL path is always the last argument
    //
    dll = argv[argc - 1];
    
    //
    // Parse out any optional command line switches
    //
    for (int i = 1; i < argc - 1; i++)
    {
        if (wcscmp(argv[i], L"-pid") == 0)
        {
            if (i == argc - 1)
            {
                fprintf(stderr, "[!] ERROR: No pid specified\n");
                ret = ERROR_BAD_ARGUMENTS;
                goto Cleanup;
            }

            mode |= MODE_PID;
            pid = _wtoi(argv[i + 1]);
            i++;
        }
        else if (wcscmp(argv[i], L"-image") == 0)
        {
            if (i == argc - 1)
            {
                fprintf(stderr, "[!] ERROR: No image name specified\n");
                ret = ERROR_BAD_ARGUMENTS;
                goto Cleanup;
            }

            mode |= MODE_IMAGE;
            imageName = argv[i + 1];
            i++;
        }
        else if (wcscmp(argv[i], L"-cmd") == 0)
        {
            if (i == argc - 1)
            {
                fprintf(stderr, "[!] ERROR: No command line specified\n");
                ret = ERROR_BAD_ARGUMENTS;
                goto Cleanup;
            }

            mode |= MODE_COMMAND;
            commandLine = argv[i + 1];
            i++;
        }
        else if (wcscmp(argv[i], L"-launch") == 0)
        {
            if (i == argc - 1)
            {
                fprintf(stderr, "[!] ERROR: No executable specified\n");
                ret = ERROR_BAD_ARGUMENTS;
                goto Cleanup;
            }

            mode |= MODE_LAUNCH;
            launchPath = argv[i + 1];
            i++;
        }
        else if (wcscmp(argv[i], L"-args") == 0)
        {
            if (i == argc - 1)
            {
                fprintf(stderr, "[!] ERROR: No arguments specified\n");
                ret = ERROR_BAD_ARGUMENTS;
                goto Cleanup;
            }

            launchArgs = argv[i + 1];
            i++;
        }
        else if (wcscmp(argv[i], L"-debug") == 0)
        {
            printf("[+] Forcing use of debug privileges\n");
            debugPrivs = TRUE;
        }
        else if (argv[i][0] == L'-')
        {
            fprintf(stderr, "[!] Error unrecognised command switch: %ls\n", argv[i]);
            ret = ERROR_BAD_ARGUMENTS;
            goto Cleanup;
        }
    }

    //
    // Obatin debug privileges
    //
    if (debugPrivs || (mode & MODE_COMMAND) != 0)
    {
        printf("[+] Obtaining debug privileges\n");
        ret = EnableDebugPriv();
        if (ret != ERROR_SUCCESS)
        {
            fprintf(stderr, "[!] Error obtaining debug privileges\n");
            goto Cleanup;
        }
    }

    //
    // Validate operating mode and provided arguments
    //
    switch (mode)
    {
    case MODE_PID:
        if (pid == -1)
        {
            fprintf(stderr, "[!] Error no pid specified\n");
            ret = ERROR_BAD_ARGUMENTS;
            goto Cleanup;
        }

        printf("[+] Injecting into pid %d\n", pid);
        ret = InjectIntoPid(pid, dll);
        break;
    case MODE_IMAGE:
        if (imageName == NULL)
        {
            fprintf(stderr, "[!] Error no image name specified\n");
            ret = ERROR_BAD_ARGUMENTS;
            goto Cleanup;
        }

        printf("[+] Injecting into processes with image name \"%ls\"\n", imageName);
        ret = InjectIntoImage(imageName, dll);
        break;
    case MODE_COMMAND:
        if (commandLine == NULL)
        {
            fprintf(stderr, "[!] Error no command line specified\n");
            ret = ERROR_BAD_ARGUMENTS;
            goto Cleanup;
        }

        printf("[+] Injecting into processes with \"%ls\" in command line\n", commandLine);
        ret = InjectIntoProcessWithCommand(commandLine, dll);
        break;
    case MODE_LAUNCH:
        if (launchPath == NULL)
        {
            fprintf(stderr, "[!] Error no launch path specified\n");
            ret = ERROR_BAD_ARGUMENTS;
            goto Cleanup;
        }

        printf("[+] Launching program and injecting DLL\n");
        ret = LaunchAndInject(launchPath, launchArgs, dll);
        break;
    default:
        fprintf(stderr, "[!] Error no or invalid operating mode specified\n");
        ret = ERROR_BAD_ARGUMENTS;
        goto Cleanup;
    }
    
    if (ret != ERROR_SUCCESS)
    {
        ret = GetErrorMessage(ret, &errorMessage);
        if (ret != ERROR_SUCCESS)
        {
            fprintf(stderr, "[!] Unknown error\n");
            goto Cleanup;
        }

        fprintf(stderr, "[!] Error %ls\n", errorMessage);
        goto Cleanup;
    }

    printf("[+] Injection successful\n");

Cleanup:

    if (errorMessage != NULL)
    {
        free(errorMessage);
    }

    return ret;

}