#include <Windows.h>
#include <psapi.h>
#include <processthreadsapi.h>
#include <winternl.h>
#include <stdio.h>
#include "Injection.h"

inline void
CloseAndNullHandle(
    _In_ HANDLE* Handle
)
{
    CloseHandle(*Handle);
    *Handle = NULL;
}

inline BOOL
HandleIsCurrentProcess(
    _In_ HANDLE ProcessHandle
)
 /*
 * Check that the handle provided is not
 * for the current process
 */
{
    DWORD handleId;

    handleId = GetProcessId(ProcessHandle);
    //if (handleId == 0)
    //{
    //    status = GetLastError();
    //    goto Cleanup;
    //}

    if (handleId == GetCurrentProcessId())
    {
        return TRUE;
    }
    return FALSE;
}

int
AwaitRemoteThreadCompletion(
    _In_ HANDLE Thread,
    _Out_ PDWORD ExitCode)
{
    int status;
    DWORD waitResult;
    BOOL exitCodeResult;

    *ExitCode = (DWORD)0;

    waitResult = WaitForSingleObject(Thread, INFINITE);
    if (waitResult == WAIT_FAILED)
    {
        status = GetLastError();
        goto Cleanup;
    }

    exitCodeResult = GetExitCodeThread(Thread, ExitCode);
    if (!exitCodeResult)
    {
        status = GetLastError();
        goto Cleanup;
    }

    //printf("Thread exited with code [0x%x]\n", ExitCode);

    status = ERROR_SUCCESS;

Cleanup:

    return status;
}

int
InjectDLL(
    _In_ const WCHAR* DLLPath,
    _In_ const HANDLE ProcessHandle
)
/*
 * DLL Injector
 * Code adapted from example on Wikipedia: https://en.wikipedia.org/wiki/DLL_injection
*/
{
    WCHAR  fullDLLPath[_MAX_PATH];
    LPVOID dllPathAddr;
    BOOL   memoryWritten;
    SIZE_T bytesWritten;
    HMODULE hKernel32;
    LPVOID loadLibraryAddr;
    HANDLE hThread;
    int status;
    DWORD  exitCode;
    DWORD pathRet;

    if (ProcessHandle == INVALID_HANDLE_VALUE || ProcessHandle == NULL)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    hThread = INVALID_HANDLE_VALUE;
    dllPathAddr = NULL;
    ZeroMemory(fullDLLPath, sizeof(fullDLLPath));

    if (HandleIsCurrentProcess(ProcessHandle))
    {
        status = ERROR_BAD_ARGUMENTS;
        goto Cleanup;
    }

    pathRet = GetFullPathNameW(DLLPath, _MAX_PATH, fullDLLPath, NULL);
    if (pathRet == 0)
    {
        status = GetLastError();
        goto Cleanup;
    }

    dllPathAddr = VirtualAllocEx(ProcessHandle, NULL, sizeof(fullDLLPath), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (dllPathAddr == NULL)
    {
        status = GetLastError();
        goto Cleanup;
    }

    memoryWritten = WriteProcessMemory(ProcessHandle, dllPathAddr, fullDLLPath, sizeof(fullDLLPath), &bytesWritten);
    if (!memoryWritten ||
        bytesWritten != sizeof(fullDLLPath)
        )
    {
        status = ERROR_IO_INCOMPLETE;
        goto Cleanup;
    }

    hKernel32 = GetModuleHandleW(L"Kernel32");
    if (hKernel32 == INVALID_HANDLE_VALUE || hKernel32 == 0)
    {
        status = GetLastError();
        goto Cleanup;
    }

    loadLibraryAddr = GetProcAddress(hKernel32, "LoadLibraryW");
    if (loadLibraryAddr == NULL)
    {
        status = GetLastError();
        goto Cleanup;
    }

    hThread = CreateRemoteThread(ProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, dllPathAddr, 0, NULL);
    if (hThread == INVALID_HANDLE_VALUE || hThread == 0)
    {
        status = GetLastError();
        goto Cleanup;
    }

    status = AwaitRemoteThreadCompletion(hThread, &exitCode);

Cleanup:

    if (dllPathAddr != NULL)
    {
        VirtualFreeEx(ProcessHandle, dllPathAddr, 0, MEM_RELEASE);
    }

    if (hThread != INVALID_HANDLE_VALUE && hThread != 0)
    {
        CloseAndNullHandle(&hThread);
    }

    return status;
}

int
InjectIntoPid(
    _In_ const int Pid,
    _In_ const WCHAR* DllPath
)
{
    int status;
    HANDLE proc;

    //
    // Open the process handle
    //
    proc = OpenProcess(
        PROCESS_ALL_ACCESS,
        /*PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION |
        PROCESS_VM_READ | PROCESS_VM_WRITE | SYNCHRONIZE, */
        FALSE, Pid
    );
    if (proc == NULL)
    {
        status = GetLastError();
        goto Cleanup;
    }

    //
    // Perform the DLL Injection
    //
    status = InjectDLL(DllPath, proc);

Cleanup:

    if (proc != NULL)
    {
        CloseAndNullHandle(&proc);
    }

    return status;
}

static int
FindImagePids(
    _In_ const WCHAR* ImageName,
    _Inout_ size_t* PidCount,
    _Out_writes_to_ptr_(PidCount, *PidCount) int* Pids
)
{
    int status;
    size_t providedCount;
    BOOL success;
    DWORD aProcesses[1024];
    DWORD cbNeeded;
    DWORD cProcesses;
    HANDLE hProcess;
    DWORD nameLength;
    WCHAR szProcessName[MAX_PATH];
    HMODULE hMod;
    size_t counter;

    providedCount = *PidCount;
    *PidCount = 0;
    *Pids = 0;

    success = EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded);
    if (!success)
    {
        status = GetLastError();
        goto Cleanup;
    }

    status = ERROR_NOT_FOUND;
    counter = 0;

    cProcesses = cbNeeded / sizeof(DWORD);
    for (size_t i = 0; i < cProcesses; i++)
    {
        hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
        if (hProcess == NULL)
        {
            continue;
        }

        success = EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded);
        if (!success)
        {
            CloseAndNullHandle(&hProcess);
            continue;
        }

        nameLength = GetModuleBaseNameW(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(WCHAR));
        if (nameLength == 0)
        {
            CloseAndNullHandle(&hProcess);
            continue;
        }

        if (wcscmp(szProcessName, ImageName) == 0) // right process
        {
            status = ERROR_SUCCESS;
            Pids[counter++] = (int)aProcesses[i];
            if (counter == providedCount)
            {
                CloseAndNullHandle(&hProcess);
                status = ERROR_INSUFFICIENT_BUFFER;
                goto Cleanup;
            }
        }

        CloseAndNullHandle(&hProcess);
    }

    *PidCount = counter;

Cleanup:

    return status;
}

int
InjectIntoImage(
    _In_ const WCHAR* ImageName,
    _In_ const WCHAR* DllPath
)
{
    int status;
    size_t pidCount;
    int pids[64];

    pidCount = ARRAYSIZE(pids);

    status = FindImagePids(ImageName, &pidCount, pids);
    if (status != ERROR_SUCCESS)
    {
        goto Cleanup;
    }

    for (size_t i = 0; i < pidCount; i++)
    {
        status = InjectIntoPid(pids[i], DllPath);
        if (status != ERROR_SUCCESS)
        {
            goto Cleanup;
        }
    }

Cleanup:

    return status;

}

int
EnableDebugPriv(
    void
)
{
    int status;
    HANDLE              hToken;
    LUID                SeDebugNameValue;
    TOKEN_PRIVILEGES    tokenPrivileges;
    BOOL success;

    hToken = INVALID_HANDLE_VALUE;
    ZeroMemory(&tokenPrivileges, sizeof(tokenPrivileges));

    success = OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
    if (!success)
    {
        status = GetLastError();
        goto Cleanup;
    }

    success = LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &SeDebugNameValue);
    if (!success)
    {
        status = GetLastError();
        goto Cleanup;
    }

    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = SeDebugNameValue;
    tokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    success = AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    if (!success)
    {
        status = GetLastError();
        goto Cleanup;
    }

    status = ERROR_SUCCESS;

Cleanup:

    if (hToken != INVALID_HANDLE_VALUE)
    {
        CloseAndNullHandle(&hToken);
    }

    return status;

}

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    IN  HANDLE ProcessHandle,
    IN  PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation,
    IN  ULONG ProcessInformationLength,
    OUT PULONG ReturnLength    OPTIONAL
    );

int
GetRemoteCommandLine(
    _In_ HANDLE hProc,
    _Out_ WCHAR** commandLineStr)
{
    int status;
    HMODULE hNtDll;
    pfnNtQueryInformationProcess ntQueryInformationProcess;
    ULONG_PTR wow64Information;
    PROCESS_BASIC_INFORMATION pbi;
    PEB peb;
    BOOL success;
    RTL_USER_PROCESS_PARAMETERS upp;
    WCHAR* commandLineContents;
    size_t bytesRead;

    commandLineContents = NULL;
    *commandLineStr = NULL;
    bytesRead = 0;
    ZeroMemory(&pbi, sizeof(pbi));
    ZeroMemory(&peb, sizeof(peb));
    ZeroMemory(&upp, sizeof(upp));
    ZeroMemory(&wow64Information, sizeof(wow64Information));

    //
    // First we need to find and read the remote process PEB
    //
    hNtDll = LoadLibraryExW(L"ntdll.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (hNtDll == NULL)
    {
        return GetLastError();
    }

    ntQueryInformationProcess = (pfnNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (ntQueryInformationProcess == NULL) {
        status = GetLastError();
        goto Cleanup;
    }

    //
    // Check if it is a wow64 process
    // We won't attempt to read a 32 bit PEB
    // Currently, 32 bit processes are not supported
    // 
    status = ntQueryInformationProcess(hProc, ProcessWow64Information, &wow64Information, sizeof(wow64Information), NULL);
    if (status < 0)
    {
        goto Cleanup;
    }

    if ((void*)wow64Information != NULL)
    {
        status = ERROR_SXS_ASSEMBLY_MISSING;
        goto Cleanup;
    }

    status = ntQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), NULL);
    if (status < 0)
    {
        status = GetLastError();
        goto Cleanup;
    }

    success = ReadProcessMemory(hProc, (PCHAR)pbi.PebBaseAddress, &peb, sizeof(PEB), NULL);
    if (!success)
    {
        status = GetLastError();
        goto Cleanup;
    }

    success = ReadProcessMemory(hProc, (PVOID)peb.ProcessParameters, &upp, sizeof(RTL_USER_PROCESS_PARAMETERS), NULL);
    if (!success)
    {
        status = GetLastError();
        goto Cleanup;
    }

    commandLineContents = (WCHAR*)calloc(upp.CommandLine.Length + 2, sizeof(BYTE));
    if (commandLineContents == NULL)
    {
        status = ERROR_INSUFFICIENT_BUFFER;
        goto Cleanup;
    }
    commandLineContents[upp.CommandLine.Length] = L'\0';

    /* read the command line */
    success = ReadProcessMemory(hProc, upp.CommandLine.Buffer, commandLineContents, upp.CommandLine.Length, &bytesRead);
    if (!success)
    {
        status = GetLastError();
        goto Cleanup;
    }

    *commandLineStr = commandLineContents;
    status = ERROR_SUCCESS;

Cleanup:

    FreeLibrary(hNtDll);

    if (commandLineContents != NULL && status != ERROR_SUCCESS)
    {
        free(commandLineContents);
    }

    return status;
}

int
InjectIntoProcessWithCommand(
    _In_ const WCHAR* CommandLine,
    _In_ const WCHAR* DllPath
)
{
    int status;
    BOOL success;
    DWORD aProcesses[1024];
    DWORD cbNeeded;
    DWORD cProcesses;
    HANDLE hProcess;
    WCHAR* commandLine;

    hProcess = NULL;
    status = ERROR_UNIDENTIFIED_ERROR;
    ZeroMemory(aProcesses, sizeof(aProcesses));

    success = EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded);
    if (!success)
    {
        status = GetLastError();
        goto Cleanup;
    }

    // Calculate how many process identifiers were returned.
    cProcesses = cbNeeded / sizeof(DWORD);

    for (size_t i = 0; i < cProcesses; i++)
    {
        if (aProcesses[i] != 0)
        {
            //
            // We want to skip the current process
            //
            if (aProcesses[i] == GetCurrentProcessId())
            {
                continue;
            }

            hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, aProcesses[i]);
            if (hProcess == INVALID_HANDLE_VALUE || hProcess == NULL)
            {
                continue;
            }

            commandLine = NULL;
            status = GetRemoteCommandLine(hProcess, &commandLine);
            if (status != ERROR_SUCCESS)
            {
                // Just skip this process if we fail to get the command line, and retry the next
                CloseAndNullHandle(&hProcess);
                continue;
            }

            if (wcsstr(commandLine, CommandLine) != NULL)
            {
                printf("[+] Injecting into command %ls\n", commandLine);
                free(commandLine);

                status = InjectDLL(DllPath, hProcess);
                CloseAndNullHandle(&hProcess);
                if (status != ERROR_SUCCESS)
                {
                    goto Cleanup;
                }
            }
        }
    }

Cleanup:

    if (hProcess != NULL)
    {
        CloseAndNullHandle(&hProcess);
    }

    return status;

}

static
int
CreateSuspendedProcess(
    _In_ const PWCHAR Command,
    _In_opt_ const PWCHAR Args,
    _Out_opt_ PHANDLE ProcessHandle,
    _Out_opt_ PHANDLE ThreadHandle,
    _Out_opt_ PDWORD  ProcessId
)
{
    int status;
    BOOL success;
    STARTUPINFO startupInfo;
    PROCESS_INFORMATION processInformation;

    ZeroMemory(&processInformation, sizeof(processInformation));
    ZeroMemory(&startupInfo, sizeof(startupInfo));
    startupInfo.cb = sizeof(startupInfo);

    success = CreateProcessW(
        Command,
        (LPWSTR)Args,
        NULL,
        NULL,
        FALSE,
        CREATE_NEW_CONSOLE | CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP,
        NULL,
        NULL,
        &startupInfo,
        &processInformation
    );
    if (!success)
    {
        status = GetLastError();
        goto Cleanup;
    }

    if (ProcessHandle != NULL)
    {
        *ProcessHandle = processInformation.hProcess;
    }
    else
    {
        CloseAndNullHandle(&processInformation.hProcess);
    }
    
    if (ThreadHandle != NULL)
    {
        *ThreadHandle = processInformation.hThread;
    }
    else
    {
        CloseAndNullHandle(&processInformation.hThread);
    }
    
    if (ProcessId != NULL)
    {
        *ProcessId = processInformation.dwProcessId;
    }

    status = ERROR_SUCCESS;

Cleanup:

    if (status != ERROR_SUCCESS)
    {
        if (ProcessHandle != NULL)
        {
            *ProcessHandle = NULL;
        }
        
        if (ThreadHandle != NULL)
        {
            *ThreadHandle = NULL;
        }
        
        if (ProcessId != NULL)
        {
            *ProcessId = 0;
        }
    }

    return status;

}

static
int
CreateSuspendedProcessEx(
    _In_ const PWCHAR Command,
    _In_ const PWCHAR Args[],
    _In_ const SIZE_T NumArgs,
    _Out_ PHANDLE ProcessHandle,
    _Out_ PHANDLE ThreadHandle,
    _Out_ PDWORD  ProcessId
)
{
    WCHAR commandLine[MAX_PATH];

    commandLine[0] = L'\0';

    for (SIZE_T arg = 0; arg < NumArgs; arg++)
    {
        wcsncat_s(commandLine, ARRAYSIZE(commandLine), Args[arg], wcslen(Args[arg]));
        if (arg < NumArgs - 1)
        {
            wcsncat_s(commandLine, ARRAYSIZE(commandLine), L" ", 1);
        }
    }

    return CreateSuspendedProcess(
        Command,
        commandLine,
        ProcessHandle,
        ThreadHandle,
        ProcessId
    );
}

int
LaunchAndInject(
    _In_ const PWCHAR Command,
    _In_opt_ const PWCHAR Args,
    _In_ const PWCHAR DllPath
)
{
    int status;
    HANDLE processHandle;
    HANDLE threadHandle;
    DWORD resumeResult;

    processHandle = INVALID_HANDLE_VALUE;
    threadHandle = INVALID_HANDLE_VALUE;

    //
    // Launch the program suspended so that we can
    // inject before the main thread starts
    //
    status = CreateSuspendedProcess(Command, Args, &processHandle, &threadHandle, NULL);
    if (status != ERROR_SUCCESS)
    {
        goto Cleanup;
    }

    //
    // Inject the DLL
    //
    status = InjectDLL(DllPath, processHandle);
    if (status != ERROR_SUCCESS)
    {
        goto Cleanup;
    }

    //
    // Resume the main thread
    //
    resumeResult = ResumeThread(threadHandle);
    if (resumeResult == -1)
    {
        status = GetLastError();
        goto Cleanup;
    }

    status = ERROR_SUCCESS;

Cleanup:

    if (processHandle != INVALID_HANDLE_VALUE)
    {
        CloseAndNullHandle(&processHandle);
    }

    if (threadHandle != INVALID_HANDLE_VALUE)
    {
        CloseAndNullHandle(&threadHandle);
    }

    return status;

}