#include <Windows.h>
#include <psapi.h>
#include "Injection.h"

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
InjectDLL(_In_ const PWCHAR DLLPath,
    _In_ HANDLE ProcessHandle
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

    if (ProcessHandle == INVALID_HANDLE_VALUE)
    {
        return ERROR_BAD_ARGUMENTS;
    }

    hThread = INVALID_HANDLE_VALUE;
    dllPathAddr = NULL;
    memset(fullDLLPath, 0, sizeof(fullDLLPath));

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
        CloseHandle(hThread);
    }

    return status;
}

int
InjectIntoPid(
    _In_ int Pid,
    _In_ WCHAR* DllPath
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
        CloseHandle(proc);
    }

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
    TOKEN_PRIVILEGES    TokenPrivileges;
    BOOL success;

    hToken = INVALID_HANDLE_VALUE;

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

    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Luid = SeDebugNameValue;
    TokenPrivileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    success = AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
    if (!success)
    {
        status = GetLastError();
        goto Cleanup;
    }

    status = ERROR_SUCCESS;

Cleanup:

    if (hToken != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hToken);
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
        CloseHandle(processInformation.hProcess);
    }
    
    if (ThreadHandle != NULL)
    {
        *ThreadHandle = processInformation.hThread;
    }
    else
    {
        CloseHandle(processInformation.hThread);
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
        CloseHandle(processHandle);
    }

    if (threadHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(threadHandle);
    }

    return status;

}