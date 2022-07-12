#include <Windows.h>

BOOL APIENTRY
DllMain(
    HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    int msgboxID;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        msgboxID = MessageBox(
            NULL,
            (LPCWSTR)L"Hello from injected dll",
            (LPCWSTR)L"Injection successful",
            MB_ICONWARNING | MB_OK
        );
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

