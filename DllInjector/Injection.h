#pragma once

#include <Windows.h>

int
EnableDebugPriv(
    void
);

int
InjectIntoPid(
    _In_ const int Pid,
    _In_ const WCHAR* DllPath
);

int
InjectIntoImage(
    _In_ const WCHAR* ImageName,
    _In_ const WCHAR* DllPath
);

int
InjectIntoProcessWithCommand(
    _In_ const WCHAR* CommandLine,
    _In_ const WCHAR* DllPath
);

int
LaunchAndInject(
    _In_ const PWCHAR Command,
    _In_opt_ const PWCHAR Args,
    _In_ const PWCHAR DllPath
);