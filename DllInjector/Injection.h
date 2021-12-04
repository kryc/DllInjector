#pragma once

#include <Windows.h>

int
EnableDebugPriv(
    void
);

int
InjectIntoPid(
    _In_ int Pid,
    _In_ WCHAR* DllPath
);

int
LaunchAndInject(
    _In_ const PWCHAR Command,
    _In_opt_ const PWCHAR Args,
    _In_ const PWCHAR DllPath
);