# Dll Injector

Inject Microsoft Windows dll files into processes using CreateRemoteThread

## Overview
This project uses Windows APIs to inject a dll into a running process. Alternatively, it can spawn a new suspended process and inject the dll before execution begins.

## Usage
DllInjector works by injecting a provided dll file into a target process. There are several modes in which a user can specify which process to inject into.

`-pid`
The most basic, this will inject the dll into the given process ID.

`-image`
Injects into all processes with a given image name, ie "explorer.exe"

`-cmd`
Injects into all processes whose command line arguments match the provided string.

`-launch`
Launches a suspended process then injects the dll so that it will be run before the main program initialises. This is used in combination with the `-args` switch to specify the arguments to the target program.

## Example usages
Launch Microsoft Edge and inject a dll named mydll.dll. This will spawn a new suspended instance of Edge. **Note** that this means that the process is not initialized and things like delay-loaded modules will not be available.
```powershell
DllInjext.exe -launch "msedge.exe" -args "-inprivate" .\mydll.dll
```

Inject into the GPU process of edge. **Note** that this will inject into every process with `gpu-process` in the full command string.
```powershell
DllInjext.exe -cmd "gpu-process" .\mydll.dll
```