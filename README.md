# ThreadlessInject-C

This repository implements Threadless Injection in C

The original POC is available here: https://github.com/CCob/ThreadlessInject

# Implementation

The current implementation is designed to inject and execute calc.exe shellcode. Shellcode loading is not integrated. The POC is also tested with ```windows/x64/shell_reverse_tcp``` msfvenom payload. <br/> <br/>
Additionally, the current POC is intentionally implemented with WINAPIs instead of syscalls.
