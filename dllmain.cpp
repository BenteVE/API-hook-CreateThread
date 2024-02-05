#include <Windows.h>

#include "detours.h"
#include "Console.h"
#include "NtCreateThreadEx.hpp"

// The console to show debugging info
Console console;

// Uses GetModuleHandle and GetProcAddress to find a pointer to a specific function inside a specific DLL
FARPROC getAddress(LPCTSTR dllName, LPCSTR function) {
	HMODULE h_mod = GetModuleHandle(dllName);
	if (h_mod == 0) {
		fwprintf(console.stream, TEXT("No handle found for %s\n"), dllName);
		return NULL;
	}
	fwprintf(console.stream, TEXT("Found handle %p for dll %s\n"), h_mod, dllName);

	FARPROC address = GetProcAddress(h_mod, function);
	if (address == NULL) {
		fprintf(console.stream, "No handle found for %s\n", function);
		return NULL;
	}
	fprintf(console.stream, "Found address %p for %s\n", address, function);

	return address;
}


// Signature of the real CreateThread function, this function is documented in the Windows API 
typedef HANDLE(WINAPI* TrueCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, __drv_aliasesMem LPVOID, DWORD, LPDWORD);

// We need to store the address of the original function so we can still use it inside our hook
// The function is included in the Windows.h header (processthreadsapi.h), so we can just reference it without using GetProcAddress
TrueCreateThread createThread = CreateThread;

// Our intercept function
HANDLE WINAPI CreateThreadHook(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
	fprintf(console.stream, "CreateThread hook triggered \n");
	HANDLE h_thread = createThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
	fprintf(console.stream, "CreateThread created a thread with handle: %p \n", h_thread);

	return h_thread;
}


// Signature of the real NtCreateThreadEx function
// this function are some of its arguments are undocumented, but it is possible to find the signatures and structures online or through reverse engineering 
typedef NTSYSCALLAPI NTSTATUS(NTAPI* NtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PUSER_THREAD_START_ROUTINE, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);

// We need to store the address of the original function so we can still use it inside our hook
// The function is not included in the Windows.h header, so we need to find the address with GetProcAddress
NtCreateThreadEx ntCreateThreadEx = NULL;

NTSTATUS NTAPI NtCreateThreadExHook(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PUSER_THREAD_START_ROUTINE StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList)
{
	fprintf(console.stream, "NtCreateThreadEx hook triggered \n");
	NTSTATUS status = ntCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
	fprintf(console.stream, "NtCreateThreadEx created a thread with handle: %p \n", *ThreadHandle);

	return status;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:

	{
		if (!console.open()) {
			// Indicate DLL loading failed
			return FALSE;
		}

		// Get the address of the original function NtCreateThreadEx
		ntCreateThreadEx = (NtCreateThreadEx) getAddress(TEXT("ntdll.dll"), "NtCreateThreadEx");
		if (!ntCreateThreadEx) {
			return FALSE;
		}

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)ntCreateThreadEx, NtCreateThreadExHook);
		DetourAttach(&(PVOID&)createThread, CreateThreadHook);

		LONG lError = DetourTransactionCommit();
		if (lError != NO_ERROR) {
			fprintf(console.stream, "Detours failed to attach the hook\n");
			return FALSE;
		}

		fprintf(console.stream, "Hook attach successful\n");
	}
	break;

	case DLL_PROCESS_DETACH:

	{
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)ntCreateThreadEx, NtCreateThreadExHook);
		DetourDetach(&(PVOID&)createThread, CreateThreadHook);

		LONG lError = DetourTransactionCommit();
		if (lError != NO_ERROR) {
			fprintf(console.stream, "Detours failed to detach the hook\n");
			return FALSE;
		}
	}

	break;
	}

	return TRUE;
}