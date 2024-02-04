#include <Windows.h>

#include "detours.h"
#include "Console.h"

Console console;

typedef struct _INITIAL_TEB {
	PVOID                StackBase;
	PVOID                StackLimit;
	PVOID                StackCommit;
	PVOID                StackCommitMax;
	PVOID                StackReserved;
} INITIAL_TEB, * PINITIAL_TEB;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

/* signature of NtCreateThread
NTSYSAPI
NTSTATUS
NTAPI
NtCreateThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	OUT PCLIENT_ID ClientId,
	IN PCONTEXT ThreadContext,
	IN PINITIAL_TEB InitialTeb,
	IN BOOLEAN CreateSuspended);
*/

// Signature of the real NtCreateThread API
typedef NTSYSAPI NTSTATUS (NTAPI* True_NtCreateThread)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PCLIENT_ID, PCONTEXT, PINITIAL_TEB, BOOLEAN);

True_NtCreateThread true_NtCreateThread = NULL;

// Our intercept function
NTSTATUS NTAPI HookedNtCreateThread(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PCLIENT_ID ClientId, PCONTEXT ThreadContext, PINITIAL_TEB InitialTeb, BOOLEAN CreateSuspended)
{
	//printf("Created thread with id %i\n", *lpThreadId);
	NTSTATUS s = true_NtCreateThread(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientId, ThreadContext, InitialTeb, CreateSuspended);
	fprintf(console.stream, "Created Nt thread with handle: %p \n", *ThreadHandle);

	return s;
}



// Address of the real CreateThread API
HANDLE (WINAPI* trueCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, __drv_aliasesMem LPVOID, DWORD, LPDWORD) = CreateThread;

// Our intercept function
HANDLE WINAPI HookedCreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
	//printf("Created thread with id %i\n", *lpThreadId);
	HANDLE h = trueCreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
	fprintf(console.stream, "Created thread with handle: %p \n", h);

	return h;
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

		HMODULE h_ntdll = GetModuleHandle(TEXT("ntdll.dll"));

		if (h_ntdll == 0) {
			console.log("No handle found for ntdll.dll\n");
			return FALSE;
		}

		true_NtCreateThread = (True_NtCreateThread)GetProcAddress(h_ntdll, "NtCreateThread");
		if (true_NtCreateThread == NULL) {
			console.log("GetProcAddress failed, aborting detours\n");
			return FALSE;
		}

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)true_NtCreateThread, HookedNtCreateThread);
		DetourAttach(&(PVOID&)trueCreateThread, HookedCreateThread);

		LONG lError = DetourTransactionCommit();
		if (lError != NO_ERROR) {
			console.log("Detours failed to attach the hook\n");
			return FALSE;
		}

		console.log("Hook attach successful\n");
	}
	break;

	case DLL_PROCESS_DETACH:

	{
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)true_NtCreateThread, HookedNtCreateThread);
		DetourDetach(&(PVOID&)trueCreateThread, HookedCreateThread);

		LONG lError = DetourTransactionCommit();
		if (lError != NO_ERROR) {
			console.log("Detours failed to detach the hook\n");
			return FALSE;
		}
	}

	break;
	}

	return TRUE;
}