#include <Windows.h>

#include "detours.h"
#include "Console.h"

Console console;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PS_ATTRIBUTE
{
	ULONG_PTR Attribute;
	SIZE_T Size;
	union
	{
		ULONG_PTR Value;
		PVOID ValuePtr;
	};
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI* PUSER_THREAD_START_ROUTINE)(
	_In_ PVOID ThreadParameter
);


/* signature of NtCreateThreadEx (NtCreateThread is a legacy function and is not used anymore)
NTSYSCALLAPI
NTSTATUS
NTAPI
NtCreateThreadEx(
	_Out_ PHANDLE ThreadHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
	_In_ HANDLE ProcessHandle,
	_In_ PUSER_THREAD_START_ROUTINE StartRoutine,
	_In_opt_ PVOID Argument,
	_In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
	_In_ SIZE_T ZeroBits,
	_In_ SIZE_T StackSize,
	_In_ SIZE_T MaximumStackSize,
	_In_opt_ PPS_ATTRIBUTE_LIST AttributeList
	);

*/


// Signature of the real NtCreateThread API
typedef NTSYSCALLAPI NTSTATUS(NTAPI* True_NtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PUSER_THREAD_START_ROUTINE, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PPS_ATTRIBUTE_LIST);

True_NtCreateThreadEx true_NtCreateThreadEx = NULL;

// Our intercept function
NTSTATUS NTAPI HookedNtCreateThreadEx(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ProcessHandle, PUSER_THREAD_START_ROUTINE StartRoutine, PVOID Argument, ULONG CreateFlags, SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PPS_ATTRIBUTE_LIST AttributeList)
{
	//printf("Created thread with id %i\n", *lpThreadId);
	NTSTATUS s = true_NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, StartRoutine, Argument, CreateFlags, ZeroBits, StackSize, MaximumStackSize, AttributeList);
	fprintf(console.stream, "Created Nt thread with handle: %p \n", *ThreadHandle);

	return s;
}



// Address of the real CreateThread API
HANDLE(WINAPI* trueCreateThread)(LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, __drv_aliasesMem LPVOID, DWORD, LPDWORD) = CreateThread;

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

		true_NtCreateThreadEx = (True_NtCreateThreadEx)GetProcAddress(h_ntdll, "NtCreateThreadEx");
		if (true_NtCreateThreadEx == NULL) {
			console.log("GetProcAddress failed, aborting detours\n");
			return FALSE;
		}

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourAttach(&(PVOID&)true_NtCreateThreadEx, HookedNtCreateThreadEx);
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
		DetourDetach(&(PVOID&)true_NtCreateThreadEx, HookedNtCreateThreadEx);
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