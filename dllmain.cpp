#include <Windows.h>

#include "detours.h"

// Address of the real WriteFile API
typedef BOOL(WINAPI* True_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);

True_WriteFile true_Writefile = NULL;

// Our intercept function
BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
	const char* pBuf = "Your original text was replaced by the hooked function!";
	return true_Writefile(hFile, pBuf, strlen(pBuf), lpNumberOfBytesWritten, lpOverlapped);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
	{

		HMODULE modKernel32 = GetModuleHandle(TEXT("kernel32.dll"));

		if (modKernel32 == 0) {
			MessageBox(HWND_DESKTOP, TEXT("No handle found for kernel32.dll"), TEXT("Module handle not found"), MB_OK);
		}
		else
		{
			true_Writefile = (True_WriteFile)GetProcAddress(modKernel32, "WriteFile");
		}

		if (true_Writefile == NULL) {
			MessageBox(HWND_DESKTOP, TEXT("GetProcAddress failed, aborting detours"), TEXT("GetProcAddress Failed"), MB_OK);
		}
		else {

			DetourTransactionBegin();
			DetourUpdateThread(GetCurrentThread());
			DetourAttach(&(PVOID&)true_Writefile, HookedWriteFile);

			LONG lError = DetourTransactionCommit();
			if (lError != NO_ERROR) {
				MessageBox(HWND_DESKTOP, TEXT("Failed to attach the hook"), TEXT("Detours Error"), MB_OK);
				return FALSE;
			}
		}
	}
	break;

	case DLL_PROCESS_DETACH:
	{
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		DetourDetach(&(PVOID&)true_Writefile, HookedWriteFile);

		LONG lError = DetourTransactionCommit();
		if (lError != NO_ERROR) {
			MessageBox(HWND_DESKTOP, L"Failed to detach the hook", L"Detours Error", MB_OK);
			return FALSE;
		}
	}
	break;
	}

	return TRUE;
}


