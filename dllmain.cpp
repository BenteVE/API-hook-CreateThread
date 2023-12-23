// dllmain.cpp : Defines the entry point for the DLL application.
// project settings: Linked => Input => Additional Dependencies => detours.lib
#include "pch.h"
#include "detours.h"
#include "detver.h"
#include "syelog.h"



// Address of the real WriteFile API
typedef BOOL(WINAPI* True_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);

True_WriteFile true_Writefile = NULL;

/*
BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
    return True_WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}
*/

// Our intercept function
BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)
{
    const char* pBuf = "Your original text was replaced by the hooked function!";
    return true_Writefile(hFile, pBuf, 55, lpNumberOfBytesWritten, lpOverlapped);
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
        {

            HMODULE modKernel32 = GetModuleHandle(TEXT("kernel32.dll"));

            if (modKernel32 == 0) {
                MessageBox(HWND_DESKTOP, L"No handle found for kernel32.dll", L"Module handle not found", MB_OK);
            }
            else
            {
                true_Writefile = (True_WriteFile)GetProcAddress(modKernel32, "WriteFile");
            }

            if (true_Writefile == NULL) {
                MessageBox(HWND_DESKTOP, L"GetProcAddress Failed", L"GetProcAddress Failed, aborting detours", MB_OK);
            }
            else {

                DetourTransactionBegin();
                DetourUpdateThread(GetCurrentThread());
                DetourAttach(&(PVOID&)true_Writefile, HookedWriteFile);

                LONG lError = DetourTransactionCommit();
                if (lError != NO_ERROR) {
                    MessageBox(HWND_DESKTOP, L"Failed to detour", L"ATTACH FAILED", MB_OK);
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
                MessageBox(HWND_DESKTOP, L"Failed to detour", L"DETACH FAILED", MB_OK);
                return FALSE;
            }
        }
    break;
    }

    return TRUE;
}


