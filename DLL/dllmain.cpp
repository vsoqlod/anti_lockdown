//this file contains the hooks and the logic for the hooks. it also contains the logic for the registry key setting and the window resizing. this is the primary file for DLL creation.

#include "stdafx.h"
#include "structs.h"
#include <thread>
#include <iostream>


int width = 800, height = 600;
tTerminateProcess ogTerminateProcess;
tGetForegroundWindow ogGetForegroundWindow;
PNT_QUERY_SYSTEM_INFORMATION ogNtQuerySystemInformation;
tEnumWindows originalEnumWindows = nullptr;
tGetDesktopWindow originalGetDesktopWindow = nullptr;


HWND g_hMainWnd;
BOOL firstTimeuWu = TRUE;




// registry key set
bool SetRegistryKeyDword(HKEY hKey, LPCSTR subKey, LPCSTR valueName, DWORD value) {
	HKEY hSubKey;
	LONG lResult;

	// Open the specified key
	lResult = RegOpenKeyExA(hKey, subKey, 0, KEY_WRITE, &hSubKey);
	if (lResult != ERROR_SUCCESS) {
		std::cerr << "[!] Error opening key: " << lResult << '\n';
		return false;
	}

	// Set the value
	lResult = RegSetValueExA(hSubKey, valueName, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(value));
	if (lResult != ERROR_SUCCESS)
	{
		std::cerr << "[!] Error setting key value: " << lResult << '\n';
		// It's important to close the opened key even when an error occurs
		RegCloseKey(hSubKey);
		return false;
	}

	// Close the key
	lResult = RegCloseKey(hSubKey);
	if (lResult != ERROR_SUCCESS) {
		std::cerr << "[!] Error closing key: " << lResult << '\n';
		return false;
	}

	return true;
}

// just a wrapper for ease
BOOL SetWindowSize(HWND hWnd, int width, int height)
{
	// The parameters for SetWindowPos are as follows:
	// hWnd: Handle to the window
	// hWndInsertAfter: A handle to the window to precede the positioned window in the Z order
	//                  (use one of the special values, e.g., HWND_TOP)
	// X: New position of the left side of the window
	// Y: New position of the top of the window
	// cx: New width of the window
	// cy: New height of the window
	// uFlags: Window sizing and positioning flags

	return SetWindowPos(hWnd, HWND_TOP, 0, 0, width, height, SWP_NOMOVE | SWP_NOZORDER);
}


// get foregroudnwindow but we only return the pseudo handle of the browser
HWND WINAPI hkGetForegroundWindow()
{
	g_hMainWnd = FindWindowA("CEFCLIENT", NULL);
	return g_hMainWnd;
}

// fix the taskbar
BOOL FixTaskBar()
{
	HWND shell_wnd = FindWindow(L"Shell_TrayWnd", NULL);
	if (!shell_wnd)
		return FALSE;
	ShowWindow(shell_wnd, SW_SHOW);
	printf("[+] Fixed taskbar \n");
	return TRUE;
}

HWND WINAPI hkGetDesktopWindow()
{
	printf("[*] Lockdown Browser is attempting to take a screenshot\n");
	printf("[!] Call to GetDesktopWindow() by RESPONDUS: Preventing Screenshot\n");
	//list the sub calls this hwnd may be used for to take a screenshot and tab them out in the print statement
	printf("[!] Sub calls: \n");
	printf("\t[!] GetWindowRect()\n");
	printf("\t[!] GetDC()\n");
	printf("\t[!] BitBlt()\n");
	return g_hMainWnd;
}

BOOL WINAPI hkTerminateProcess(HANDLE hProcess, UINT uExitCode)
{
	// the logic behind this is we are waiting for the application to start the hooking. I found that once it starts killing processes, the hooks are set. 
	// this could be set to any other logic, we just use a flag.
	if (firstTimeuWu)
	{
		AllocConsole();
		FILE* f;
		freopen_s(&f, "CONOUT$", "w", stdout);

		printf("[~] hi\n");
		SetRegistryKeyDword(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "DisableTaskMgr", 0x0);
		printf("[+] unset key: DisableTaskMgr\n");
		SetRegistryKeyDword(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "NoChangeStartMenu", 0x0);
		printf("[+] unset key: NoChangeStartMenu\n");
		SetRegistryKeyDword(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "NoClose", 0x0);
		printf("[+] unset key: NoClose\n");
		SetRegistryKeyDword(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", "NoLogOff", 0x0);
		printf("[+] unset key: NoLogOff\n");
		printf("[+] registry keys reset\n");

		//MessageBoxA(NULL, "ew spyware", "ew", MB_OK);
		FixTaskBar();
		HWND tstWindow = FindWindowA("CEFCLIENT", NULL);
		SetWindowSize(tstWindow, width, height);
		HWND canvasWindow = FindWindowA("LOCKDOWNCHROME", NULL);
		SetWindowSize(canvasWindow, width, height);
		HWND coverWindow = FindWindowA("Respondus LockDown Browser CW", NULL);
		SetWindowSize(coverWindow, 200, 200);
		printf("[+] Windows fixed\n");
		MessageBoxA(NULL, "much better", "whew", MB_OK);
		firstTimeuWu = FALSE;
		printf("[+] First time flag set to false\n");
		printf("[!] Task Killing Beginnning: \n");

	}
	printf("[*] Im a naughty boy and I tried to kill: %p\n", (VOID*)hProcess);
	// Print the module name

	return TRUE;
}

NTSTATUS WINAPI HookedNtQuerySystemInformation(
	__in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout    PVOID                    SystemInformation,
	__in       ULONG                    SystemInformationLength,
	__out_opt  PULONG                   ReturnLength
)
{
	NTSTATUS status = ogNtQuerySystemInformation(SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength);
	if (SystemProcessInformation == SystemInformationClass && STATUS_SUCCESS == status)
	{
		// Loop through the list of processes
		PMY_SYSTEM_PROCESS_INFORMATION pCurrent = NULL;
		PMY_SYSTEM_PROCESS_INFORMATION pNext = (PMY_SYSTEM_PROCESS_INFORMATION)
			SystemInformation;

		do
		{
			// remove the current entry
			pCurrent = pNext;
			pNext = (PMY_SYSTEM_PROCESS_INFORMATION)((PUCHAR)pCurrent + pCurrent->
				NextEntryOffset);

			if (!pNext->NextEntryOffset)
			{
				pCurrent->NextEntryOffset = 0;
			}
			else
			{
				pCurrent->NextEntryOffset += pNext->NextEntryOffset;
			}
			pNext = pCurrent;

		} while (pCurrent->NextEntryOffset != 0 && !firstTimeuWu);
	}
	return status;
}

HDC WINAPI hkCreateCompatibleDC(HDC hdc)
{
	return hdc;
}


DWORD WINAPI HackThread(HMODULE hModule)
{
	// Console handling thread


	ogNtQuerySystemInformation = (PNT_QUERY_SYSTEM_INFORMATION)GetProcAddress(GetModuleHandle(L"ntdll"), "NtQuerySystemInformation");
	ogNtQuerySystemInformation = (PNT_QUERY_SYSTEM_INFORMATION)mem::TrampHook32((BYTE*)ogNtQuerySystemInformation, (BYTE*)HookedNtQuerySystemInformation, 5);

	ogGetForegroundWindow = (tGetForegroundWindow)GetProcAddress(GetModuleHandle(L"user32.dll"), "GetForegroundWindow");
	ogGetForegroundWindow = (tGetForegroundWindow)mem::TrampHook32((BYTE*)ogGetForegroundWindow, (BYTE*)hkGetForegroundWindow, 5);

	ogTerminateProcess = (tTerminateProcess)GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "TerminateProcess");
	ogTerminateProcess = (tTerminateProcess)mem::TrampHook32((BYTE*)ogTerminateProcess, (BYTE*)hkTerminateProcess, 5);

	originalGetDesktopWindow = (tGetDesktopWindow)GetProcAddress(GetModuleHandle(L"user32.dll"), "GetDesktopWindow");
	originalGetDesktopWindow = (tGetDesktopWindow)mem::TrampHook32((BYTE*)originalGetDesktopWindow, (BYTE*)hkGetDesktopWindow, 5);

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CloseHandle(CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)HackThread, hModule, 0, nullptr));
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
