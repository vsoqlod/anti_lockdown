// Content: structs for the DLL

#pragma once
#include <iostream>
#include <Psapi.h>
#include "mem.h"
#include <windows.h>
#include <winternl.h>
#include <TlHelp32.h>

// Define a success status code for NTSTATUS
#define STATUS_SUCCESS  ((NTSTATUS)0x00000000L)



// Structure to hold process information, extending the SYSTEM_PROCESS_INFORMATION structure
typedef struct _MY_SYSTEM_PROCESS_INFORMATION
{
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	ULONG                   BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
} MY_SYSTEM_PROCESS_INFORMATION, * PMY_SYSTEM_PROCESS_INFORMATION;


// Function pointer types for various Windows API functions
typedef NTSTATUS(WINAPI* PNT_QUERY_SYSTEM_INFORMATION)(
	__in       SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__inout    PVOID SystemInformation,
	__in       ULONG SystemInformationLength,
	__out_opt  PULONG ReturnLength
	);

typedef HWND(WINAPI* tGetForegroundWindow)();
typedef BOOL(WINAPI* tTerminateProcess)(HANDLE hProcess, UINT uExitCode);
typedef BOOL(WINAPI* tEnumWindows)(WNDENUMPROC lpEnumFunc, LPARAM lParam);

typedef HWND(WINAPI* tGetDesktopWindow)();