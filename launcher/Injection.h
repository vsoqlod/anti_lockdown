#pragma once
#include <windows.h>
#include <string>
#include <iostream>
#include <thread>
#include <vector>


LPVOID write_into_process(HANDLE hProcess, LPBYTE buffer, SIZE_T buffer_size, DWORD protect);
bool inject(HANDLE hProcess, const wchar_t* inject_path);
HANDLE open_process(DWORD pid);
HANDLE create_new_process(IN std::wstring exe_path, IN std::wstring cmd, OUT PROCESS_INFORMATION& pi, DWORD flags);
bool inject_into_process(DWORD pid, const wchar_t* inject_path);
