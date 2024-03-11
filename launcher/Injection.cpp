//this file is used to inject the dll into the target process
// ref: https://github.com/hasherezade/dll_injector

#include "Injection.h"


//write the buffer into the process
LPVOID write_into_process(HANDLE hProcess, LPBYTE buffer, SIZE_T buffer_size, DWORD protect)
{
	LPVOID remote_buffer = VirtualAllocEx(hProcess, NULL, buffer_size, MEM_COMMIT | MEM_RESERVE, protect);
	if (remote_buffer == NULL)
	{
		std::cerr << "VirtualAllocEx failed: " << GetLastError() << std::endl;
		return NULL;
	}
	printf("[i] pAddress Allocated At : 0x%p Of Size : %d\n", remote_buffer, buffer_size);

	SIZE_T bytes_written;
	if (!WriteProcessMemory(hProcess, remote_buffer, buffer, buffer_size, &bytes_written))
	{
		std::cerr << "WriteProcessMemory failed: " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, remote_buffer, 0, MEM_FREE);
		return NULL;
	}

	printf("[i] Successfully Written %d Bytes\n", bytes_written);

	return remote_buffer;
}

//inject the dll into the process
bool inject(HANDLE hProcess, const wchar_t* inject_path)
{
	if (!inject_path) {
		return false;
	}
	HMODULE hModule = GetModuleHandleW(L"kernel32.dll");
	if (!hModule) return false;

	FARPROC hLoadLib = GetProcAddress(hModule, "LoadLibraryW");
	if (!hLoadLib) return false;

	//calculate size along with the terminating '\0'
	SIZE_T inject_path_size = (wcslen(inject_path) + 1) * sizeof(inject_path[0]);

	LPVOID remote_buffer = write_into_process(hProcess, (LPBYTE)inject_path, inject_path_size, PAGE_READWRITE);
	if (!remote_buffer) return false;
	std::cout << "Remote buffer: " << remote_buffer << std::endl;

	DWORD ret = WAIT_FAILED;
	std::cout << "[*] Creating remote thread\n";
	HANDLE hndl = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)hLoadLib, remote_buffer, NULL, NULL);
	if (hndl) {
		std::cout << "[*] Waiting for remote thread\n";
		ret = WaitForSingleObject(hndl, 100000);
		std::cout << "[*] Remote thread finished\n";
		CloseHandle(hndl); hndl = NULL;
	}
	else {
		std::cout << "Creating thread failed!\n";
	}
	// cleanup:
	VirtualFreeEx(hProcess, remote_buffer, 0, MEM_RELEASE);
	if (ret == WAIT_OBJECT_0) {
		return true;
	}
	return false;
}

//open the process
HANDLE open_process(DWORD pid)
{
	HANDLE hProcess = OpenProcess(
		PROCESS_CREATE_THREAD | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
		FALSE,
		pid
	);
	if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
		const DWORD err = GetLastError();
		if (err == ERROR_INVALID_PARAMETER) {
			std::cerr << "[ERROR] [" << std::dec << pid << "] Opening the process failed. Is the process still running?" << std::endl;
			return NULL;
		}
		std::cerr << "[ERROR] [" << std::dec << pid << "] Opening the process failed: " << std::hex << "0x" << err << std::endl;
		return NULL;
	}
	return hProcess;
}

//create a new process and return the handle
HANDLE create_new_process(IN std::wstring exe_path, IN  std::wstring cmd, OUT PROCESS_INFORMATION& pi, DWORD flags)
{
	std::wstring full_cmd = std::wstring(exe_path) + L" " + std::wstring(cmd);

	const size_t buf_len = (full_cmd.length() + 1) * sizeof(wchar_t);
	wchar_t* cmd_str = new wchar_t[buf_len];
	if (cmd_str) {
		memset(cmd_str, 0, buf_len);
		memcpy(cmd_str, full_cmd.c_str(), buf_len);
	}

	STARTUPINFOW si = { 0 };
	si.cb = sizeof(STARTUPINFOW);
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;

	HANDLE pHndl = NULL;
	memset(&pi, 0, sizeof(PROCESS_INFORMATION));
	if (CreateProcessW(
		exe_path.c_str(),
		cmd_str,
		NULL, //lpProcessAttributes
		NULL, //lpThreadAttributes
		FALSE, //bInheritHandles
		flags, //dwCreationFlags
		NULL, //lpEnvironment 
		NULL, //lpCurrentDirectory
		&si, //lpStartupInfo
		&pi //lpProcessInformation
	))
	{
		pHndl = pi.hProcess;
	}
	else {
		std::cerr << "CreateProcess failed: " << GetLastError() << std::endl;
	}

	delete[]cmd_str;
	return pHndl;
}

bool inject_into_process(DWORD pid, const wchar_t* inject_path)
{
	HANDLE hProcess = open_process(pid);
	std::cout << "[*] Process handle: " << hProcess << std::endl;
	std::cout << "[*] Process ID: " << pid << std::endl;
	std::cout << "[*] Injecting: " << inject_path << std::endl;
	if (!hProcess) {
		std::cerr << "Failed to open the process\n";
		return false;
	}
	bool ret = inject(hProcess, inject_path);
	CloseHandle(hProcess);
	return ret;
}