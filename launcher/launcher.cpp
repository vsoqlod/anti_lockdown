#include "Injection.h"

int main()
{
    AllocConsole();

    // Redirect standard input/output to the new console
    freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
    freopen_s((FILE**)stdin, "CONIN$", "r", stdin);


    std::wstring hookDll = L"DLL.dll";
    std::wstring targetExe = L"C:\\Program Files (x86)\\Respondus\\LockDown Browser\\LockDownBrowser.exe";
    std::wstring commandLine = L"cmd";
    
    
    bool iscreated = false;

    HANDLE hProcess = NULL;
    PROCESS_INFORMATION pi = { 0 };

    hProcess = create_new_process(targetExe, commandLine, pi, CREATE_SUSPENDED | CREATE_NEW_CONSOLE);
    if (!hProcess) {
        std::cerr << "Failed to create the process\n";
        return -1;
    }
    std::cout << "[!] Process created in suspended mode\n";

    iscreated = true;
    //store the process id
    DWORD pid = pi.dwProcessId;
    //stpre tje thread   
    HANDLE hThread = pi.hThread;

    // Console handling thread
    std::thread consoleThread([]() {
        std::string cmd;
        while (true) {
            std::cin >> cmd;
            if (cmd == "exit") {
                PostQuitMessage(0);
                break;
            }
        }
    });

    // Inject the DLL
    if (!inject_into_process(pid, hookDll.c_str())) {
		std::cerr << "Failed to inject the DLL\n";
		return -1;
	}   
    else if (iscreated) {
        ResumeThread(hThread);
    }

    std::cout << "   SSS   AA  DDD      RRRR  EEEE  SSS  PPPP   OOO  N   N DDD  U   U  SSS          (( " << std::endl;
    std::cout << "  S     A  A D  D     R   R E    S     P   P O   O NN  N D  D U   U S         :: ((  " << std::endl;
    std::cout << "   SSS  AAAA D  D     RRRR  EEE   SSS  PPPP  O   O N N N D  D U   U  SSS         ((  " << std::endl;
    std::cout << "      S A  A D  D     R R   E        S P     O   O N  NN D  D U   U     S     :: ((  " << std::endl;
    std::cout << "  SSSS  A  A DDD      R  RR EEEE SSSS  P      OOO  N   N DDD   UUU  SSSS          (( " << std::endl;

    consoleThread.join(); // Wait for the console thread to finish

    FreeConsole(); // Free the console

    return 0;
}
