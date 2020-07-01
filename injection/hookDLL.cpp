#include <windows.h>
#include <iostream>

#pragma comment(lib,"user32.lib")

typedef int (WINAPI *defTrampolineFunc)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
LPVOID trampoline_address; 

// The proxy function we will jump to after the hook has been installed
int __stdcall proxy_function(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    std::cout << "----------intercepted call to MessageBoxA----------\n";
    std::cout << "Text: " << (LPCSTR)lpText << "\nCaption: " << (LPCSTR)lpCaption << "\n";

    // pass to the trampoline with altered arguments which will then return to MessageBoxA
    defTrampolineFunc trampoline= (defTrampolineFunc)trampoline_address;
    return trampoline(hWnd, "hooked", "hooked", uType);
}

void install_hook()
{
    HINSTANCE hinstLib;
    VOID *proxy_address;
    DWORD *relative_offset;
    DWORD *hook_address;
    DWORD src; 
    DWORD dst;
    BYTE patch[5]= {0};
    BYTE saved_buffer[5]; // buffer to save the original bytes
    FARPROC function_address= NULL;

    // 1. get memory address of the MessageBoxA function from user32.dll 
    hinstLib= LoadLibraryA(_T("user32.dll"));
    function_address= GetProcAddress(hinstLib, _T("MessageBoxA"));

    // 2. save the first 5 bytes into saved_buffer
    ReadProcessMemory(GetCurrentProcess(), function_address, saved_buffer, 5, NULL);

    // 3. overwrite the first 5 bytes with a jump to proxy_function
    proxy_address= &proxy_function;
    src= (DWORD)function_address + 5; 
    dst= (DWORD)proxy_address;
    relative_offset= (DWORD *)(dst-src); 

    memcpy(patch, "\xE9", 1);
	memcpy(patch + 1, &relative_offset, 4);

    WriteProcessMemory(GetCurrentProcess(), (LPVOID)function_address, patch, 5, NULL);

    // 4. Build the trampoline
    trampoline_address= VirtualAlloc(NULL, 11, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    hook_address= (DWORD *)((DWORD)function_address + 5);
    memcpy((BYTE *)trampoline_address, &saved_buffer, 5);
    memcpy((BYTE *)trampoline_address + 5, "\x68", 1);
    memcpy((BYTE *)trampoline_address + 6, &hook_address, 4);
    memcpy((BYTE *)trampoline_address + 10, "\xC3", 1);
}

BOOL WINAPI DllMain (HINSTANCE const instance, DWORD const reason, LPVOID const reserved)  
{
    switch (reason)
    {
        case DLL_PROCESS_ATTACH:
            MessageBoxA(NULL, "process attached", "Monitor", MB_OK);
            MessageBoxA(NULL, "installing hook", "Monitor", MB_OK);
            install_hook();
            break;

        case DLL_THREAD_ATTACH:
        case DLL_PROCESS_DETACH:
        case DLL_THREAD_DETACH:
            break;
    }

    return TRUE;  
}

