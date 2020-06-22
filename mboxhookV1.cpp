/*
** Simple MessageBoxA hook using the classic 5 byte relative jump technique without a trampoline.
** Instead of bypassing the hook in the proxy function when passing execution to MessageBoxA, we 
** will simply re-write the original bytes, unhooking the function.
*/

#include <iostream>
#include <Windows.h>

#pragma comment(lib,"user32.lib")

char saved_buffer[5]; // buffer to save the original bytes
FARPROC hooked_address= NULL; 

// The proxy function we will jump to after the hook has been installed
int __stdcall proxy_function(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
    std::cout << "Hello from MessageBox!\n";
    std::cout << "Text: " << (LPCSTR)lpText << "\nCaption: " << (LPCSTR)lpCaption << std::endl;

    // unhook the function (re-write the saved buffer) to prevent infinite recursion
    WriteProcessMemory(GetCurrentProcess(), (LPVOID)hooked_address, saved_buffer, 5, NULL);

    // return to the original function, which is now unhooked, and modify the intended parameters
    return MessageBoxA(NULL, "yeet", "yeet", uType);
}

void install_hook()
{
    HINSTANCE hinstLib;
    VOID *proxy_address;
    DWORD *relative_offset;
    DWORD src; 
    DWORD dst;
    CHAR patch[5]= {0};

    // 1. get memory address of the MessageBoxA function from user32.dll 
    hinstLib= LoadLibraryA(TEXT("user32.dll"));
    hooked_address= GetProcAddress(hinstLib, "MessageBoxA");

    // 2. save the first 5 bytes into saved_buffer
    ReadProcessMemory(GetCurrentProcess(), hooked_address, saved_buffer, 5, NULL);

    // 3. overwrite the first 5 bytes with a jump to proxy_function
    proxy_address= &proxy_function;
    src= (DWORD)hooked_address + 5; // will jump from the next instruction (after our 5 byte jmp instruction)
    dst= (DWORD)proxy_address;
    relative_offset= (DWORD *)(dst-src); 

    memcpy(patch, "\xE9", 1);
	memcpy(patch + 1, &relative_offset, 4);

    WriteProcessMemory(GetCurrentProcess(), (LPVOID)hooked_address, patch, 5, NULL);
}

int main()
{   
    // call without hook
    MessageBoxA(NULL, "hello", "hello", MB_OK);

    // call with hook (arguments will be altered through the proxy function)
    install_hook();
    MessageBoxA(NULL, "hello", "hello", MB_OK);

    return 0;
}
