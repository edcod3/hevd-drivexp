#include <Windows.h>
#include <stdio.h>
/*
Get the addresses of the function addresses to be used 
for our shellcode 
*/

int main()
{
    HMODULE hModule = LoadLibraryA((LPCSTR) "kernel32.dll");

    FARPROC func = GetProcAddress(hModule, "LoadLibraryA");
    FARPROC func2 = GetProcAddress(hModule, "GetProcAddress");
    FARPROC func3 = GetProcAddress(hModule, "ExitProcess");

    printf("LoadLibraryA   0x%08x\n", (unsigned int)func);
    printf("GetProcAddress 0x%08x\n", (unsigned int)func2);
    printf("ExitProcess    0x%08x\n", (unsigned int)func3);

    FreeLibrary(hModule);
}