#!/usr/bin/env python3

#Disassembly of shellcode: objdump -d <file>

import sys

"""
Convert raw shellcode object to c array 
"""
def main(filename: str):
    with open(filename, "rb") as f:
        file_bytes = f.read()
        #print(file_bytes)
        shellcode = file_bytes.split(b"\x10B")[1].split(b"\x04\x00")[0]
        print(shellcode)
        hex_bytes = ["0x%02x" % char for char in shellcode]
        hex_bytes = ", ".join(hex_bytes)
        c_array = "char shellcode[] = {"+hex_bytes+"};"
        print(c_array)

if __name__ == "__main__":
    main(sys.argv[1])