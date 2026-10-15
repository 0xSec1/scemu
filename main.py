#!/usr/bin/env python3
import argparse
from core.cli import validateFile
from core.engine import *
from core.loader import FileMetadata

if __name__ == '__main__':

    #CLI arguments parsing
    parser = argparse.ArgumentParser(description="Shellcode Emulator", suggest_on_error=True)
    parser.add_argument("filename", help="Process filename", type=validateFile)

    args = parser.parse_args()

    fileInformation = FileMetadata(args.filename)
    print(fileInformation)

    #emulator setup
    emu = Emulator()
    emu.mapMemory(fileInformation.fileSize)
    emu.memWrite(fileInformation.rawBytes)
    readBytes = emu.memRead(fileInformation.fileSize)

    if readBytes == fileInformation.rawBytes:
        print(f"Mapped {fileInformation.fileSize} bytes at {hex(SHELLCODE_ADDRESS)} ({emu.mappedSize} byte region)")
        print("----- Original bytes -----")
        print(fileInformation.rawBytes)
        print("----- Read from mapped region -----")
        print(bytes(readBytes))
    else:
        print("ERROR: Read-back bytes does not match original file")
