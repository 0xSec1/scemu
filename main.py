#!/usr/bin/env python3
import argparse
from core.cli import validateFile
from core.engine import *
from core.loader import FileMetadata

if __name__ == '__main__':

    #CLI arguments parsing
    parser = argparse.ArgumentParser(description="Shellcode Emulator", suggest_on_error=True)
    parser.add_argument("filename", help="Process filename", type=validateFile)
    parser.add_argument("--max-instruction", help="Shellcode max instruction execution", type=int, default=0)
    parser.add_argument("--verbose", help="Verbose output", action="store_true")

    args = parser.parse_args()

    fileInformation = FileMetadata(args.filename)
    print(fileInformation)

    #emulator setup
    emu = Emulator()
    emu.mapShellcodeMemory(fileInformation.fileSize)
    emu.memWriteShellcode(fileInformation.rawBytes)
    readBytes = emu.memReadShellcode(fileInformation.fileSize)

    if readBytes == fileInformation.rawBytes:
        print(f"Mapped {fileInformation.fileSize} bytes at {hex(SHELLCODE_ADDRESS)} ({emu.mappedSize} byte region)")
        if args.verbose:
            print("----- Original bytes -----")
            print(fileInformation.rawBytes)
            print("----- Read from mapped region -----")
            print(bytes(readBytes))

        #maps stack, winenv and execute shellcode
        emu.mapStack()
        emu.mapWindowsEnv()
        result = emu.runShellcode(fileInformation.fileSize, maxInstruction=args.max_instruction)
        output = f"Stopped: {result.reason} at instruction: {result.mnemonic} {result.op_str} at {hex(result.executedAddress)}"
        if result.failedAddress is not None:
            output += f" (tried to {result.accessType} {result.byteSize} bytes at {hex(result.failedAddress)})"
        print(output)
    else:
        print("ERROR: Read-back bytes does not match original file")
