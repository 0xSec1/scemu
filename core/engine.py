from unicorn import *
from unicorn.x86_const import *

SHELLCODE_ADDRESS = 0x4000000

class Emulator:
    def __init__(self):
        '''initializes unicorn engine in x86 32bit mode'''
        self.mu = Uc(UC_ARCH_X86, UC_MODE_32)
        self.mappedSize = 0

    def mapMemory(self, size: int):
        self.mappedSize = (size + 4095) & ~4095
        try:
            self.mu.mem_map(SHELLCODE_ADDRESS, self.mappedSize, UC_PROT_ALL)
        except UcError as e:
            print(f"ERROR: {e}")

    def memWrite(self, shellcodeBytes: bytes):
        self.mu.mem_write(SHELLCODE_ADDRESS, shellcodeBytes)

    def memRead(self, length: int) -> bytearray:
       return self.mu.mem_read(SHELLCODE_ADDRESS, length)
