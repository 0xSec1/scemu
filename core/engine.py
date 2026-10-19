from unicorn import *
from unicorn.x86_const import *

SHELLCODE_ADDRESS = 0x4000000
STACK = 0x1000000
STACK_SIZE = 0x100000 #1MB stack size
STACK_MID = STACK + (STACK_SIZE // 2)

class EmulationResult:
    def __init__(self, reason: str, eip: int, esp: int):
        self.reason = reason
        self.eip = eip
        self.esp = esp

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

    def mapStack(self):
        '''maps stack region and sets ESP and EBP at middle of stack'''
        try:
            self.mu.mem_map(STACK, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
            self.mu.reg_write(UC_X86_REG_ESP, STACK_MID)
            self.mu.reg_write(UC_X86_REG_EBP, STACK_MID)
        except UcError as e:
            print(f"ERROR: {e}")

    def memWrite(self, shellcodeBytes: bytes):
        self.mu.mem_write(SHELLCODE_ADDRESS, shellcodeBytes)

    def memRead(self, length: int) -> bytearray:
       return self.mu.mem_read(SHELLCODE_ADDRESS, length)

    def runShellcode(self, maxInstruction: int = 0) -> EmulationResult:
        try:
            self.mu.emu_start(SHELLCODE_ADDRESS, 0, count=maxInstruction)
            stopReason = "Instruction limit reached"
        except UcError as e:
            stopReason = f"{e}"

        eip = self.mu.reg_read(UC_X86_REG_EIP)
        esp = self.mu.reg_read(UC_X86_REG_ESP)

        return EmulationResult(reason=stopReason, eip=eip, esp=esp)
