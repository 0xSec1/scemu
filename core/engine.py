from unicorn import *
from unicorn.x86_const import *
from core.disassemble import *

SHELLCODE_ADDRESS = 0x4000000
STACK = 0x1000000
STACK_SIZE = 0x100000 #1MB stack size
STACK_MID = STACK + (STACK_SIZE // 2)

class EmulationResult:
    def __init__(self, reason: str,
                 executedAddress: int, instructionCounter: int,
                 mnemonic: str | None, op_str: str | None,
                 accessType: int, failedAddress: int | None,
                 byteSize: int, eip: int, esp: int):
        self.reason = reason
        self.executedAddress = executedAddress
        self.instructionCounter = instructionCounter
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.accessType = accessType
        self.failedAddress = failedAddress
        self.byteSize = byteSize
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

    #hook each instruction and stores executing instruction address and increment counter
    def codeHook(self, uc, address, size, user_data):
        self.execAddress = address
        self.instructionCounter += 1

    #hook on invalid memory access(Read, Write, Fetch)
    def memInvalidHook(self, uc, access, address, size, value, user_data):
        if access == UC_MEM_READ_UNMAPPED:
            self.access = "read"
        elif access == UC_MEM_WRITE_UNMAPPED:
            self.access = "write"
        elif access == UC_MEM_FETCH_UNMAPPED:
            self.access = "fetch"
        else:
            self.access = "access"

        self.failedAddress = address
        self.size = size

        return False

    def runShellcode(self, shellcodeLength: int, maxInstruction: int = 0) -> EmulationResult:
        SHELLCODE_END_ADDRESS = SHELLCODE_ADDRESS + shellcodeLength

        self.instructionCounter = 0
        self.access = 0
        self.failedAddress = None
        self.size = 0

        try:
            self.mu.hook_add(UC_HOOK_CODE, callback=self.codeHook ,begin=SHELLCODE_ADDRESS, end=SHELLCODE_END_ADDRESS)
            self.mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, callback=self.memInvalidHook)
            self.mu.emu_start(SHELLCODE_ADDRESS, SHELLCODE_END_ADDRESS, count=maxInstruction)
            if maxInstruction:
                stopReason = "Instruction limit reached"
            else:
                stopReason = "End of shellcode"
        except UcError as e:
            stopReason = f"{e}"

        eip = self.mu.reg_read(UC_X86_REG_EIP)
        esp = self.mu.reg_read(UC_X86_REG_ESP)

        byteLength = min(15, self.mappedSize - (self.execAddress - SHELLCODE_ADDRESS)) #prevent from crossing page boundary
        executedBytes = self.mu.mem_read(self.execAddress, byteLength)
        disasmInstruction = disasm.disassemble(bytes(executedBytes), self.execAddress)

        return EmulationResult(
                reason=stopReason,
                executedAddress=self.execAddress,
                instructionCounter=self.instructionCounter,
                mnemonic=disasmInstruction[0],
                op_str=disasmInstruction[1],
                accessType=self.access,
                failedAddress=self.failedAddress,
                byteSize=self.size,
                eip=eip,
                esp=esp
        )
