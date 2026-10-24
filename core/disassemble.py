from capstone import *

class Disassemble:
    def __init__(self):
        self.md = Cs(CS_ARCH_X86, CS_MODE_32)

    def disassemble(self, shellcodeBytes: bytes, address: int):
        '''takes shellcode bytes and address returning mnemonic and operand string'''
        instruction = list(self.md.disasm(shellcodeBytes, address))

        if not instruction:
            print("ERROR: instruction cannot be disassembled")
            return None, None

        i = instruction[0]
        return i.mnemonic, i.op_str

#creating object only once
disasm = Disassemble()
