import struct

#GDT entry constants
F_GRANULARITY = 0x8	# If set block=4KiB otherwise block=1B
F_PROT_32 = 0x4		# Protected Mode 32 bit
F_LONG = 0x2		# Long Mode
F_AVAILABLE = 0x1 	# Free Use
A_PRESENT = 0x80	# Segment active
A_PRIV_3 = 0x60		# Ring 3 Privs
A_PRIV_2 = 0x40		# Ring 2 Privs
A_PRIV_1 = 0x20		# Ring 1 Privs
A_PRIV_0 = 0x0		# Ring 0 Privs
A_CODE = 0x10		# Code Segment
A_DATA = 0x10		# Data Segment
A_TSS = 0x0		# TSS
A_GATE = 0x0		# GATE
A_EXEC = 0x8		# Executable
A_DATA_WRITABLE = 0x2
A_CODE_READABLE = 0x2
A_DIR_CON_BIT = 0x4
S_GDT = 0x0		# Index points to GDT
S_LDT = 0x4		# Index points to LDT
S_PRIV_3 = 0x3		# Ring 3 Privs
S_PRIV_2 = 0x2		# Ring 2 Privs
S_PRIV_1 = 0x1		# Ring 1 Privs
S_PRIV_0 = 0x0		# Ring 0 Privs

#segment register index
FS_INDEX = 0xe
GS_INDEX = 0xf
DS_INDEX = 0x10
CS_INDEX = 0x11
SS_INDEX = 0x12

def buildTEB(tebAddress: int, pebAddress: int, stackBase: int, stackLimit: int):
    '''builds TEB env and populates its information'''
    teb = bytearray(0x1000)

    teb[0x04:0x08] = struct.pack("<I", stackBase)
    teb[0x08:0x0C] = struct.pack("<I", stackLimit)
    teb[0x18:0x1C] = struct.pack("<I", tebAddress)
    teb[0x30:0x34] = struct.pack("<I", pebAddress)

    return bytes(teb)

def createGDTEntry(base: int, limit: int, access: int, flags:int):
    '''create GDT entry with required info'''
    #lower 32-bit
    entry = limit & 0xffff
    entry |= (base & 0xffffff) << 16

    #higher 32-bit
    entry |= (access & 0xff) << 40
    entry |= ((limit >> 16) & 0xf) << 48
    entry |= (flags & 0xff) << 52
    entry |= ((base >> 24) & 0xff) << 56
    return struct.pack("<Q", entry)

def createSelector(index: int, flags: int):
    selector = flags
    selector |= index << 3
    return selector

def gdtSetup(fsBase=None, fsLimit=None, gsBase=None, gsLimit=None, segmentLimit=0xffffffff):
    gdt_entries = [createGDTEntry(0,0,0,0) for i in range(31)]

    if fsBase != None and fsLimit != None:
        gdt_entries[FS_INDEX] = createGDTEntry(fsBase, fsLimit, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT, F_PROT_32)
    else:
        gdt_entries[FS_INDEX] = createGDTEntry(0, segmentLimit, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)

    if gsBase != None and gsLimit != None:
        gdt_entries[GS_INDEX] = createGDTEntry(gsBase, gsLimit, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)
    else:
        gdt_entries[GS_INDEX] = createGDTEntry(0, segmentLimit, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32)

    gdt_entries[DS_INDEX] = createGDTEntry(0, segmentLimit, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_3 | A_DIR_CON_BIT, F_PROT_32 | F_GRANULARITY)
    gdt_entries[CS_INDEX] = createGDTEntry(0, segmentLimit, A_PRESENT | A_CODE | A_CODE_READABLE | A_PRIV_3 | A_EXEC | A_DIR_CON_BIT, F_PROT_32 | F_GRANULARITY)
    gdt_entries[SS_INDEX] = createGDTEntry(0, segmentLimit, A_PRESENT | A_DATA | A_DATA_WRITABLE | A_PRIV_0 | A_DIR_CON_BIT, F_PROT_32 | F_GRANULARITY)

    fs_selector = createSelector(FS_INDEX, S_GDT | S_PRIV_0)
    gs_selector = createSelector(GS_INDEX, S_GDT | S_PRIV_3)
    ds_selector = createSelector(DS_INDEX, S_GDT | S_PRIV_3)
    cs_selector = createSelector(CS_INDEX, S_GDT | S_PRIV_3)
    ss_selector = createSelector(SS_INDEX, S_GDT | S_PRIV_0)

    return gdt_entries, fs_selector, gs_selector, ds_selector, cs_selector, ss_selector
