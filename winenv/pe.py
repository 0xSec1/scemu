import struct

def buildPEHeader(baseAddress: int, moduleSize: int):
    '''builds minimal PE header for modules'''
    #-----DOS HEADER(64 bytes)----
    dosHeader = bytearray(0x40)
    dosHeader[0x0:0x2] = b'MZ'  #e_magic
    e_lfanew = 0x80
    struct.pack_into("<I", dosHeader, 0x3c, e_lfanew) #pe header start at 0x80

    #----PE HEADER---
    peHeader = bytearray()
    peHeader[0x0:0x4] = b'PE\0\0' #signature

    #COFF header format
    peHeader += struct.pack("<HHIIIHH",
                           0x14c,   #machine arcitecture i386
                           0,       #NumberOfSections
                           0,       #TimeDateStamp
                           0,       #PointerToSymbolTable
                           0,       #NumberOfSymbols
                           0xE0,    #SizeOfOptionalHeader(0xe0)
                           0x102)   #Characteristics(IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE)
    #Optional header format
    optionalHeader = bytearray(0xE0)
    struct.pack_into("<H", optionalHeader, 0x0, 0x10b)          #magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC
    struct.pack_into("<I", optionalHeader, 0x1C, baseAddress)   #ImageBase = baseAddress
    struct.pack_into("<I", optionalHeader, 0x38, moduleSize)    #SizeOfImage = moduleSize
    struct.pack_into("<I", optionalHeader, 0x5C, 16)            #NumberOfRvaAndSizes = 16 data directory entries
    struct.pack_into("<II", optionalHeader, 0x60, 0, 0)         #DataDirectory[0]->EXPORT TABLE

    peHeader += optionalHeader

    image = bytearray(e_lfanew + len(peHeader))
    image[0:0x40] = dosHeader
    image[e_lfanew:] = peHeader

    return bytes(image)
