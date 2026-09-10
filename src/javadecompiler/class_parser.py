import struct
import zipfile
import os
from typing import Dict, Any

class ClassFileReader:
    def __init__(self, filePath : str) -> None:

        if not os.path.isfile(filePath):
            raise FileNotFoundError(f"File not found: {filePath}")
        try:
            with open(filePath, 'rb') as filePointer:
                self.fileData: bytes = filePointer.read()
        except IOError as e:
            raise IOError(f"Error reading file {filePath}: {e}")

        self.currentCursor: int = 0
        self.fileLength: int = len(self.fileData)


    def readUnsignedByte(self) -> int:
        if self.currentCursor >= self.fileLength:
            raise EOFError("Reached end of file while trying to read an unsigned byte.")
        
        val: int = self.fileData[self.currentCursor]
        self.currentCursor += 1
        return val

    def readUnsignedShort(self) -> int:
        try:
            val = struct.unpack('>H', self.fileData, self.currentCursor)[0]
            self.currentCursor += 2
            return val
        except struct.error as e:
            raise ValueError(f"Error reading unsigned short at position {self.currentCursor}: {e}")

    def readUnsignedInt(self) -> int:
        try:
            val = struct.unpack('>I', self.fileData, self.currentCursor)[0]
            self.currentCursor += 4
            return val
        except struct.error as e:
            raise ValueError(f"Error reading unsigned int at position {self.currentCursor}: {e}")

    def readBytes(self, byteLength : int) -> bytes:
        if self.currentCursor + byteLength > self.fileLength:
            raise EOFError("Reached end of file while trying to read bytes.")

        val: bytes = self.fileData[self.currentCursor:self.currentCursor + byteLength]
        self.currentCursor += byteLength
        return val

def parseClassHeader(classReader: ClassFileReader) -> int:
    magicNumber: int = classReader.readUnsignedInt()
    if magicNumber != 0xCAFEBABE:
        raise ValueError(f"Invalid class file: Expected magic number 0xCAFEBABE, found {hex(magicNumber)}")

    minorVersion: int = classReader.readUnsignedShort()
    majorVersion: int = classReader.readUnsignedShort()

    constantPoolCount: int = classReader.readUnsignedShort()

    print(f"Validated class file with magic number: {hex(magicNumber)}")
    print(f"Class file version: {majorVersion}.{minorVersion}, Constant Pool Count: {constantPoolCount - 1}")

    return constantPoolCount
