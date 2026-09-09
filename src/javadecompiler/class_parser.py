import struct
import zipfile

class ClassFileReader:
    def __init__(self, filePath : str = None ):
        if filePath is None:
            print("No file path provided.")
        with open(filePath, 'rb') as filePointer:
            self.fileData = filePointer.read()
        self.currentCursor = 0

    def readUnsignedByte(self) -> int:
        val = self.fileData[self.currentCursor]
        self.currentCursor += 1
        return val

    def readUnsignedShort(self) -> int:
        val = struct.unpack('>H', self.fileData, self.currentCursor)[0]
        self.currentCursor += 2
        return val

    def readUnsignedInt(self) -> int:
        val = struct.unpack('>I', self.fileData, self.currentCursor)[0]
        self.currentCursor += 4
        return val

    def readBytes(self, byteLength : int) -> bytes:
        val = self.fileData[self.currentCursor : self.currentCursor + byteLength]
        self.currentCursor += byteLength
        return val