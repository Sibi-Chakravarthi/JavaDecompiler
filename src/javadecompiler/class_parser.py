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

def parseConstantPool(classReader: ClassFileReader, poolCount: int) -> Dict[int, Any]:
    constantPool: Dict[int, Any] = {}
    currentIndex: int = 1

    tagUtf8: int = 1
    tagInteger: int = 3
    tagFloat: int = 4
    tagLong: int = 5
    tagDouble: int = 6
    tagClass: int = 7
    tagString: int = 8
    tagFieldRef: int = 9
    tagMethodRef: int = 10 
    tagInterfaceMethodRef: int = 11 
    tagNameAndType: int = 12
    tagMethodHandle: int = 15
    tagMethodType: int = 16 
    tagInvokeDynamic: int = 18

    while currentIndex < poolCount:
        currentTag: int = classReader.readUnsignedByte()

        if currentTag == tagUtf8:
            byteLength: int = classReader.readUnsignedShort()
            utf8Bytes: bytes = classReader.readRawBytes(byteLength)
            constantPool[currentIndex] = {"type": "Utf8", "value":utf8Bytes.decode('utf-8', errors='replace')}

        elif currentTag == tagClass:
            nameIndex: int = classReader.readUnsignedShort()
            constantPool[currentIndex] = {"type":"Class", "nameIndex": nameIndex}

        elif currentTag in (tagFieldRef, tagMethodRef, tagInterfaceMethodRef):
            classIndex: int = classReader.readUnsignedShort()
            nameAndTypeIndex: int = classReader.readUnsignedShort()
            constantPool[currentIndex] = {
                "type": "Ref",
                "classIndex": classIndex,
                "nameAndTypeIndex": nameAndTypeIndex
            }

        elif currentTag == tagString:
            stringIndex: int = classReader.readUnsignedShort()
            constantPool[currentIndex] = {"type": "String", "stringIndex": stringIndex}

        elif currentTag == tagNameAndType:
            nameIndex: int = classReader.readUnsignedShort()
            descriptorIndex: int = classReader.readUnsignedShort()
            constantPool[currentIndex] = {
                "type": "NameAndType",
                "nameIndex": nameIndex,
                "descriptorIndex": descriptorIndex
            }

        elif currentTag in (tagInteger, tagFloat):
            primitiveValue: int = classReader.readUnsignedInt()
            constantPool[currentIndex] = {"type": "Primitive32", "value": primitiveValue}

        elif currentTag in (tagLong, tagDouble):
            highBytes: int = classReader.readUnsignedInt()
            lowBytes: int = classReader.readUnsignedInt()
            constantPool[currentIndex] = {"type": "Primitive64", "high": highBytes, "low": lowBytes}

            currentIndex += 1 

        elif currentTag == tagMethodHandle:
            classReader.readUnsignedByte()
            classReader.readUnsignedShort()
            constantPool[currentIndex] = {"type": "MethodHandle"}

        elif currentTag == tagMethodType:
            classReader.readUnsignedShort()
            constantPool[currentIndex] = {"type": "MethodType"}

        elif currentTag == tagInvokeDynamic:
            classReader.readUnsignedShort()
            classReader.readUnsignedShort()
            constantPool[currentIndex] = {"type": "InvokeDynamic"}

        else:
            raise NotImplementedError(f"Unsupported Constant Pool Tag '{currentTag}' encountered at index {currentIndex}.")

        currentIndex += 1

    return constantPool

def extractAndParseJar(jarFilePath: str, targetClassFile: str) -> Dict[int, Dict[str, Any]]:
    if not os.path.isfile(jarFilePath):
        raise FileNotFoundError(f"JAR file not found: {jarFilePath}")

    extractPath: str = "extractedClasses"
    os.makedirs(extractPath, exist_ok=True)

    try:
        with zipfile.ZipFile(jarFilePath, "r") as jarArchive:
            jarArchive.extract(targetClassFile ,path=extractPath)

    except zipfile.BadZipFile:
        raise ValueError(f"The file {jarFilePath} is not a valid JAR/ZIP file")
    except KeyError:
        raise KeyError(f"The class file {targetClassFile} was not found in the JAR archive {jarFilePath}")

    extractedFilePath: str = os.path.join(extractPath, targetClassFile)

    try:
        classReader: ClassFileReader = ClassFileReader(extractedFilePath)
        poolCount: int = parseClassHeader(classReader)
        constantPoolDict: Dict[int, Dict[str, Any]] = parseConstantPool(classReader, poolCount)
        return constantPoolDict
    finally:
        if os.path.exists(extractedFilePath):
            os.remove(extractedFilePath)