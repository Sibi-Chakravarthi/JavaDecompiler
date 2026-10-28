import struct
import zipfile
import os
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple

@dataclass
class MethodInfo:
    name: str
    descriptor: str
    access_flags: int
    bytecode: bytes
    is_static: bool = False
    param_types: List[str] = field(default_factory=list)
    return_type: str = "void"
    exception_handlers: List[Dict[str, int]] = field(default_factory=list)

@dataclass
class ClassInfo:
    class_name: str
    super_class: str
    interfaces: List[str]
    major_version: int
    minor_version: int
    constant_pool: Dict[int, Any]
    methods: Dict[str, MethodInfo]
    fields: List[Dict[str, Any]] = field(default_factory=list)
    attributes: Dict[str, bytes] = field(default_factory=dict)
    bootstrap_methods: List[Dict[str, Any]] = field(default_factory=list)

class ClassFileReader:
    def __init__(self, filePath: str) -> None:
        if not os.path.isfile(filePath):
            raise FileNotFoundError(f"File not found: {filePath}")
        try:
            with open(filePath, 'rb') as filePointer:
                self.fileData: bytes = filePointer.read()
        except IOError as e:
            raise IOError(f"Error reading file {filePath}: {e}")

        self.currentCursor: int = 0
        self.fileLength: int = len(self.fileData)

    @classmethod
    def from_bytes(cls, data: bytes) -> "ClassFileReader":
        reader = cls.__new__(cls)
        reader.fileData = data
        reader.currentCursor = 0
        reader.fileLength = len(data)
        return reader

    def readUnsignedByte(self) -> int:
        if self.currentCursor >= self.fileLength:
            raise EOFError("Reached end of file while trying to read an unsigned byte.")
        
        val: int = self.fileData[self.currentCursor]
        self.currentCursor += 1
        return val

    def readUnsignedShort(self) -> int:
        try:
            val = struct.unpack_from('>H', self.fileData, self.currentCursor)[0]
            self.currentCursor += 2
            return val
        except struct.error as e:
            raise ValueError(f"Error reading unsigned short at position {self.currentCursor}: {e}")

    def readUnsignedInt(self) -> int:
        try:
            val = struct.unpack_from('>I', self.fileData, self.currentCursor)[0]
            self.currentCursor += 4
            return val
        except struct.error as e:
            raise ValueError(f"Error reading unsigned int at position {self.currentCursor}: {e}")

    def readBytes(self, byteLength: int) -> bytes:
        if self.currentCursor + byteLength > self.fileLength:
            raise EOFError("Reached end of file while trying to read bytes.")
        val: bytes = self.fileData[self.currentCursor:self.currentCursor + byteLength]
        self.currentCursor += byteLength
        return val

    def readRawBytes(self, byteLength: int) -> bytes:
        if self.currentCursor + byteLength > self.fileLength:
            raise EOFError("Reached end of file while trying to read raw bytes.")
        val: bytes = self.fileData[self.currentCursor:self.currentCursor + byteLength]
        self.currentCursor += byteLength
        return val


def decodeModifiedUtf8(b: bytes) -> str:
    """Decodes JVM Modified UTF-8 bytes to Python str (JVM Spec §4.4.7)."""
    res = []
    i = 0
    n = len(b)
    try:
        while i < n:
            byte1 = b[i]
            if byte1 == 0:
                res.append('\x00')
                i += 1
            elif (byte1 & 0x80) == 0:
                res.append(chr(byte1))
                i += 1
            elif (byte1 & 0xE0) == 0xC0:
                if i + 1 < n:
                    byte2 = b[i + 1]
                    if byte1 == 0xC0 and byte2 == 0x80:
                        res.append('\x00')
                    else:
                        char_code = ((byte1 & 0x1F) << 6) | (byte2 & 0x3F)
                        res.append(chr(char_code))
                    i += 2
                else:
                    res.append('\ufffd')
                    i += 1
            elif (byte1 & 0xF0) == 0xE0:
                if i + 2 < n:
                    byte2 = b[i + 1]
                    byte3 = b[i + 2]
                    # Check for surrogate pair representation in Modified UTF-8
                    if byte1 == 0xED and (byte2 & 0xF0) == 0xA0 and i + 5 < n and b[i + 3] == 0xED and (b[i + 4] & 0xF0) == 0xB0:
                        high_surr = ((byte1 & 0x0F) << 12) | ((byte2 & 0x3F) << 6) | (byte3 & 0x3F)
                        low_surr = ((b[i + 3] & 0x0F) << 12) | ((b[i + 4] & 0x3F) << 6) | (b[i + 5] & 0x3F)
                        code_point = 0x10000 + ((high_surr - 0xD800) << 10) + (low_surr - 0xDC00)
                        res.append(chr(code_point))
                        i += 6
                    else:
                        char_code = ((byte1 & 0x0F) << 12) | ((byte2 & 0x3F) << 6) | (byte3 & 0x3F)
                        res.append(chr(char_code))
                        i += 3
                else:
                    res.append('\ufffd')
                    i += 1
            else:
                chunk = b[i:i+1].decode('utf-8', errors='replace')
                res.append(chunk)
                i += 1
        return "".join(res)
    except Exception:
        return b.decode('utf-8', errors='replace')


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
    tagDynamic: int = 17
    tagInvokeDynamic: int = 18
    tagModule: int = 19
    tagPackage: int = 20

    while currentIndex < poolCount:
        currentTag: int = classReader.readUnsignedByte()

        if currentTag == tagUtf8:
            byteLength: int = classReader.readUnsignedShort()
            utf8Bytes: bytes = classReader.readRawBytes(byteLength)
            constantPool[currentIndex] = {"type": "Utf8", "value": decodeModifiedUtf8(utf8Bytes)}

        elif currentTag == tagClass:
            nameIndex: int = classReader.readUnsignedShort()
            constantPool[currentIndex] = {"type": "Class", "nameIndex": nameIndex}

        elif currentTag in (tagFieldRef, tagMethodRef, tagInterfaceMethodRef):
            classIndex: int = classReader.readUnsignedShort()
            nameAndTypeIndex: int = classReader.readUnsignedShort()
            refKind = "FieldRef" if currentTag == tagFieldRef else ("MethodRef" if currentTag == tagMethodRef else "InterfaceMethodRef")
            constantPool[currentIndex] = {
                "type": "Ref",
                "refKind": refKind,
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
            constantPool[currentIndex] = {
                "type": "Primitive64",
                "kind": "Long" if currentTag == tagLong else "Double",
                "high": highBytes,
                "low": lowBytes,
            }
            # JVM Spec §4.4.5: 8-byte constants take two entries; index n+1 is unusable but present
            constantPool[currentIndex + 1] = None
            currentIndex += 1 

        elif currentTag == tagMethodHandle:
            referenceKind: int = classReader.readUnsignedByte()
            referenceIndex: int = classReader.readUnsignedShort()
            constantPool[currentIndex] = {
                "type": "MethodHandle",
                "referenceKind": referenceKind,
                "referenceIndex": referenceIndex,
            }

        elif currentTag == tagMethodType:
            descriptorIndex: int = classReader.readUnsignedShort()
            constantPool[currentIndex] = {
                "type": "MethodType",
                "descriptorIndex": descriptorIndex,
            }

        elif currentTag == tagDynamic:
            bootstrapMethodAttrIndex: int = classReader.readUnsignedShort()
            nameAndTypeIndex: int = classReader.readUnsignedShort()
            constantPool[currentIndex] = {
                "type": "Dynamic",
                "bootstrapMethodAttrIndex": bootstrapMethodAttrIndex,
                "nameAndTypeIndex": nameAndTypeIndex,
            }

        elif currentTag == tagInvokeDynamic:
            bootstrapMethodAttrIndex: int = classReader.readUnsignedShort()
            nameAndTypeIndex: int = classReader.readUnsignedShort()
            constantPool[currentIndex] = {
                "type": "InvokeDynamic",
                "bootstrapMethodAttrIndex": bootstrapMethodAttrIndex,
                "nameAndTypeIndex": nameAndTypeIndex,
            }

        elif currentTag == tagModule:
            nameIndex: int = classReader.readUnsignedShort()
            constantPool[currentIndex] = {
                "type": "Module",
                "nameIndex": nameIndex,
            }

        elif currentTag == tagPackage:
            nameIndex: int = classReader.readUnsignedShort()
            constantPool[currentIndex] = {
                "type": "Package",
                "nameIndex": nameIndex,
            }

        else:
            raise NotImplementedError(f"Unsupported Constant Pool Tag '{currentTag}' encountered at index {currentIndex}.")

        currentIndex += 1

    return constantPool


def resolveUtf8(constantPool: Dict[int, Any], index: int) -> str:
    entry = constantPool.get(index)
    if entry and entry.get("type") == "Utf8":
        return entry.get("value", "")
    return ""


def resolveClass(constantPool: Dict[int, Any], index: int) -> str:
    entry = constantPool.get(index)
    if entry and entry.get("type") == "Class":
        return resolveUtf8(constantPool, entry.get("nameIndex", 0))
    return ""


def resolveNameAndType(constantPool: Dict[int, Any], index: int) -> Tuple[str, str]:
    entry = constantPool.get(index)
    if entry and entry.get("type") == "NameAndType":
        name = resolveUtf8(constantPool, entry.get("nameIndex", 0))
        descriptor = resolveUtf8(constantPool, entry.get("descriptorIndex", 0))
        return name, descriptor
    return "", ""


def resolveRef(constantPool: Dict[int, Any], index: int) -> Dict[str, str]:
    entry = constantPool.get(index)
    if entry and entry.get("type") == "Ref":
        className = resolveClass(constantPool, entry.get("classIndex", 0))
        name, descriptor = resolveNameAndType(constantPool, entry.get("nameAndTypeIndex", 0))
        return {
            "kind": entry.get("refKind", "Ref"),
            "class": className,
            "name": name,
            "descriptor": descriptor
        }
    return {"kind": "Unknown", "class": "", "name": "", "descriptor": ""}


def resolveString(constantPool: Dict[int, Any], index: int) -> str:
    entry = constantPool.get(index)
    if entry and entry.get("type") == "String":
        return resolveUtf8(constantPool, entry.get("stringIndex", 0))
    return ""


def parseDescriptor(descriptor: str) -> Tuple[List[str], str]:
    """Parses a method descriptor like '(Ljava/lang/String;I)V' into ([param_types], return_type)."""
    if not descriptor or not descriptor.startswith("("):
        return [], "void"
    
    endParen = descriptor.find(")")
    if endParen == -1:
        return [], "void"
        
    paramStr = descriptor[1:endParen]
    retStr = descriptor[endParen + 1:]
    
    typeMap = {
        'B': 'byte',
        'C': 'char',
        'D': 'double',
        'F': 'float',
        'I': 'int',
        'J': 'long',
        'S': 'short',
        'Z': 'boolean',
        'V': 'void'
    }
    
    def decodeType(s: str) -> Tuple[str, str]:
        if not s:
            return "", ""
        if s[0] == '[':
            subType, remainder = decodeType(s[1:])
            return f"{subType}[]", remainder
        if s[0] == 'L':
            semicolon = s.find(';')
            if semicolon != -1:
                rawClass = s[1:semicolon].replace('/', '.')
                simpleClass = rawClass.split('.')[-1]
                return simpleClass, s[semicolon + 1:]
            return s[1:], ""
        if s[0] in typeMap:
            return typeMap[s[0]], s[1:]
        return s[0], s[1:]

    params: List[str] = []
    rem = paramStr
    while rem:
        pType, rem = decodeType(rem)
        if pType:
            params.append(pType)
        else:
            break
            
    retType, _ = decodeType(retStr)
    return params, retType or "void"


def parseClassInfo(classReader: ClassFileReader) -> ClassInfo:
    """Parses all class metadata, constant pool, fields, methods, and attributes into a ClassInfo object."""
    magicNumber: int = classReader.readUnsignedInt()
    if magicNumber != 0xCAFEBABE:
        raise ValueError(f"Invalid class file: Expected magic number 0xCAFEBABE, found {hex(magicNumber)}")

    minorVersion: int = classReader.readUnsignedShort()
    majorVersion: int = classReader.readUnsignedShort()
    constantPoolCount: int = classReader.readUnsignedShort()
    constantPoolDict: Dict[int, Any] = parseConstantPool(classReader, constantPoolCount)

    accessFlags: int = classReader.readUnsignedShort()
    thisClassIndex: int = classReader.readUnsignedShort()
    superClassIndex: int = classReader.readUnsignedShort()
    thisClassName = resolveClass(constantPoolDict, thisClassIndex)
    superClassName = resolveClass(constantPoolDict, superClassIndex)

    interfacesCount: int = classReader.readUnsignedShort()
    interfaces: List[str] = []
    for _ in range(interfacesCount):
        ifaceIndex = classReader.readUnsignedShort()
        interfaces.append(resolveClass(constantPoolDict, ifaceIndex))

    # Parse fields
    fieldsCount: int = classReader.readUnsignedShort()
    fields: List[Dict[str, Any]] = []
    for _ in range(fieldsCount):
        fAccess = classReader.readUnsignedShort()
        fNameIdx = classReader.readUnsignedShort()
        fDescIdx = classReader.readUnsignedShort()
        fName = resolveUtf8(constantPoolDict, fNameIdx)
        fDesc = resolveUtf8(constantPoolDict, fDescIdx)
        
        fAttrCount = classReader.readUnsignedShort()
        for _ in range(fAttrCount):
            classReader.readUnsignedShort()
            attrLen = classReader.readUnsignedInt()
            classReader.readRawBytes(attrLen)
            
        fields.append({"name": fName, "descriptor": fDesc, "accessFlags": fAccess})

    # Parse methods
    methodsCount: int = classReader.readUnsignedShort()
    methods: Dict[str, MethodInfo] = {}

    for _ in range(methodsCount):
        mAccess = classReader.readUnsignedShort()
        nameIndex: int = classReader.readUnsignedShort()
        descriptorIndex: int = classReader.readUnsignedShort()
        
        methodName: str = resolveUtf8(constantPoolDict, nameIndex) or f"UnknownMethod_{nameIndex}"
        descriptor: str = resolveUtf8(constantPoolDict, descriptorIndex)
        paramTypes, returnType = parseDescriptor(descriptor)
        isStatic = bool(mAccess & 0x0008)

        attributesCount: int = classReader.readUnsignedShort()
        bytecode: bytes = b""
        exceptionHandlers: List[Dict[str, int]] = []

        for _ in range(attributesCount):
            attributeNameIndex: int = classReader.readUnsignedShort()
            attributeLength: int = classReader.readUnsignedInt()
            attributePayload: bytes = classReader.readRawBytes(attributeLength)
            attributeName: str = resolveUtf8(constantPoolDict, attributeNameIndex)

            if attributeName == "Code":
                codeLength: int = struct.unpack_from('>I', attributePayload, 4)[0]
                bytecode = attributePayload[8 : 8 + codeLength]
                exOffset = 8 + codeLength
                if exOffset + 2 <= len(attributePayload):
                    exTableLen = struct.unpack_from('>H', attributePayload, exOffset)[0]
                    exOffset += 2
                    for _ in range(exTableLen):
                        if exOffset + 8 <= len(attributePayload):
                            s_pc, e_pc, h_pc, c_type = struct.unpack_from('>HHHH', attributePayload, exOffset)
                            exceptionHandlers.append({
                                "start_pc": s_pc,
                                "end_pc": e_pc,
                                "handler_pc": h_pc,
                                "catch_type": c_type,
                            })
                            exOffset += 8

        methods[methodName] = MethodInfo(
            name=methodName,
            descriptor=descriptor,
            access_flags=mAccess,
            bytecode=bytecode,
            is_static=isStatic,
            param_types=paramTypes,
            return_type=returnType,
            exception_handlers=exceptionHandlers,
        )

    # Parse class attributes (e.g. BootstrapMethods, InnerClasses, SourceFile)
    class_attributes: Dict[str, bytes] = {}
    bootstrap_methods: List[Dict[str, Any]] = []
    if classReader.currentCursor + 2 <= classReader.fileLength:
        attrCount = classReader.readUnsignedShort()
        for _ in range(attrCount):
            attrNameIdx = classReader.readUnsignedShort()
            attrLen = classReader.readUnsignedInt()
            attrData = classReader.readRawBytes(attrLen)
            attrName = resolveUtf8(constantPoolDict, attrNameIdx)
            if attrName:
                class_attributes[attrName] = attrData
                if attrName == "BootstrapMethods" and len(attrData) >= 2:
                    bmOffset = 0
                    numBM = struct.unpack_from('>H', attrData, bmOffset)[0]
                    bmOffset += 2
                    for _ in range(numBM):
                        if bmOffset + 4 <= len(attrData):
                            bmRef, numArgs = struct.unpack_from('>HH', attrData, bmOffset)
                            bmOffset += 4
                            bmArgs = []
                            for _ in range(numArgs):
                                if bmOffset + 2 <= len(attrData):
                                    bmArgs.append(struct.unpack_from('>H', attrData, bmOffset)[0])
                                    bmOffset += 2
                            bootstrap_methods.append({
                                "method_ref": bmRef,
                                "arguments": bmArgs,
                            })

    return ClassInfo(
        class_name=thisClassName,
        super_class=superClassName,
        interfaces=interfaces,
        major_version=majorVersion,
        minor_version=minorVersion,
        constant_pool=constantPoolDict,
        methods=methods,
        fields=fields,
        attributes=class_attributes,
        bootstrap_methods=bootstrap_methods,
    )


def parseClassFile(classFilePath: str) -> ClassInfo:
    """Parses a standalone .class file returning full ClassInfo (CP + Methods + Metadata)."""
    if not os.path.isfile(classFilePath):
        raise FileNotFoundError(f"Class file not found: {classFilePath}")
    reader = ClassFileReader(classFilePath)
    return parseClassInfo(reader)


def extractAndParseJar(jarFilePath: str, targetClassFile: str) -> Dict[str, bytes]:
    """Safely extracts and parses method bytecodes from a JAR class in-memory without disk leaks."""
    if not os.path.isfile(jarFilePath):
        raise FileNotFoundError(f"JAR file not found: {jarFilePath}")

    try:
        with zipfile.ZipFile(jarFilePath, "r") as jarArchive:
            try:
                classBytes = jarArchive.read(targetClassFile)
            except KeyError:
                raise KeyError(f"The class file {targetClassFile} was not found in the JAR archive {jarFilePath}")
    except zipfile.BadZipFile:
        raise ValueError(f"The file {jarFilePath} is not a valid JAR/ZIP file")

    classReader = ClassFileReader.from_bytes(classBytes)
    poolCount: int = parseClassHeader(classReader)
    constantPoolDict: Dict[int, Dict[str, Any]] = parseConstantPool(classReader, poolCount)
    
    skipClassMetadataAndInterfaces(classReader)
    skipFields(classReader)
    
    extractedBytecodes = extractMethodBytecode(classReader, constantPoolDict)
    return extractedBytecodes


def parseJarFile(jarFilePath: str) -> List[ClassInfo]:
    """Unpacks a JAR archive and parses all .class files into ClassInfo objects in-memory."""
    if not os.path.isfile(jarFilePath):
        raise FileNotFoundError(f"JAR file not found: {jarFilePath}")

    classes: List[ClassInfo] = []
    with zipfile.ZipFile(jarFilePath, "r") as jarArchive:
        for member in jarArchive.namelist():
            if member.endswith(".class") and not member.startswith("__MACOSX"):
                classBytes = jarArchive.read(member)
                classReader = ClassFileReader.from_bytes(classBytes)
                info = parseClassInfo(classReader)
                classes.append(info)
    return classes


def skipClassMetadataAndInterfaces(classReader: ClassFileReader) -> None:
    classReader.readUnsignedShort()
    classReader.readUnsignedShort()
    classReader.readUnsignedShort()

    interfacesCount: int = classReader.readUnsignedShort()
    classReader.readRawBytes(interfacesCount * 2)


def skipFields(classReader: ClassFileReader) -> None:
    fieldsCount: int = classReader.readUnsignedShort()
    
    for _ in range(fieldsCount):
        classReader.readUnsignedShort()
        classReader.readUnsignedShort()
        classReader.readUnsignedShort()
        
        attributesCount: int = classReader.readUnsignedShort()
        for _ in range(attributesCount):
            classReader.readUnsignedShort()
            attributeLength: int = classReader.readUnsignedInt()
            classReader.readRawBytes(attributeLength)


def extractMethodBytecode(classReader: ClassFileReader, constantPool: Dict[int, Dict[str, Any]]) -> Dict[str, bytes]:
    methodsCount: int = classReader.readUnsignedShort()
    extractedMethods: Dict[str, bytes] = {}

    for _ in range(methodsCount):
        classReader.readUnsignedShort()
        nameIndex: int = classReader.readUnsignedShort()
        classReader.readUnsignedShort()
        
        methodName: str = constantPool[nameIndex].get("value", f"UnknownMethod_{nameIndex}")
        attributesCount: int = classReader.readUnsignedShort()

        for _ in range(attributesCount):
            attributeNameIndex: int = classReader.readUnsignedShort()
            attributeLength: int = classReader.readUnsignedInt()
            
            attributePayload: bytes = classReader.readRawBytes(attributeLength)
            
            attributeName: str = constantPool[attributeNameIndex].get("value", "")

            if attributeName == "Code":
                codeLength: int = struct.unpack_from('>I', attributePayload, 4)[0]
                rawInstructions: bytes = attributePayload[8 : 8 + codeLength]
                extractedMethods[methodName] = rawInstructions

    return extractedMethods


def parseClassDirectly(classFilePath: str) -> Dict[str, bytes]:
    """Parses a standalone .class file directly from disk returning method name -> bytecode."""
    if not os.path.isfile(classFilePath):
        raise FileNotFoundError(f"Class file not found: {classFilePath}")

    classReader: ClassFileReader = ClassFileReader(classFilePath)
    poolCount: int = parseClassHeader(classReader)
    constantPoolDict: Dict[int, Dict[str, Any]] = parseConstantPool(classReader, poolCount)
    
    skipClassMetadataAndInterfaces(classReader)
    skipFields(classReader)
    
    extractedBytecodes = extractMethodBytecode(classReader, constantPoolDict)
    return extractedBytecodes


if __name__ == "__main__":
    from disassembler import disassembleMethod

    targetClassPath = "EngineMath.class" 

    methodBytecodes = parseClassDirectly(targetClassPath)

    for mName, mBytes in methodBytecodes.items():
        print(f"\nDisassembling Method: {mName}")
        parsedInstructions = disassembleMethod(mName, mBytes)
        
        for instr in parsedInstructions:
            opStr = f"{instr['mnemonic']} " + " ".join([str(op) for op in instr['operands']])
            print(f"  {instr['offset']:4}: {opStr.strip()}")
