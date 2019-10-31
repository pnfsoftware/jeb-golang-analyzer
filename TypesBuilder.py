from com.pnfsoftware.jeb.core.units.code.asm.memory import MemoryException
from com.pnfsoftware.jeb.core.units.code.asm.items import INativeDataItem
from com.pnfsoftware.jeb.core.units.code.asm.type import StringType

from Commons import readPtr, SliceHeader, StringHeader, ModuleData

import JebUtils

"""
Recover and parse type information from Golang metadata.

Type information are then translated into their memory 
representation (see logs)

Some types and imported in JEB types.
(for now, limited to Struct)

(This file is part of JEB Decompiler's scripts used to analyze Golang executables.)
"""
DEBUG_MODE = False
LOG_STD_PACKAGES = True

TYPE_KINDS = ['Invalid Kind','Bool','Int','Int8','Int16','Int32','Int64','Uint','Uint8','Uint16','Uint32','Uint64','Uintptr','Float32','Float64','Complex64','Complex128','Array','Chan','Func','Interface','Map','Ptr','Slice','String','Struct','UnsafePointer']
STANDARD_PACKAGES = ['archive/tar', 'archive/zip', 'bufio', 'builtin', 'bytes', 'compress/bzip2', 'compress/flate', 'compress/gzip', 'compress/lzw', 'compress/zlib', 'container/heap', 'container/list', 'container/ring', 'context', 'crypto', 'crypto/aes', 'crypto/cipher', 'crypto/des', 'crypto/dsa', 'crypto/ecdsa', 'crypto/ed25519', 'crypto/elliptic', 'crypto/hmac', 'crypto/md5', 'crypto/rand', 'crypto/rc4', 'crypto/rsa', 'crypto/sha1', 'crypto/sha256', 'crypto/sha512', 'crypto/subtle', 'crypto/tls', 'crypto/x509', 'crypto/x509/pkix', 'database/sql', 'database/sql/driver', 'debug/dwarf', 'debug/elf', 'debug/gosym', 'debug/macho', 'debug/pe', 'debug/plan9obj', 'encoding', 'encoding/ascii85', 'encoding/asn1', 'encoding/base32', 'encoding/base64', 'encoding/binary', 'encoding/csv', 'encoding/gob', 'encoding/hex', 'encoding/json', 'encoding/pem', 'encoding/xml', 'errors', 'expvar', 'flag', 'fmt', 'go/ast', 'go/build', 'go/constant', 'go/doc', 'go/format', 'go/importer', 'go/parser', 'go/printer', 'go/scanner', 'go/token', 'go/types', 'hash', 'hash/adler32', 'hash/crc32', 'hash/crc64', 'hash/fnv', 'html', 'html/template', 'image', 'image/color', 'image/color/palette', 'image/draw', 'image/gif', 'image/jpeg', 'image/png', 'index/suffixarray', 'io', 'io/ioutil', 'log', 'log/syslog', 'math', 'math/big', 'math/bits', 'math/cmplx', 'math/rand', 'mime', 'mime/multipart', 'mime/quotedprintable', 'net', 'net/http', 'net/http/cgi', 'net/http/cookiejar', 'net/http/fcgi', 'net/http/httptest', 'net/http/httptrace', 'net/http/httputil', 'net/http/pprof', 'net/mail', 'net/rpc', 'net/rpc/jsonrpc', 'net/smtp', 'net/textproto', 'net/url', 'os', 'os/exec', 'os/signal', 'os/user', 'path', 'path/filepath', 'plugin', 'reflect', 'regexp', 'regexp/syntax', 'runtime', 'runtime/cgo', 'runtime/debug', 'runtime/pprof', 'runtime/race', 'runtime/trace', 'sort', 'strconv', 'strings', 'sync', 'sync/atomic', 'syscall', 'syscall/js', 'testing', 'testing/iotest', 'testing/quick', 'text/scanner', 'text/tabwriter', 'text/template', 'text/template/parse', 'time', 'unicode', 'unicode/utf16', 'unicode/utf8', 'unsafe']

class TypesBuilder():

  def __init__(self, golangAnalyzer):
    self.golangAnalyzer = golangAnalyzer
    self.memory = golangAnalyzer.nativeCodeAnalyzer.getMemory()
    self.moduleDataList = golangAnalyzer.moduleDataList
    self.pclntab = golangAnalyzer.pclntab
    self.ptrSize = self.pclntab.ptrSize
    self.curModuleData = None
    self.typeManager = golangAnalyzer.typeManager
    self.labelManager = golangAnalyzer.codeUnit.getCodeModel().getLabelManager()
    self.codeUnit = golangAnalyzer.codeUnit
    self.parsedTypes = dict() # address -> parsed type

    # for stats:
    self.counterParsedTypes = 0 
    self.createdJebTypes = list() # not all types are imported
    self.itabs = list()
    self.errors = list()

    self.importBasicTypes(self.typeManager)

  def importBasicTypes(self, typeManager):  
    rtypeJebType = Rtype.createJebStructure(typeManager, self.ptrSize)
    if rtypeJebType != None:
      self.createdJebTypes.append(rtypeJebType)

    ptrTypeJebType = PtrType.createJebStructure(typeManager, self.ptrSize)
    if ptrTypeJebType != None:
      self.createdJebTypes.append(ptrTypeJebType)

    structFieldJebType = StructField.createJebStructure(typeManager, self.ptrSize)
    if structFieldJebType != None:
      self.createdJebTypes.append(structFieldJebType)

    structTypeJebType = StructType.createJebStructure(typeManager, self.ptrSize)
    if structTypeJebType != None:
      self.createdJebTypes.append(structTypeJebType)

    arrayTypeJebType = ArrayType.createJebStructure(typeManager, self.ptrSize)
    if arrayTypeJebType != None:
      self.createdJebTypes.append(arrayTypeJebType)

    iMethodTypeJebType = IMethodType.createJebStructure(typeManager, self.ptrSize)
    if iMethodTypeJebType != None:
      self.createdJebTypes.append(iMethodTypeJebType)

    interfaceTypeJebType = InterfaceType.createJebStructure(typeManager, self.ptrSize)
    if interfaceTypeJebType != None:
      self.createdJebTypes.append(interfaceTypeJebType)

    sliceTypeJebType = SliceType.createJebStructure(typeManager, self.ptrSize)
    if sliceTypeJebType != None:
      self.createdJebTypes.append(sliceTypeJebType)

    uncommonTypeJebType = UncommonType.createJebStructure(typeManager, self.ptrSize)
    if uncommonTypeJebType != None:
      self.createdJebTypes.append(uncommonTypeJebType)

    methodTypeJebType = MethodType.createJebStructure(typeManager, self.ptrSize)
    if methodTypeJebType != None:
      self.createdJebTypes.append(methodTypeJebType)

    funcTypeJebType = FuncType.createJebStructure(typeManager, self.ptrSize)
    if funcTypeJebType != None:
      self.createdJebTypes.append(funcTypeJebType)

    chanTypeJebType = ChanType.createJebStructure(typeManager, self.ptrSize)
    if chanTypeJebType != None:
      self.createdJebTypes.append(chanTypeJebType)

    mapTypeJebType = MapType.createJebStructure(typeManager, self.ptrSize)
    if mapTypeJebType != None:
      self.createdJebTypes.append(mapTypeJebType)

    itabJebType = Itab.createJebStructure(typeManager, self.ptrSize)
    if itabJebType != None:
      self.createdJebTypes.append(itabJebType)

  def run(self):  
    print('> %s: reconstructing types...' % self.__class__.__name__),
    for md in self.moduleDataList:
      self.curModuleData = md
      self.printIfDebug('> types @%x (end: @%x) - typelinks @%x (%d offsets)' % (md.types, md.etypes, md.typelinks.data, md.typelinks._len))

      # parse type metadata: iterate over 'types', using offsets in 'typelinks' slice
      curPtr = self.curModuleData.typelinks.data
      for counter in range(self.curModuleData.typelinks._len):
        typeOffset = self.memory.readInt(curPtr) # !! always int32
        typeAddr = (self.curModuleData.types + typeOffset) & 0xFFFFFFFF
        try:
          self.parseType(typeAddr)
        except MemoryException as memError:
          print('\n  > error: fail to parse root type at %x, stopping types parsing (likely not handled Go version)' % typeAddr)
          return
        curPtr+=4

      # import in JEB the parsed types
      self.createAllTypesInJEB()

      # experimental: parse interface metadata (iterate over 'itablinks')
      curPtr = self.curModuleData.itablinks.data
      for counter in range(self.curModuleData.itablinks._len):
        itabStartAddr, curPtr = readPtr(self.memory, self.ptrSize, curPtr)
        myItab = Itab(self, itabStartAddr)
        myItab.parse()
        myItab.applyJebStructure()
        self.itabs.append(myItab)

    print('OK (%d parsed types - %d types imported to JEB - see logs)' % (self.counterParsedTypes, len(self.createdJebTypes)))

  def parseType(self, typeAddr, depth=1):
    '''
      Parse type description at given address (i.e. a structure encapsulating a rtype), 
      and register the Python parsed object in self.parsedTypes.

      Note: the parsing might be recursive, as some types reference
      others types.
    '''    
    self.printIfDebug(' '*depth + '> parsing type @ %x' % typeAddr)

    # all types starts with rtype
    parsedType = Rtype(self, typeAddr)
    parsedType.parse()
    self.printIfDebug(' '*depth + '%s' % parsedType.getSimpleName())
  
    # prevent infinite recursion: check if parsing already done
    if typeAddr in self.parsedTypes.keys():
      self.printIfDebug(' '*depth + 'already parsed')
      return parsedType

    self.counterParsedTypes+=1

    if parsedType.size == 0:
      # not sure why it happens, some types are pruned?
      # metadata are still there though, so we can continue parsing
      self.printIfDebug(' '*depth + '> WARNING: empty type')

    # note: some types reference themselves (e.g. linked list struct 
    # with next/prev fields). To avoid infinite recursion we register
    # the type in self.parsedTypes *before* parsing it.
    if parsedType.getKind() == 'Ptr':
      myPtr = PtrType(self, typeAddr, parsedType)
      self.parsedTypes[typeAddr] = myPtr
      myPtr.parse()
      self.printIfDebug(' '*depth + '%s' % myPtr)
    
    elif parsedType.getKind() == 'Struct':
      myStruct = StructType(self, typeAddr, parsedType)
      self.parsedTypes[typeAddr] = myStruct
      myStruct.parse()
      self.printIfDebug(' '*depth + '%s' % myStruct)

    elif parsedType.getKind() == 'Array':
      myArray = ArrayType(self, typeAddr, parsedType)
      self.parsedTypes[typeAddr] = myArray
      myArray.parse()
      self.printIfDebug(' '*depth + '%s' % myArray)

    elif parsedType.getKind() == 'Slice':
      mySlice = SliceType(self, typeAddr, parsedType)
      self.parsedTypes[typeAddr] = mySlice
      mySlice.parse()
      self.printIfDebug(' '*depth + '%s' % mySlice)

    elif parsedType.getKind() == 'Interface':
      myInterface = InterfaceType(self, typeAddr, parsedType)
      self.parsedTypes[typeAddr] = myInterface
      myInterface.parse()
      self.printIfDebug(' '*depth + '%s' % myInterface)

    elif parsedType.getKind() == 'Chan':
      myChan = ChanType(self, typeAddr, parsedType)
      self.parsedTypes[typeAddr] = myChan
      myChan.parse()
      self.printIfDebug(' '*depth + '%s' % myChan)

    elif parsedType.getKind() == 'Func':
      myFunc = FuncType(self, typeAddr, parsedType)
      self.parsedTypes[typeAddr] = myFunc
      myFunc.parse()
      self.printIfDebug(' '*depth + '%s' % myFunc)

    elif parsedType.getKind() == 'Map':
      myMap = MapType(self, typeAddr, parsedType)
      self.parsedTypes[typeAddr] = myMap
      myMap.parse()
      self.printIfDebug(' '*depth + '%s' % myMap)

    elif self.isRawType(parsedType.getKind()):
      self.printIfDebug(' '*depth + '%s' % parsedType)
      self.parsedTypes[typeAddr] = RawType(self, typeAddr, parsedType)

    else:
      raise Exception('Unknown type (kind:%s)' % parsedType.getKind())

    # handle "uncommon" types (i.e. types with methods)
    # by replacing type with a wrapper
    if parsedType.isUncommon():
      primaryType = self.parsedTypes[typeAddr] # must exist
      uncommonType = UncommonType(self, primaryType)
      uncommonType.parse()
      self.parsedTypes[typeAddr] = uncommonType

    return parsedType

  def printIfDebug(self, str):
    global DEBUG_MODE
    if DEBUG_MODE:
      print(str)

  def createAllTypesInJEB(self, wantedName=''):
    '''
      Import type information in JEB:

      - apply metadata structures

      - translate parsed types into their runtime memory 
        representations, and add them to JEB types

        Note: limited to *named* structures, for now. 
    '''

    # metadata
    for curType in self.parsedTypes.values():
      if isinstance(curType, StructType) \
      or isinstance(curType, ArrayType) \
      or isinstance(curType, PtrType) \
      or isinstance(curType, InterfaceType) \
      or isinstance(curType, SliceType) \
      or isinstance(curType, FuncType) \
      or isinstance(curType, ChanType) \
      or isinstance(curType, MapType) \
      or isinstance(curType, UncommonType) \
      or self.isRawType(curType.rtype.getKind()):
        curType.applyJebStructure()
      else:
        # by default, add a label and create 1-byte data item (if no item)
        self.labelManager.setLabel(curType.startAddr, curType.getSimpleName(), True, True, False)
        if not self.codeUnit.getNativeItemAt(curType.startAddr):
          self.codeUnit.setDataTypeAt(curType.startAddr, self.typeManager.getPrimitives().getExactIntegerBySize(1, False))

    # import named structures in JEB
    for curType in self.parsedTypes.values():
      try:
        if wantedName == '' or curType.rtype.getSimpleName().startswith(wantedName):           
          if curType.rtype.isNamed():
            if (isinstance(curType, UncommonType) and isinstance(curType.primaryType, StructType)) \
              or isinstance(curType, StructType):
              self.printIfDebug('> adding to JEB %s' % curType)
              self.createJebType(curType.rtype)
        else:
          continue
      except TypeTranslationError as err:
        msg = '> import failed for %s: %s' % (curType.rtype.getSimpleName(), err.message)
        self.printIfDebug(msg)
        self.errors.append(msg)
      except Exception as generalErr:
        msg = '> import failed for %s (unknown error)' % (curType.rtype.getSimpleName())
        self.printIfDebug(msg)
        self.errors.append(msg)

  def createJebType(self, rtype):
    '''
      Create and provide the corresponding JEB type for the given rtype, 
      or alternatively retrieve the existing JEB type if it already exists.

      Throws TypeTranslationError
    '''
    global TYPE_KINDS

    kind = rtype.kind
    startAddr = rtype.startAddr
    primitiveTypeManager =  self.typeManager.getPrimitives()
    if TYPE_KINDS[kind] == 'Invalid Kind':
      raise TypeTranslationError('not implemented type translation: %s' % TYPE_KINDS[kind])
    if TYPE_KINDS[kind] == 'Bool':
      return self.typeManager.getType('_Bool')
    if TYPE_KINDS[kind] == 'Int':
      return primitiveTypeManager.getExactIntegerBySize(self.ptrSize, True)
    if TYPE_KINDS[kind] == 'Int8':
      return primitiveTypeManager.getExactIntegerBySize(1, True)
    if TYPE_KINDS[kind] == 'Int16':
      return primitiveTypeManager.getExactIntegerBySize(2, True)
    if TYPE_KINDS[kind] == 'Int32':
      return primitiveTypeManager.getExactIntegerBySize(4, True)
    if TYPE_KINDS[kind] == 'Int64':
      return primitiveTypeManager.getExactIntegerBySize(8, True)
    if TYPE_KINDS[kind] == 'Uint':
      return self.typeManager.getType('unsigned int')
    if TYPE_KINDS[kind] == 'Uint8':
      return primitiveTypeManager.getExactIntegerBySize(1, False)
    if TYPE_KINDS[kind] == 'Uint16':
      return primitiveTypeManager.getExactIntegerBySize(2, False)
    if TYPE_KINDS[kind] == 'Uint32':
      return primitiveTypeManager.getExactIntegerBySize(4, False)
    if TYPE_KINDS[kind] == 'Uint64':
      return primitiveTypeManager.getExactIntegerBySize(8, False)
    if TYPE_KINDS[kind] == 'Uintptr':
      return self.typeManager.getType('void*') # better to use pclntab.ptrSize?
    if TYPE_KINDS[kind] == 'Float32':
      return primitiveTypeManager.getExactFloatBySize(4)
    if TYPE_KINDS[kind] == 'Float64':
      return primitiveTypeManager.getExactFloatBySize(8)
    if TYPE_KINDS[kind] == 'Complex64':
      raise TypeTranslationError('not implemented type translation: %s' % TYPE_KINDS[kind])
    if TYPE_KINDS[kind] == 'Complex128':
      raise TypeTranslationError('not implemented type translation: %s' % TYPE_KINDS[kind])
    if TYPE_KINDS[kind] == 'Array':
      myArray = self.parsedTypes[startAddr]
      if isinstance(myArray, UncommonType):
        myArray = myArray.primaryType
      elemJebType = self.createJebType(myArray.elemType)
      return self.typeManager.createArray(elemJebType, myArray.length)
    if TYPE_KINDS[kind] == 'Chan':
      raise TypeTranslationError('not implemented type translation: %s' % TYPE_KINDS[kind])
    if TYPE_KINDS[kind] == 'Func':
      raise TypeTranslationError('not implemented type translation: %s' % TYPE_KINDS[kind])
    if TYPE_KINDS[kind] == 'Interface':
      return self.createInterfaceInJEB(self.parsedTypes[startAddr])
    if TYPE_KINDS[kind] == 'Map':
      raise TypeTranslationError('not implemented type translation: %s' % TYPE_KINDS[kind])
    if TYPE_KINDS[kind] == 'Ptr':
      return self.typeManager.getType('void*')
    if TYPE_KINDS[kind] == 'Slice':
      return self.typeManager.getType(SliceHeader.JEB_NAME) # see importBasicTypes()
    if TYPE_KINDS[kind] == 'String':
      return self.typeManager.getType(StringHeader.JEB_NAME) # see importBasicTypes()
    if TYPE_KINDS[kind] == 'Struct':
      return self.createStructInJEB(self.parsedTypes[startAddr])
    if TYPE_KINDS[kind] == 'UnsafePointer':
      return self.typeManager.getType('void*')
    raise TypeTranslationError('not implemented type translation: %s' % TYPE_KINDS[kind])

  def isRawType(self, kind):
    RAW_TYPES = ['Bool','Int','Int8','Int16','Int32','Int64','Uint','Uint8','Uint16','Uint32','Uint64','Uintptr','Float32','Float64','Complex64','Complex128', 'UnsafePointer', 'String']
    return kind in RAW_TYPES

  def createInterfaceInJEB(self, interfaceType):
    '''
      Interface are represented as the following structure at runtime:

      type iface struct { // 16 bytes on a 64bit arch
          tab  *itab
          data unsafe.Pointer
      }
    '''
    if isinstance(interfaceType, UncommonType):
      interfaceType = interfaceType.primaryType

    rtype = interfaceType.rtype
    if not rtype.isNamed():
      raise TypeTranslationError('unnamed interface')

    jebInterfaceName = rtype.getSimpleName() + 'Interface'
    jebInterface = self.typeManager.getType(jebInterfaceName)
    if not jebInterface:
      jebInterface = self.typeManager.createStructure(jebInterfaceName)
      self.typeManager.addStructureField(jebInterface, 'tab', self.typeManager.getType('void*'), 0)
      self.typeManager.addStructureField(jebInterface, 'data', self.typeManager.getType('void*'), self.ptrSize)
      self.createdJebTypes.append(jebInterface)
    return jebInterface

  def createStructInJEB(self, structType):
    if isinstance(structType, UncommonType):
      structType = structType.primaryType
    rtype = structType.rtype
    if not rtype.isNamed():
      raise TypeTranslationError('unnamed structure')
    jebStruct = self.typeManager.getType(rtype.getSimpleName())
    if not jebStruct:
      if len(structType.fields) == 0:
        raise TypeTranslationError('structure with no fields')

      # first, try to create all fields
      fieldsJebType = list()
      for field in structType.fields:
        fieldsJebType.append(self.createJebType(field.typ)) # will throw if error
      
      # then, create the structure
      jebStruct = self.typeManager.createStructure(rtype.getSimpleName())
      for i in range(0, len(structType.fields)):
        field = structType.fields[i]
        fieldJebType = fieldsJebType[i]
        self.typeManager.addStructureField(jebStruct, field.name.getSimpleName(), fieldJebType, field.offset)

      self.createdJebTypes.append(jebStruct)
    return jebStruct

  def getStats(self):
    global LOG_STD_PACKAGES, STANDARD_PACKAGES

    pkgToNamedTypes = dict() #  pkg -> named type
    for parsedType in self.parsedTypes.values():
      if parsedType.rtype.isNamed():
        pkgName = parsedType.pkgPath.getSimpleName() if hasattr(parsedType, 'pkgPath') and parsedType.pkgPath != None else 'unknown'
        if pkgName not in pkgToNamedTypes.keys():
          pkgToNamedTypes[pkgName] = list()
        pkgToNamedTypes[pkgName].append(parsedType)

    stats = '> %d parsed types\n> %d named types:\n\n' % (len(self.parsedTypes.values()), len(pkgToNamedTypes.values()))
    for package in sorted(pkgToNamedTypes):
      if not LOG_STD_PACKAGES and package in STANDARD_PACKAGES:
        continue
      stats += '> PACKAGE: %s:\n\n' % package
      for nameType in pkgToNamedTypes[package]:
        stats += '\t%s\n' % nameType

    stats += '\n-----------------------\n'
    stats += '> %d itabs parsed:\n' % len(self.itabs)
    for itab in self.itabs:
      stats += '%s\n' % itab

    stats += '\n-----------------------\n'
    stats += '> %d types imported in jeb:\n' % len(self.createdJebTypes)
    for jebType in self.createdJebTypes:
      stats += '%s\n' % jebType
    stats += '-----------------------\n'
    stats += '> %d errors:\n' % len(self.errors)
    for error in self.errors:
      stats += '%s\n' % error
    return stats

class TypeTranslationError(Exception):
  '''
    Error when translating parsed type representation into its memory representation.
  '''
  def __init__(self, message):
    self.message = message

class Rtype():
  '''
    Reference: src\\reflect\\type.go

    type rtype struct {
      size       uintptr
      ptrdata    uintptr  // number of bytes in the type that can contain pointers
      hash       uint32   // hash of type; avoids computation in hash tables
      tflag      tflag    // extra type information flags
      align      uint8    // alignment of variable with this type
      fieldAlign uint8    // alignment of struct field with this type
      kind       uint8    // enumeration for C
      alg        *typeAlg // algorithm table
      gcdata     *byte    // garbage collection data
      str        nameOff  // string form
      ptrToThis  typeOff  // type for pointer to this type, may be zero
    }
  '''
  JEB_NAME = 'Rtype'

  # see src\reflect\type.go for constants definition
  TFLAG_UNCOMMON    = 0x1
  TFLAG_EXTRASTAR   = 0x2
  TFLAG_NAMED       = 0x4
  KIND_DIRECT_IFACE = 1 << 5
  KIND_GCPROG       = 1 << 6 # Type.gc points to GC program
  KIND_MASK         = (1 << 5) - 1

  @staticmethod
  def createJebStructure(typeManager, ptrSize):
    primitiveTypeManager =  typeManager.getPrimitives()
    if typeManager.getType(Rtype.JEB_NAME):
      return None
    else:
      jebType = typeManager.createStructure(Rtype.JEB_NAME)
      typeManager.addStructureField(jebType, 'size', primitiveTypeManager.getExactIntegerBySize(ptrSize, False))
      typeManager.addStructureField(jebType, 'ptrdata', primitiveTypeManager.getExactIntegerBySize(ptrSize, False))
      typeManager.addStructureField(jebType, 'hash', primitiveTypeManager.getExactIntegerBySize(4, False))
      typeManager.addStructureField(jebType, 'tflag', primitiveTypeManager.getExactIntegerBySize(1, False))
      typeManager.addStructureField(jebType, 'align', primitiveTypeManager.getExactIntegerBySize(1, False))
      typeManager.addStructureField(jebType, 'fieldAlign', primitiveTypeManager.getExactIntegerBySize(1, False))
      typeManager.addStructureField(jebType, 'kind', primitiveTypeManager.getExactIntegerBySize(1, False))
      typeManager.addStructureField(jebType, 'alg', typeManager.getType('void*'))
      typeManager.addStructureField(jebType, 'gcdata', typeManager.getType('void*'))
      typeManager.addStructureField(jebType, 'str', primitiveTypeManager.getExactIntegerBySize(4, False))
      typeManager.addStructureField(jebType, 'ptrToThis', primitiveTypeManager.getExactIntegerBySize(4, False))
      return jebType

  def __init__(self, typesBuilder, startAddr):
    self.typesBuilder = typesBuilder
    self.codeUnit = typesBuilder.codeUnit
    self.typeManager = typesBuilder.typeManager
    self.memory = typesBuilder.memory
    self.ptrSize = typesBuilder.ptrSize
    self.startAddr = startAddr & 0xFFFFFFFF
    self.typesAddr = typesBuilder.curModuleData.types
    self.mySize = 0x20 if self.ptrSize == 4 else 0x30

  def applyJebStructure(self):
    self.name.applyJebStructure()
    # rest of struct application will be done by the wrapping type

  def parse(self):
    curAddress = self.startAddr
    self.size, curAddress = readPtr(self.memory, self.ptrSize, curAddress)
    self.ptrdata, curAddress = readPtr(self.memory, self.ptrSize, curAddress)
    self.hash = self.memory.readInt(curAddress) & 0xFFFFFFFF # always int32
    curAddress+=4
    self.tflag = self.memory.readByte(curAddress)
    curAddress+=1
    self.align = self.memory.readByte(curAddress)
    curAddress+=1
    self.fieldAlign = self.memory.readByte(curAddress)
    curAddress+=1
    self.kind = self.memory.readByte(curAddress) & self.KIND_MASK
    curAddress+=1
    self.alg, curAddress = readPtr(self.memory, self.ptrSize, curAddress)
    self.gcdata, curAddress = readPtr(self.memory, self.ptrSize, curAddress)

    nameOff = self.memory.readInt(curAddress) & 0xFFFFFFFF # always int32
    self.name = Name(self.typesAddr + nameOff, self)
    self.name.parse(self.extraStar())

    curAddress+=4

    ptrToThisOff = self.memory.readInt(curAddress) & 0xFFFFFFFF # always int32
    if ptrToThisOff != 0:
      typeAddr = (self.typesAddr + ptrToThisOff) & 0xFFFFFFFF
      self.ptrToThis = self.typesBuilder.parseType(typeAddr)

  def getKind(self):
    global TYPE_KINDS
    return TYPE_KINDS[self.kind]

  def extraStar(self):
    return self.tflag & self.TFLAG_EXTRASTAR != 0

  def isNamed(self):
    return self.tflag & self.TFLAG_NAMED != 0

  def isUncommon(self):
    return self.tflag & self.TFLAG_UNCOMMON != 0

  def getSimpleName(self):
    return self.name.getSimpleName()

  def __str__(self):
    tflags = []
    if self.tflag & self.TFLAG_UNCOMMON:
      tflags.append('TFLAG_UNCOMMON')
    if self.tflag & self.TFLAG_EXTRASTAR:
      tflags.append('TFLAG_EXTRASTAR')
    if self.tflag & self.TFLAG_NAMED:
      tflags.append('TFLAG_NAMED')
    tflagsStr = ' & '.join(tflags)

    return 'kind: %s - name: %s - size: %x - align: %d - fieldAlign: %d - tflag: %s' % (self.getKind(), self.name, self.size, self.align, self.fieldAlign, tflagsStr)

class StructField():
  '''
    Reference: src\\reflect\\type.go

    type structField struct {
      name        name    // name is always non-empty
      typ         *rtype  // type of field
      offsetEmbed uintptr // byte offset of field<<1 | isEmbedded
    }
  '''
  JEB_NAME = 'StructField'

  @staticmethod
  def createJebStructure(typeManager, ptrSize):
    primitiveTypeManager =  typeManager.getPrimitives()
    if typeManager.getType(StructField.JEB_NAME):
      return None
    else:
      jebType = typeManager.createStructure(StructField.JEB_NAME)
      typeManager.addStructureField(jebType, 'name', typeManager.getType('void*'))
      typeManager.addStructureField(jebType, 'typ', typeManager.getType('%s*' % Rtype.JEB_NAME))
      typeManager.addStructureField(jebType, 'offsetEmbed', primitiveTypeManager.getExactIntegerBySize(ptrSize, False))
      return jebType

  def __init__(self, typesBuilder, startAddr):
    self.typesBuilder = typesBuilder
    self.ptrSize = typesBuilder.ptrSize
    self.memory = typesBuilder.memory
    self.codeUnit = typesBuilder.golangAnalyzer.codeUnit
    self.typeManager = typesBuilder.typeManager
    self.startAddr = startAddr
    self.typesStartAddr = typesBuilder.curModuleData.types
    self.name = None
    self.typ = None
    self.offset = 0
    self.isEmbedded = None
    self.mySize = 3 * self.ptrSize

  def applyJebStructure(self):
    self.codeUnit.setDataAt(self.startAddr, self.typeManager.getType(StructField.JEB_NAME), self.getSimpleName())
    self.name.applyJebStructure()
    
  def parse(self):
    nameAddr, curAddr = readPtr(self.memory, self.ptrSize, self.startAddr)
    if nameAddr == 0:
      raise Exception('empty name when parsing StructField')
    self.name = Name(nameAddr, self)
    self.name.parse(False)

    self.typAddr, curAddr = readPtr(self.memory, self.ptrSize, curAddr)
    if self.typAddr == 0:
      raise Exception('undefined type when parsing StructField')
    self.typ = self.typesBuilder.parseType(self.typAddr)

    offsetEmbed, curAddr = readPtr(self.memory, self.ptrSize, curAddr)
    self.offset = offsetEmbed >> 1
    self.isEmbedded = (offsetEmbed & 1) != 0

  def __str__(self):
    return '%s %s (offset:%x%s)' % (self.typ.getSimpleName(), self.name.getSimpleName(), self.offset, ', tag:\'%s\'' % self.name.tag if self.name.tag else '')

  def getSimpleName(self):
    return 'struct_field:%s' % self.name.getSimpleName()

class StructType():
  '''
    Reference: src\\reflect\\type.go

    type structType struct {
      rtype
      pkgPath name          // !! pointer
      fields  []structField // sorted by offset
    }
  '''
  JEB_NAME = 'StructType'

  @staticmethod
  def createJebStructure(typeManager, ptrSize):
    primitiveTypeManager =  typeManager.getPrimitives()
    if typeManager.getType(StructType.JEB_NAME):
      return None
    else:
      jebType = typeManager.createStructure(StructType.JEB_NAME)
      typeManager.addStructureField(jebType, 'rtype', typeManager.getType(Rtype.JEB_NAME))
      typeManager.addStructureField(jebType, 'pkgPath', typeManager.getType('void*'))
      typeManager.addStructureField(jebType, 'fields', typeManager.getType(SliceHeader.JEB_NAME))
      return jebType

  def __init__(self, typesBuilder, startAddr, rtype):
    self.typesBuilder = typesBuilder
    self.rtype = rtype 
    self.ptrSize = typesBuilder.ptrSize
    self.memory = typesBuilder.memory
    self.startAddr = startAddr
    self.typeManager = typesBuilder.typeManager
    self.codeUnit = self.typesBuilder.golangAnalyzer.codeUnit
    self.typesStartAddr = typesBuilder.curModuleData.types
    self.fields = list()
    self.pkgPath = None # not always set
    self.mySize = rtype.mySize + self.ptrSize + 3 * self.ptrSize

  def applyJebStructure(self):
    self.rtype.applyJebStructure()
    self.codeUnit.setDataAt(self.startAddr, self.typeManager.getType(StructType.JEB_NAME), self.getSimpleName())
    for field in self.fields:
      field.applyJebStructure()
    if self.pkgPath != None:
      self.pkgPath.applyJebStructure()

  def parse(self):
    pkgPathAddr, curAddr = readPtr(self.memory, self.ptrSize, self.startAddr + self.rtype.mySize)
    if pkgPathAddr != 0:
      self.pkgPath = Name(pkgPathAddr, self)
      self.pkgPath.parse(False)

    # fields parsing
    fieldsHeader = SliceHeader(curAddr, self.memory, self.ptrSize)
    fieldsHeader.parse()
    curAddr = fieldsHeader.data
    while len(self.fields) < fieldsHeader._len:
      field = StructField(self.typesBuilder, curAddr)
      field.parse()
      self.fields.append(field)
      curAddr += field.mySize

  def __str__(self):
    structStr = '> struct %s (%d fields):\n' % (self.rtype.getSimpleName(), len(self.fields))
    for field in self.fields:
      structStr+= '\t\t- %s\n' % field
    return structStr

  def getSimpleName(self):
    return 'struct:%s' % self.rtype.getSimpleName()

class FuncType():
  '''
    Reference: src\\reflect\\type.go

    type funcType struct {
      rtype
      inCount  uint16
      outCount uint16 // top bit is set if last input parameter is ...
      
      padding  uint32 // ! only on some architectures (e.g. x64)
    }

    Note: "A *rtype for each in and out parameter is stored in an array that
    directly follows the funcType (and possibly its uncommonType)."
  '''
  JEB_NAME = 'FuncType'
  VARIADIC_FLAG = 0x8000

  @staticmethod
  def createJebStructure(typeManager, ptrSize):
    primitiveTypeManager =  typeManager.getPrimitives()
    if typeManager.getType(FuncType.JEB_NAME):
      return None
    else:
      jebType = typeManager.createStructure(FuncType.JEB_NAME)
      typeManager.addStructureField(jebType, 'rtype', typeManager.getType(Rtype.JEB_NAME))
      typeManager.addStructureField(jebType, 'inCount', primitiveTypeManager.getExactIntegerBySize(2, False))
      typeManager.addStructureField(jebType, 'outCount', primitiveTypeManager.getExactIntegerBySize(2, False))
      return jebType

  def __init__(self, typesBuilder, startAddr, rtype):
    self.typesBuilder = typesBuilder
    self.rtype = rtype 
    self.ptrSize = typesBuilder.ptrSize
    self.memory = typesBuilder.memory
    self.startAddr = startAddr
    self.typeManager = typesBuilder.typeManager
    self.codeUnit = self.typesBuilder.golangAnalyzer.codeUnit
    self.typesStartAddr = typesBuilder.curModuleData.types
    self.inCount = 0
    self.outCount = 0
    self.isVariadic = False
    self.padding = -1
    self.inParameterTypes = list()
    self.inParameterTypesAddr = list() # for renaming
    self.outParameterTypes = list()
    self.outParameterTypesAddr = list() # for renaming
    self.mySize = rtype.mySize + 2 * 2 # !! without padding

  def applyJebStructure(self):
    self.rtype.applyJebStructure()
    self.codeUnit.setDataAt(self.startAddr, self.typeManager.getType(FuncType.JEB_NAME), self.getSimpleName())
    for i in range(len(self.inParameterTypesAddr)):
      self.codeUnit.setDataAt(self.inParameterTypesAddr[i], self.typeManager.getType('void*'), 'arg%d_' % i + self.getSimpleName())
    for i in range(len(self.outParameterTypesAddr)):
      self.codeUnit.setDataAt(self.outParameterTypesAddr[i], self.typeManager.getType('void*'), 'ret%d_' % i + self.getSimpleName())
    
  def parse(self):
    curAddr = self.startAddr + self.rtype.mySize
    self.inCount = self.memory.readShort(curAddr) & 0xFFFF
    curAddr+=2
    self.outCount = self.memory.readShort(curAddr) & 0xFFFF
    if self.outCount & FuncType.VARIADIC_FLAG:
      self.isVariadic = True
      self.outCount = self.outCount & 0x7FFF
    curAddr+=2
    self.padding = self.memory.readInt(curAddr) & 0xFFFFFFFF
    if self.padding == 0: # skip padding if present
      self.mySize += 4
      curAddr+=4
     
    # parse series of *rtype corresponding to in and out parameters
    if self.rtype.isUncommon():
      curAddr += UncommonType.SIZE

    for i in range(self.inCount):
      self.inParameterTypesAddr.append(curAddr)
      paramTypeAddr, curAddr = readPtr(self.memory, self.ptrSize, curAddr)
      self.inParameterTypes.append(self.typesBuilder.parseType(paramTypeAddr))

    for i in range(self.outCount):
      self.outParameterTypesAddr.append(curAddr)
      paramTypeAddr, curAddr = readPtr(self.memory, self.ptrSize, curAddr)
      self.outParameterTypes.append(self.typesBuilder.parseType(paramTypeAddr))

  def __str__(self):
    return '> func %s (#in:%d %s - out:%d):\n' % (self.rtype.getSimpleName(), self.inCount, '+ [...]' if self.isVariadic else '', self.outCount)

  def getSimpleName(self):
    return 'func:%s' % self.rtype.getSimpleName()

class UncommonType():
  '''
    Wrapper around primaryType to access uncommon type:

    type uncommonType struct {
      pkgPath nameOff // import path; empty for built-in types like int, string
      mcount  uint16  // number of methods
      xcount  uint16  // number of exported methods
      moff    uint32  // offset from this uncommontype to [mcount]method
      _       uint32  // unused
    }
  '''
  JEB_NAME = 'UncommonType'
  SIZE = 16 # fixed

  @staticmethod
  def createJebStructure(typeManager, ptrSize):
    primitiveTypeManager =  typeManager.getPrimitives()
    if typeManager.getType(UncommonType.JEB_NAME):
      return None
    else:
      jebType = typeManager.createStructure(UncommonType.JEB_NAME)
      typeManager.addStructureField(jebType, 'pkgPath', primitiveTypeManager.getExactIntegerBySize(4, False))
      typeManager.addStructureField(jebType, 'mcount', primitiveTypeManager.getExactIntegerBySize(2, False))
      typeManager.addStructureField(jebType, 'xcount', primitiveTypeManager.getExactIntegerBySize(2, False))
      typeManager.addStructureField(jebType, 'moff', primitiveTypeManager.getExactIntegerBySize(4, False))
      typeManager.addStructureField(jebType, '_', primitiveTypeManager.getExactIntegerBySize(4, False))
      return jebType

  def __init__(self, typesBuilder, primaryType):
    self.typesBuilder = typesBuilder
    self.primaryType = primaryType 
    self.startAddr = primaryType.startAddr
    self.uncommonTypeStartAddr = primaryType.startAddr + primaryType.mySize
    self.typesAddr = typesBuilder.curModuleData.types
    self.rtype = primaryType.rtype 
    self.ptrSize = typesBuilder.ptrSize
    self.memory = typesBuilder.memory
    self.codeUnit = typesBuilder.golangAnalyzer.codeUnit
    self.typeManager = typesBuilder.typeManager
    self.methods = list()
    self.pkgPath = None
    self.mySize = UncommonType.SIZE

  def applyJebStructure(self):
    self.primaryType.applyJebStructure()
    self.codeUnit.setDataAt(self.uncommonTypeStartAddr, self.typeManager.getType(UncommonType.JEB_NAME), 'uncommon_' + self.getSimpleName())
    for method in self.methods:
      method.applyJebStructure()
    if self.pkgPath != None:
      self.pkgPath.applyJebStructure()

  def parse(self):
    curAddr = self.uncommonTypeStartAddr
    pkgPathOff = self.memory.readInt(curAddr) & 0xFFFFFFFF # always int32
    curAddr += 4
    if pkgPathOff != 0:
      self.pkgPath = Name(self.typesAddr + pkgPathOff, self)
      self.pkgPath.parse(False)

    self.mcount = self.memory.readShort(curAddr) & 0xFFFF
    curAddr+=2
    self.xcount = self.memory.readShort(curAddr) & 0xFFFF
    curAddr+=2
    self.moff = self.memory.readInt(curAddr) & 0xFFFFFFFF
    curAddr+=4
    self.unused = self.memory.readInt(curAddr) & 0xFFFFFFFF
    curAddr+=4

    # parse methods
    curAddr = (self.uncommonTypeStartAddr + self.moff) & 0xFFFFFFFF
    for i in range(self.mcount):
      method = MethodType(self.typesBuilder, curAddr)
      method.parse()
      self.methods.append(method)
      curAddr += method.mySize

  def __str__(self):
    uncommonStr = '%s' % self.primaryType
    if self.mcount != 0:
      uncommonStr += '\n\t\t> %d methods:\n' % self.mcount
      for method in self.methods:
        uncommonStr += '\t\t - %s\n' % method.getSimpleName()
    return uncommonStr

  def getSimpleName(self):
    return self.primaryType.getSimpleName()

class RawType():
  '''
    Wrapper for built-in types (contains only rtype)
  '''
  JEB_NAME = 'Rtype'

  def __init__(self, typesBuilder, startAddr, rtype):
    self.typesBuilder = typesBuilder
    self.rtype = rtype 
    self.startAddr = startAddr
    self.mySize = self.rtype.mySize
    self.typeManager = typesBuilder.typeManager
    self.codeUnit = self.typesBuilder.golangAnalyzer.codeUnit

  def applyJebStructure(self):
    self.rtype.applyJebStructure()
    self.codeUnit.setDataAt(self.startAddr, self.typeManager.getType(RawType.JEB_NAME), self.getSimpleName())

  def __str__(self):
    return '> raw type: %s\n' % self.rtype.getSimpleName()

  def getSimpleName(self):
    return 'raw_type:%s' % self.rtype.getSimpleName()

class PtrType():
  '''
    Reference: src\\reflect\\type.go

    type ptrType struct {
      rtype
      elem *rtype // pointer element (pointed at) type
    }
  '''
  JEB_NAME = 'PtrType'

  @staticmethod
  def createJebStructure(typeManager, ptrSize):
    primitiveTypeManager =  typeManager.getPrimitives()
    if typeManager.getType(PtrType.JEB_NAME):
      return None
    else:
      jebType = typeManager.createStructure(PtrType.JEB_NAME)
      typeManager.addStructureField(jebType, 'rtype', typeManager.getType(Rtype.JEB_NAME))
      typeManager.addStructureField(jebType, 'elem', typeManager.getType('%s*' % Rtype.JEB_NAME))
      return jebType

  def __init__(self, typesBuilder, startAddr, rtype):
    self.typesBuilder = typesBuilder
    self.rtype = rtype 
    self.ptrSize = typesBuilder.ptrSize
    self.memory = typesBuilder.memory
    self.startAddr = startAddr
    self.codeUnit = self.typesBuilder.golangAnalyzer.codeUnit
    self.typeManager = typesBuilder.typeManager
    self.mySize = rtype.mySize + self.ptrSize

  def applyJebStructure(self):
    self.rtype.applyJebStructure()
    self.codeUnit.setDataAt(self.startAddr, self.typeManager.getType(PtrType.JEB_NAME), self.getSimpleName())

  def parse(self):
    pointedTypeAddr, curAddress = readPtr(self.memory, self.ptrSize, self.startAddr + self.rtype.mySize)
    self.pointedType = self.typesBuilder.parseType(pointedTypeAddr)

  def __str__(self):
    return 'Ptr to %s' % self.pointedType.getSimpleName()

  def getSimpleName(self):
    return 'ptr:*%s' % self.pointedType.getSimpleName()

class ArrayType():
  '''
    Reference: src\\reflect\\type.go

    type arrayType struct {
      rtype
      elem  *rtype // array element type
      slice *rtype // slice type
      len   uintptr
    }
  '''
  JEB_NAME = 'ArrayType'

  @staticmethod
  def createJebStructure(typeManager, ptrSize):
    primitiveTypeManager =  typeManager.getPrimitives()
    if typeManager.getType(ArrayType.JEB_NAME):
      return None
    else:
      jebType = typeManager.createStructure(ArrayType.JEB_NAME)
      typeManager.addStructureField(jebType, 'rtype', typeManager.getType(Rtype.JEB_NAME))
      typeManager.addStructureField(jebType, 'elem', typeManager.getType('%s*' % Rtype.JEB_NAME))
      typeManager.addStructureField(jebType, 'slice', typeManager.getType('%s*' % Rtype.JEB_NAME))
      typeManager.addStructureField(jebType, 'len', primitiveTypeManager.getExactIntegerBySize(ptrSize, False))
      return jebType

  def __init__(self, typesBuilder, startAddr, rtype):
    self.typesBuilder = typesBuilder
    self.rtype = rtype 
    self.ptrSize = typesBuilder.ptrSize
    self.memory = typesBuilder.memory
    self.startAddr = startAddr
    self.codeUnit = self.typesBuilder.golangAnalyzer.codeUnit
    self.typeManager = typesBuilder.typeManager
    self.mySize = rtype.mySize + 3 * self.ptrSize

  def applyJebStructure(self):
    self.rtype.applyJebStructure()
    self.codeUnit.setDataAt(self.startAddr, self.typeManager.getType(ArrayType.JEB_NAME), self.getSimpleName())

  def parse(self):
    self.elemTypeAddr, curAddress = readPtr(self.memory, self.ptrSize, self.startAddr + self.rtype.mySize)
    self.elemType = self.typesBuilder.parseType(self.elemTypeAddr)

    sliceTypeAddr, curAddress = readPtr(self.memory, self.ptrSize, curAddress)
    self.sliceType = self.typesBuilder.parseType(sliceTypeAddr)

    self.length, curAddress = readPtr(self.memory, self.ptrSize, curAddress)

  def __str__(self):
    return '> array %s (element type:%s - length:%d)\n' % (self.rtype.getSimpleName(), self.elemType.getSimpleName(), self.length)

  def getSimpleName(self):
    return 'array:%s' % (self.rtype.getSimpleName())

class InterfaceType():
  '''
    Reference: src\\reflect\\type.go

    type interfaceType struct {
      rtype
      pkgPath name      // import path
      methods []imethod // sorted by hash
    }
  '''
  JEB_NAME = 'InterfaceType'

  @staticmethod
  def createJebStructure(typeManager, ptrSize):
    primitiveTypeManager =  typeManager.getPrimitives()
    if typeManager.getType(InterfaceType.JEB_NAME):
      return None
    else:
      jebType = typeManager.createStructure(InterfaceType.JEB_NAME)
      typeManager.addStructureField(jebType, 'rtype', typeManager.getType(Rtype.JEB_NAME))
      typeManager.addStructureField(jebType, 'pkgPath', typeManager.getType('void*'))
      typeManager.addStructureField(jebType, 'methods', typeManager.getType(SliceHeader.JEB_NAME))
      return jebType

  def __init__(self, typesBuilder, startAddr, rtype):
    self.typesBuilder = typesBuilder
    self.rtype = rtype 
    self.ptrSize = typesBuilder.ptrSize
    self.memory = typesBuilder.memory
    self.startAddr = startAddr
    self.methods = list()
    self.pkgPath = None
    self.codeUnit = typesBuilder.golangAnalyzer.codeUnit
    self.typeManager = typesBuilder.typeManager
    self.mySize = rtype.mySize + self.ptrSize + 3 * self.ptrSize

  def applyJebStructure(self):
    self.rtype.applyJebStructure()
    self.codeUnit.setDataAt(self.startAddr, self.typeManager.getType(InterfaceType.JEB_NAME), self.getSimpleName())
    for method in self.methods:
      method.applyJebStructure()
    if self.pkgPath != None:
      self.pkgPath.applyJebStructure()

  def parse(self):
    pkgPathAddr, curAddr = readPtr(self.memory, self.ptrSize, self.startAddr + self.rtype.mySize)
    if pkgPathAddr != 0:
      self.pkgPath = Name(pkgPathAddr, self)
      self.pkgPath.parse(False)

    methodsHeader = SliceHeader(curAddr, self.memory, self.ptrSize)
    methodsHeader.parse()
    curAddr = methodsHeader.data
    while len(self.methods) < methodsHeader._len:
      method = IMethodType(self.typesBuilder, curAddr)
      method.parse()
      self.methods.append(method)
      curAddr += method.mySize

  def __str__(self):
    interfaceDesc = '> interface %s (%d methods):\n' % (self.rtype.getSimpleName(), len(self.methods))
    for method in self.methods:
      interfaceDesc += '\t\t- %s\n' % method
    return interfaceDesc

  def getSimpleName(self):
    return 'interface:%s' % self.rtype.getSimpleName()

class IMethodType():
  '''
    Represents a method on an interface type
    Reference: src\\reflect\\type.go

    type imethod struct {
      name nameOff // name of method
      typ  typeOff // .(*FuncType) underneath
    }
  '''
  JEB_NAME = 'IMethodType'

  @staticmethod
  def createJebStructure(typeManager, ptrSize):
    primitiveTypeManager =  typeManager.getPrimitives()
    if typeManager.getType(IMethodType.JEB_NAME):
      return None
    else:
      jebType = typeManager.createStructure(IMethodType.JEB_NAME)
      typeManager.addStructureField(jebType, 'name', primitiveTypeManager.getExactIntegerBySize(4, False))
      typeManager.addStructureField(jebType, 'typ', primitiveTypeManager.getExactIntegerBySize(4, False))
      return jebType

  def __init__(self, typesBuilder, startAddr):
    self.typesBuilder = typesBuilder 
    self.ptrSize = typesBuilder.ptrSize
    self.memory = typesBuilder.memory
    self.startAddr = startAddr
    self.typesAddr = typesBuilder.curModuleData.types
    self.mySize = 2 * 4 # fixed
    self.codeUnit = typesBuilder.golangAnalyzer.codeUnit
    self.typeManager = typesBuilder.typeManager

  def applyJebStructure(self):
    self.codeUnit.setDataAt(self.startAddr, self.typeManager.getType(IMethodType.JEB_NAME), self.getSimpleName())
    self.name.applyJebStructure()
   
  def parse(self):
    curAddress = self.startAddr
    nameOff = self.memory.readInt(curAddress) & 0xFFFFFFFF # always int32
    curAddress += 4
    self.name = Name(self.typesAddr + nameOff, self)
    self.name.parse(False)

    typeOffset = self.memory.readInt(curAddress) # always int32
    typeAddr = (self.typesAddr + typeOffset) & 0xFFFFFFFF
    self.type = self.typesBuilder.parseType(typeAddr)

  def __str__(self):
    return '%s' % self.name.getSimpleName()

  def getSimpleName(self):
    return 'interface_method:%s' % self.name.getSimpleName()

class SliceType():
  '''
    Reference: src\\reflect\\type.go

    type sliceType struct {
      rtype
      elem *rtype // slice element type
    }
  '''
  JEB_NAME = 'SliceType'

  @staticmethod
  def createJebStructure(typeManager, ptrSize):
    primitiveTypeManager =  typeManager.getPrimitives()
    if typeManager.getType(SliceType.JEB_NAME):
      return None
    else:
      jebType = typeManager.createStructure(SliceType.JEB_NAME)
      typeManager.addStructureField(jebType, 'rtype', typeManager.getType(Rtype.JEB_NAME))
      typeManager.addStructureField(jebType, 'elem', typeManager.getType('%s*' % Rtype.JEB_NAME))
      return jebType

  def __init__(self, typesBuilder, startAddr, rtype):
    self.typesBuilder = typesBuilder
    self.rtype = rtype
    self.ptrSize = typesBuilder.ptrSize
    self.memory = typesBuilder.memory
    self.startAddr = startAddr
    self.codeUnit = typesBuilder.golangAnalyzer.codeUnit
    self.typeManager = typesBuilder.typeManager
    self.mySize = rtype.mySize + self.ptrSize

  def applyJebStructure(self):
    self.rtype.applyJebStructure()
    self.codeUnit.setDataAt(self.startAddr, self.typeManager.getType(SliceType.JEB_NAME), self.getSimpleName())

  def parse(self):
    self.elemTypeAddr, curAddress = readPtr(self.memory, self.ptrSize, self.startAddr + self.rtype.mySize)
    self.elemType = self.typesBuilder.parseType(self.elemTypeAddr)

  def __str__(self):
    return '> slice %s (element type:%s)\n' % (self.rtype.getSimpleName(), self.elemType.getSimpleName())

  def getSimpleName(self):
    return 'slice:%s' % self.rtype.getSimpleName()

class MethodType():
  '''
    Method on non-interface type
  
    Reference: src\\reflect\\type.go

    type method struct {
      name nameOff // name of method
      mtyp typeOff // method type (without receiver) // offset to an *rtype
      ifn  textOff // fn used in interface call (one-word receiver) // offset from top of text section
      tfn  textOff // fn used for normal method call // offset from top of text section
    }
  '''
  JEB_NAME = 'MethodType'

  @staticmethod
  def createJebStructure(typeManager, ptrSize):
    primitiveTypeManager =  typeManager.getPrimitives()
    if typeManager.getType(MethodType.JEB_NAME):
      return None
    else:
      jebType = typeManager.createStructure(MethodType.JEB_NAME)
      typeManager.addStructureField(jebType, 'name', primitiveTypeManager.getExactIntegerBySize(4, False))
      typeManager.addStructureField(jebType, 'mtyp', primitiveTypeManager.getExactIntegerBySize(4, False))
      typeManager.addStructureField(jebType, 'ifn', primitiveTypeManager.getExactIntegerBySize(4, False))
      typeManager.addStructureField(jebType, 'tfn', primitiveTypeManager.getExactIntegerBySize(4, False))
      return jebType

  def __init__(self, typesBuilder, startAddr):
    self.typesBuilder = typesBuilder
    self.ptrSize = typesBuilder.ptrSize
    self.memory = typesBuilder.memory
    self.startAddr = startAddr
    self.codeUnit = typesBuilder.golangAnalyzer.codeUnit
    self.typeManager = typesBuilder.typeManager
    self.commentManager = typesBuilder.golangAnalyzer.codeUnit.getCodeModel().getCommentManager()
    self.typesAddr = typesBuilder.curModuleData.types
    self.textStartAddr = typesBuilder.curModuleData.text
    self.name = None
    self.mtyp = None
    self.ifn = 0
    self.tfn = 0
    self.mySize = 4 * 4

  def parse(self):
    curAddress = self.startAddr
    nameOff = self.memory.readInt(curAddress) & 0xFFFFFFFF # always int32
    curAddress += 4
    self.name = Name(self.typesAddr + nameOff, self)
    self.name.parse(False)

    # note: some methods are actually not present in the binary
    # for those, typeOff, ifn, tfn are 0
    typeOff = self.memory.readInt(curAddress) & 0xFFFFFFFF # always int32
    curAddress += 4
    if typeOff != 0: 
      typeAddr = (self.typesAddr + typeOff) & 0xFFFFFFFF
      self.mtyp = self.typesBuilder.parseType(typeAddr)

    self.ifn = self.memory.readInt(curAddress) & 0xFFFFFFFF # always int32
    curAddress += 4
    self.tfn = self.memory.readInt(curAddress) & 0xFFFFFFFF # always int32

    # provide types to corresponding routines, as comments for now
    if self.ifn != 0 and self.mtyp:
      ifnRtn = (self.ifn + self.textStartAddr) & 0xFFFFFFFF
      if self.codeUnit.getInternalMethod(ifnRtn, True):
        self.commentManager.setComment(ifnRtn, 'Go function type: %s' % self.mtyp.getSimpleName())
    if self.tfn != 0 and self.tfn != self.ifn and self.mtyp:
      tfnRtn = (self.tfn + self.textStartAddr) & 0xFFFFFFFF
      if self.codeUnit.getInternalMethod(tfnRtn, True):
        self.commentManager.setComment(tfnRtn, 'Go function type: %s' % self.mtyp.getSimpleName())

  def applyJebStructure(self):
    self.codeUnit.setDataAt(self.startAddr, self.typeManager.getType(MethodType.JEB_NAME), self.getSimpleName())
    
  def getSimpleName(self):
    return 'method:%s' % self.name.getSimpleName()

class ChanType():
  '''
    Reference: src\\reflect\\type.go

    type chanType struct {
      rtype
      elem *rtype  // channel element type
      dir  uintptr // channel direction (ChanDir)
    }
  '''

  JEB_NAME = 'ChanType'

  @staticmethod
  def createJebStructure(typeManager, ptrSize):
    primitiveTypeManager =  typeManager.getPrimitives()
    if typeManager.getType(ChanType.JEB_NAME):
      return None
    else:
      jebType = typeManager.createStructure(ChanType.JEB_NAME)
      typeManager.addStructureField(jebType, 'rtype', typeManager.getType(Rtype.JEB_NAME))
      typeManager.addStructureField(jebType, 'elem', typeManager.getType('%s*' % Rtype.JEB_NAME))
      typeManager.addStructureField(jebType, 'dir', primitiveTypeManager.getExactIntegerBySize(ptrSize, False))
      return jebType

  def __init__(self, typesBuilder, startAddr, rtype):
    self.typesBuilder = typesBuilder
    self.rtype = rtype 
    self.ptrSize = typesBuilder.ptrSize
    self.memory = typesBuilder.memory
    self.startAddr = startAddr
    self.typeManager = typesBuilder.typeManager
    self.codeUnit = self.typesBuilder.golangAnalyzer.codeUnit
    self.typesStartAddr = typesBuilder.curModuleData.types
    self.mySize = rtype.mySize + self.ptrSize + self.ptrSize

  def applyJebStructure(self):
    self.rtype.applyJebStructure()
    self.codeUnit.setDataAt(self.startAddr, self.typeManager.getType(ChanType.JEB_NAME), self.getSimpleName())
  
  def parse(self):
    elemTypeAddr, curAddress = readPtr(self.memory, self.ptrSize, self.startAddr + self.rtype.mySize)
    self.elem = self.typesBuilder.parseType(elemTypeAddr)
    self.dir, curAddress = readPtr(self.memory, self.ptrSize, curAddress)

  def __str__(self):
    return '> chan %s - element type:%s - direction: %s\n' % (self.rtype.getSimpleName(), self.elem.getSimpleName(), self.getDirection())

  def getSimpleName(self):
    return 'channel:%s (direction:%s)' % (self.rtype.getSimpleName(), self.getDirection())

  def getDirection(self):
    RECV_DIR = 1
    SEND_DIR = 2
    BOTH_DIR = 3
    if self.dir == RECV_DIR:
      return 'recv'
    elif self.dir == SEND_DIR:
      return 'send'
    else:
      return 'both'

class MapType():
  '''
    Reference: src\\reflect\\type.go

    type mapType struct {
      rtype
      key        *rtype // map key type
      elem       *rtype // map element (value) type
      bucket     *rtype // internal bucket structure
      keysize    uint8  // size of key slot
      valuesize  uint8  // size of value slot
      bucketsize uint16 // size of bucket
      flags      uint32
    }
  '''
  JEB_NAME = 'MapType'

  @staticmethod
  def createJebStructure(typeManager, ptrSize):
    primitiveTypeManager =  typeManager.getPrimitives()
    if typeManager.getType(MapType.JEB_NAME):
      return None
    else:
      jebType = typeManager.createStructure(MapType.JEB_NAME)
      typeManager.addStructureField(jebType, 'rtype', typeManager.getType(Rtype.JEB_NAME))
      typeManager.addStructureField(jebType, 'key', typeManager.getType('%s*' % Rtype.JEB_NAME))
      typeManager.addStructureField(jebType, 'elem', typeManager.getType('%s*' % Rtype.JEB_NAME))
      typeManager.addStructureField(jebType, 'bucket', typeManager.getType('%s*' % Rtype.JEB_NAME))
      typeManager.addStructureField(jebType, 'keysize', primitiveTypeManager.getExactIntegerBySize(1, False))
      typeManager.addStructureField(jebType, 'valuesize', primitiveTypeManager.getExactIntegerBySize(1, False))
      typeManager.addStructureField(jebType, 'bucketsize', primitiveTypeManager.getExactIntegerBySize(2, False))
      typeManager.addStructureField(jebType, 'flags', primitiveTypeManager.getExactIntegerBySize(4, False))
      return jebType

  def __init__(self, typesBuilder, startAddr, rtype):
    self.typesBuilder = typesBuilder
    self.rtype = rtype 
    self.ptrSize = typesBuilder.ptrSize
    self.memory = typesBuilder.memory
    self.startAddr = startAddr
    self.typeManager = typesBuilder.typeManager
    self.codeUnit = self.typesBuilder.golangAnalyzer.codeUnit
    self.typesStartAddr = typesBuilder.curModuleData.types
    self.mySize = rtype.mySize + 3 * self.ptrSize + 1 + 1 + 2 + 4
  
  def applyJebStructure(self):
    self.rtype.applyJebStructure()
    self.codeUnit.setDataAt(self.startAddr, self.typeManager.getType(MapType.JEB_NAME), self.getSimpleName())
  
  def parse(self):
    keyTypeAddr, curAddress = readPtr(self.memory, self.ptrSize, self.startAddr + self.rtype.mySize)
    self.key = self.typesBuilder.parseType(keyTypeAddr)
    elemTypeAddr, curAddress = readPtr(self.memory, self.ptrSize, curAddress)
    self.elem = self.typesBuilder.parseType(elemTypeAddr)
    bucketTypeAddr, curAddress = readPtr(self.memory, self.ptrSize, curAddress)
    self.bucket = self.typesBuilder.parseType(bucketTypeAddr)
    self.keysize = self.memory.readByte(curAddress) & 0xFF
    curAddress+=1 
    self.valuesize = self.memory.readByte(curAddress) & 0xFF
    curAddress+=1
    self.bucketsize = self.memory.readShort(curAddress) & 0xFFFF
    curAddress+=2
    self.flags = self.memory.readInt(curAddress) & 0xFFFFFFFF

  def __str__(self):
    return '> map %s - key:%s - elem:%s\n' % (self.rtype.getSimpleName(), self.key.getSimpleName(), self.elem.getSimpleName())

  def getSimpleName(self):
    return 'map:%s' % (self.rtype.getSimpleName())


class Itab():
  '''
    Reference: src\\runtime\\runtime2.go

    type itab struct {
      inter *interfacetype
      _type *_type
      hash  uint32 // copy of _type.hash. Used for type switches.
      _     [4]byte
      fun   [1]uintptr // variable sized. fun[0]==0 means _type does not implement inter.
    }
  '''
  JEB_NAME = 'Itab'

  @staticmethod
  def createJebStructure(typeManager, ptrSize):
    primitiveTypeManager =  typeManager.getPrimitives()
    if typeManager.getType(Itab.JEB_NAME):
      return None
    else:
      jebType = typeManager.createStructure(Itab.JEB_NAME)
      typeManager.addStructureField(jebType, 'inter', typeManager.getType('%s*' % InterfaceType.JEB_NAME))
      typeManager.addStructureField(jebType, '_type', typeManager.getType('%s*' % Rtype.JEB_NAME))
      typeManager.addStructureField(jebType, 'hash', primitiveTypeManager.getExactIntegerBySize(4, False))
      typeManager.addStructureField(jebType, '_', primitiveTypeManager.getExactIntegerBySize(4, False))
      typeManager.addStructureField(jebType, 'fun', typeManager.getType('void*'))
      return jebType

  def __init__(self, typesBuilder, startAddr):
    self.typesBuilder = typesBuilder
    self.ptrSize = typesBuilder.ptrSize
    self.memory = typesBuilder.memory
    self.startAddr = startAddr
    self.typeManager = typesBuilder.typeManager
    self.codeUnit = self.typesBuilder.golangAnalyzer.codeUnit
    self.typesStartAddr = typesBuilder.curModuleData.types
    self.inter = None
    self.type = None
    self.hash = 0
    self.fun = list()
    #self.mySize = 2 * self.ptrSize + 4 + 4 + 4 # !! actually last field is variable sized

  def applyJebStructure(self):
    self.codeUnit.setDataAt(self.startAddr, self.typeManager.getType(Itab.JEB_NAME), self.getSimpleName())
   
  def parse(self):
    curAddr = self.startAddr
    interAddr, curAddr = readPtr(self.memory, self.ptrSize, curAddr)
    self.inter = self.typesBuilder.parseType(interAddr)

    typeAddr, curAddr = readPtr(self.memory, self.ptrSize, curAddr)
    self.type = self.typesBuilder.parseType(typeAddr)

    self.hash = self.memory.readInt(curAddr)
    curAddr+=4

    # skip unused field
    curAddr += 4

    # # parse func
    # FIXME: not sure how to properly parse here
    # curFuncAddr, curAddr = readPtr(self.memory, self.ptrSize, curAddr)
    # while curFuncAddr != 0:
    #   self.fun.append(curFuncAddr)
    #   curFuncAddr, curAddr = readPtr(self.memory, self.ptrSize, curAddr)

  def __str__(self):
    return '> itab: interface:%s - type:%s\n' % (self.inter.getSimpleName(), self.type.getSimpleName())

  def getSimpleName(self):
    return 'itab:%s,%s' % (self.type.getSimpleName(), self.inter.getSimpleName())

class Name():
  '''
    Reference: name struct in src/reflect/type.go
  '''
  def __init__(self, startAddr, containerType):
    self.containerType = containerType
    self.typesBuilder = self.containerType.typesBuilder
    self.typesAddr = containerType.typesBuilder.curModuleData.types
    self.memory = containerType.memory
    self.startAddr = startAddr
    self.isExported          = None
    self.isFollowedByTagData = None
    self.isFollowedByPkgPath = None
    self.data = None
    self.tag = None
    self.pkgName = None
    self.dataLength = 0

  def applyJebStructure(self):
    # no structure application (variable size)
    # create a dummy item with proper label
    self.containerType.typesBuilder.labelManager.setLabel(self.startAddr, 'name:' + self.getSimpleName(), True, True, False)
    if not self.containerType.codeUnit.getNativeItemAt(self.startAddr):
      self.containerType.codeUnit.setDataTypeAt(self.startAddr, self.containerType.typeManager.getPrimitives().getExactIntegerBySize(1, False))
    self.containerType.codeUnit.setStringAt(self.startAddr + 3, self.startAddr + 3 + self.dataLength, StringType.UTF8_NONZERO, 1, -1)

  def parse(self, extraStar):
    curAddr = self.startAddr
    firstByte = self.memory.readByte(curAddr) & 0xFF
    curAddr+=1

    self.isExported = firstByte & 0x1 != 0
    self.isFollowedByTagData = firstByte & 0x2 != 0
    self.isFollowedByPkgPath = firstByte & 0x4 != 0

    secondByte = self.memory.readByte(curAddr) & 0xFF
    curAddr+=1
    thirdByte = self.memory.readByte(curAddr) & 0xFF
    curAddr+=1

    self.dataLength = ((secondByte << 8) | thirdByte) & 0xFFFF
    self.data = JebUtils.readString(self.memory, curAddr, self.dataLength)
    if extraStar:
        if self.data[0] == '*':
          self.data = self.data[1:]
        else:
          raise Exception('extra star without star (%s)' % self)
    curAddr += self.dataLength

    if self.isFollowedByTagData:
      tagLen = ((self.memory.readByte(curAddr) & 0xFF) << 8) | (self.memory.readByte(curAddr + 1) & 0xFF)
      curAddr += 2
      self.tag = JebUtils.readString(self.memory, curAddr, tagLen)
      curAddr += tagLen

    if self.isFollowedByPkgPath:
      pkgNameOff = self.memory.readInt(curAddr) & 0xFFFFFFFF
      curAddr += 4
      self.pkgName = Name(self.typesAddr + pkgNameOff, self)
      self.pkgName.parse(False)

  def __str__(self):
    return '%s%s%s' % (self.data, ' - pkg:%s' % self.pkgName if self.pkgName else '', ' - tag:%s' % self.tag if self.tag else '')

  def getSimpleName(self):
    return '%s%s' % ('%s/' % self.pkgName if self.pkgName else '', self.data)
