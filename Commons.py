from com.pnfsoftware.jeb.core.units.codeobject import CodeObjectUnitUtil
from com.pnfsoftware.jeb.core.units import WellKnownUnitTypes
from com.pnfsoftware.jeb.core.units.code.asm.memory import MemoryException
from com.pnfsoftware.jeb.core.units.code.asm.items import INativeStringItem

import JebUtils

"""
Go-specific utils and structures.

(This file is part of JEB Decompiler's scripts used to analyze Golang executables.)
"""
def getModuleDataList(golangAnalyzer):
  '''
    Locate module data in memory and return *a list* of parsed ModuleData object, or None on failure.

    IMPORTANT: for now, the returned list contains only the *first* module data. 
    (see modulesinit() in src\\runtime\\symtab.go for cases where several modules might be present)
  '''
  firstModuleDataAddr = locateFirstModuleData(golangAnalyzer)
  if firstModuleDataAddr == -1:
    return None
  return buildModuleDataList(golangAnalyzer, firstModuleDataAddr)

def buildModuleDataList(golangAnalyzer, firstModuleDataAddr):
  # FIXME: iterate over all module data
  memory = golangAnalyzer.nativeCodeAnalyzer.getMemory()
  ptrSize = golangAnalyzer.pclntab.ptrSize
  firstMD = ModuleData(golangAnalyzer, firstModuleDataAddr)
  if firstMD:
    firstMD.parse()
    firstMD.applyJebStructure()
  return [firstMD]

def locateFirstModuleData(golangAnalyzer):
    '''
      Return address of first module data structure in memory, or -1 if it cannot be found.
    '''
    # non-stripped binary
    if CodeObjectUnitUtil.findSymbolByName(golangAnalyzer.codeContainerUnit, 'runtime.firstmoduledata') != None:
      firstModuleDataAddress = CodeObjectUnitUtil.findSymbolByName(golangAnalyzer.codeContainerUnit, 'runtime.firstmoduledata').getSymbolRelativeAddress() \
                          + golangAnalyzer.codeUnit.getVirtualImageBase()
    else:
      # brute-force search over the whole binary
      startAddress = golangAnalyzer.codeUnit.getVirtualImageBase()
      endAddress = startAddress + golangAnalyzer.codeUnit.getImageSize()
      firstModuleDataAddress = moduleDataBruteForceSearch(golangAnalyzer, startAddress, endAddress)
    return firstModuleDataAddress

def moduleDataBruteForceSearch(golangAnalyzer, startAddress, endAddress):
  '''
    Search for a 'moduledata-looking' structure over the given range.
  '''
  MAGIC = golangAnalyzer.pclntab.startAddr # module data starts with ptr to pclntab
  curStartAddress = startAddress
  while curStartAddress < endAddress:
    try:
      possibleModuleDataAddr = JebUtils.searchMemoryFor4BConstant(golangAnalyzer.nativeCodeAnalyzer.memory, MAGIC, curStartAddress, endAddress)
      if possibleModuleDataAddr == 0:
        return -1
      if looksLikeModuleData(golangAnalyzer, possibleModuleDataAddr):
        return possibleModuleDataAddr
      curStartAddress = possibleModuleDataAddr + 4
    except MemoryException:
      break
  return -1

def looksLikeModuleData(golangAnalyzer, possibleModuleDataAddr):
  try:
    # 1- attempt to parse
    possibleModuleData = ModuleData(golangAnalyzer, possibleModuleDataAddr)
    possibleModuleData.parse()
    # 2- check minpc value (see moduledataverify1() in src\\runtime\\symtab.go)
    firstFunctionTableEntry = FunctionSymbolTableEntry(golangAnalyzer.pclntab, possibleModuleData.ftab.data)
    firstFunctionTableEntry.parse()
    if possibleModuleData.minpc != firstFunctionTableEntry.startPC:
      return False
  except MemoryException:
    return False
  return True

def getPclntab(golangAnalyzer):
  '''
    Locate pclntab in memory and return parsed PcLineTable object, or None on failure.
  '''
  pclntabAddress = locatePclntab(golangAnalyzer)
  if pclntabAddress == -1:
    return None
  return buildPclntab(golangAnalyzer, pclntabAddress)

def buildPclntab(golangAnalyzer, pclntabAddress):
  memory = golangAnalyzer.nativeCodeAnalyzer.getMemory()
  pclntab = PcLineTable(golangAnalyzer, pclntabAddress)
  if pclntab:
    pclntab.parse()
    
    # structures needed for pclntab parsing
    PcLineTable.createJebStructure(golangAnalyzer.typeManager)
    FunctionSymbolTableEntry.createJebStructure(golangAnalyzer.typeManager, pclntab.ptrSize) 
    
    pclntab.applyJebStructure()
  return pclntab

def locatePclntab(golangAnalyzer):
    '''
      Return address of pclntab structure in memory, or -1 if it cannot be found.

      Reference: golang.org/s/go12symtab
    '''
    # non-stripped binary
    if CodeObjectUnitUtil.findSymbolByName(golangAnalyzer.codeContainerUnit, 'runtime.pclntab') != None:
      pclntabAddress = CodeObjectUnitUtil.findSymbolByName(golangAnalyzer.codeContainerUnit, 'runtime.pclntab').getSymbolRelativeAddress() \
                          + golangAnalyzer.codeUnit.getVirtualImageBase()
    
    else:
      # PE: brute force search in .rdata. or in all binary if section not present
      if golangAnalyzer.codeContainerUnit.getFormatType() == WellKnownUnitTypes.typeWinPe:
        rdataSection = CodeObjectUnitUtil.findSegmentByName(golangAnalyzer.codeContainerUnit, '.rdata') # PE sections are JEB segments
        if rdataSection:
          startAddress = golangAnalyzer.codeUnit.getVirtualImageBase() + rdataSection.getOffsetInMemory()
          endAddress = startAddress + rdataSection.getSizeInMemory()
        else:
          print('> cannot find .rdata section (packed?), brute force search in memory...')
          startAddress = golangAnalyzer.codeUnit.getVirtualImageBase()
          endAddress = startAddress + golangAnalyzer.codeUnit.getImageSize()
        
        pclntabAddress = pclntabBruteForceSearch(golangAnalyzer.nativeCodeAnalyzer.getMemory(), startAddress, endAddress)

      # ELF: .gopclntab section if present, otherwise brute force search in all binary
      elif golangAnalyzer.codeContainerUnit.getFormatType() == WellKnownUnitTypes.typeLinuxElf:
        gopclntabSection = CodeObjectUnitUtil.findSectionByName(golangAnalyzer.codeContainerUnit, '.gopclntab')
        if gopclntabSection:
          pclntabAddress = golangAnalyzer.codeUnit.getVirtualImageBase() + gopclntabSection.getOffsetInMemory()
        else:
          print('> cannot find .gopclntab section (stripped?), brute force search in memory...')
          startAddress = golangAnalyzer.codeUnit.getVirtualImageBase()
          endAddress = startAddress + golangAnalyzer.codeUnit.getImageSize()
          pclntabAddress = pclntabBruteForceSearch(golangAnalyzer.nativeCodeAnalyzer.getMemory(), startAddress, endAddress)

    return pclntabAddress

def pclntabBruteForceSearch(memory, startAddress, endAddress):
  '''
    Search for a 'pclntab-looking' structure over the given range.
  '''
  MAGIC = 0xFFFFFFFB
  curStartAddress = startAddress
  while curStartAddress < endAddress:
    try:
      possiblePclntabAddr = JebUtils.searchMemoryFor4BConstant(memory, MAGIC, curStartAddress, endAddress)
      if possiblePclntabAddr == 0:
        return -1
      if looksLikePclntab(memory, possiblePclntabAddr):
        return possiblePclntabAddr
      curStartAddress = possiblePclntabAddr + 4
    except MemoryException:
      break
  return -1

def looksLikePclntab(memory, possiblePclntabAddr):
  '''
      Reference for header check: go12Init() in src\\debug\\gosym\\pclntab.go
    '''
  pcQuantum = memory.readByte(possiblePclntabAddr + 6)
  ptrSize = memory.readByte(possiblePclntabAddr + 7)
  return  memory.readByte(possiblePclntabAddr + 4) & 0xFF == 0 \
      and memory.readByte(possiblePclntabAddr + 5) & 0xFF == 0 \
      and pcQuantum in [1, 2, 4] \
      and ptrSize in [4, 8]
      
class PcLineTable(): 
  '''
    a.k.a. pclntab

    Reference:golang.org/s/go12symtab
  '''
  JEB_NAME = 'PcLineTableHeader'
  HEADER_SIZE = 8

  @staticmethod
  def createJebStructure(typeManager):
    primitiveTypeManager =  typeManager.getPrimitives()
    if typeManager.getType(PcLineTable.JEB_NAME):
      return None
    else:
      jebType = typeManager.createStructure(PcLineTable.JEB_NAME)
      typeManager.addStructureField(jebType, 'magic', primitiveTypeManager.getExactIntegerBySize(4, False))
      typeManager.addStructureField(jebType, '_', primitiveTypeManager.getExactIntegerBySize(1, False))
      typeManager.addStructureField(jebType, '__', primitiveTypeManager.getExactIntegerBySize(1, False))
      typeManager.addStructureField(jebType, 'minLC', primitiveTypeManager.getExactIntegerBySize(1, False))
      typeManager.addStructureField(jebType, 'ptrSize', primitiveTypeManager.getExactIntegerBySize(1, False))
      return jebType

  def __init__(self, golangAnalyzer, startAddr):
    self.startAddr = startAddr & 0xFFFFFFFF
    self.memory = golangAnalyzer.nativeCodeAnalyzer.getMemory()
    self.typeManager = golangAnalyzer.typeManager
    self.magic = 0
    self.minLC = 0 # "instruction size quantum", i.e. minimum length of an instruction code
    self.ptrSize = 0 # size in bytes of pointers and the predeclared "int", "uint", and "uintptr" types
    self.functionSymbolTable = dict() # pc -> FunctionSymbolTableEntry
    self.endPC = 0
    self.sourceFileTableAddress = 0
    self.sourceFiles = list()
    self.codeUnit = golangAnalyzer.codeUnit

  def applyJebStructure(self):
    primitiveTypeManager =  self.typeManager.getPrimitives()
    self.codeUnit.setDataAt(self.startAddr, self.typeManager.getType(PcLineTable.JEB_NAME), 'pclntab')
    self.codeUnit.setDataAt(self.startAddr + PcLineTable.HEADER_SIZE, primitiveTypeManager.getExactIntegerBySize(self.ptrSize, False), 'pclntab.func_entries')
    curAddr = self.startAddr + PcLineTable.HEADER_SIZE + self.ptrSize
    for i in range(len(self.functionSymbolTable.values())):
      self.codeUnit.setDataAt(curAddr, primitiveTypeManager.getExactIntegerBySize(self.ptrSize, False), 'pc%d' % i)
      curAddr+=self.ptrSize
      self.codeUnit.setDataAt(curAddr, primitiveTypeManager.getExactIntegerBySize(self.ptrSize, False), 'offset_func%d' % i)
      curAddr+=self.ptrSize

    for funcEntry in self.functionSymbolTable.values():
      funcEntry.applyJebStructure()
  
  def parse(self):
    curAddress = self.parseHeader()
    curAddress = self.parseSymbolFunctionTable(curAddress)
    self.parseSourceFileTable(curAddress)
    
  def parseSourceFileTable(self, curAddress):
    '''
      Basic parsing to extract paths, see pclntab.go
    '''
    self.sourceFileTableAddress = self.startAddr + (self.memory.readInt(curAddress) & 0xFFFFFFFF)
    curAddress += 4
    if self.sourceFileTableAddress != 0:
      numberOfFiles = self.memory.readInt(self.sourceFileTableAddress) & 0xFFFFFFFF
      curAddress = self.sourceFileTableAddress + 4 # !!
      for i in range(numberOfFiles):
        ptrToFilePath = (self.memory.readInt(curAddress) & 0xFFFFFFFF) + self.startAddr
        filePathItem = self.codeUnit.getCodeModel().getItemAt(ptrToFilePath)
        if isinstance(filePathItem, INativeStringItem):
          self.sourceFiles.append(filePathItem.getValue())
        curAddress += 4

  def parseSymbolFunctionTable(self, curAddress):
    functionSTEntries, curAddress = self.readNextField(curAddress)
    for i in range(0, functionSTEntries):
      pc, curAddress = self.readNextField(curAddress)
      funcOffset, curAddress = self.readNextField(curAddress)
      funcEntry = FunctionSymbolTableEntry(self, funcOffset + self.startAddr)
      funcEntry.parse()
      self.functionSymbolTable[pc] = funcEntry
    self.endPC, curAddress = self.readNextField(curAddress)
    return curAddress

  def readNextField(self, curAddress):
    val = self.memory.readInt(curAddress) & 0xFFFFFFFF if self.ptrSize == 4 else self.memory.readLong(curAddress) & 0xFFFFFFFFFFFFFFFF
    curAddress = curAddress + 4 if self.ptrSize == 4 else curAddress + 8
    return val, curAddress

  def parseHeader(self):
    '''
      Reference for header check: go12Init() in src\\debug\\gosym\\pclntab.go
    '''
    curAddress = self.startAddr
    self.magic = self.memory.readInt(curAddress) & 0xFFFFFFFF
    if self.magic != 0xFFFFFFFB:
      raise Exception('not the expected pclntab magic')
    curAddress+=4

    if self.memory.readByte(curAddress) & 0xFF != 0:
      raise Exception('wrong pclntab header')
    curAddress+=1
    if self.memory.readByte(curAddress) & 0xFF != 0:
      raise Exception('wrong pclntab header')
    curAddress+=1

    self.minLC = self.memory.readByte(curAddress) & 0xFF
    if self.minLC != 1 and self.minLC != 2 and self.minLC != 4:
      raise Exception('wrong pclntab header (strange minLC value: %d)' % self.minLC)
    curAddress+=1

    self.ptrSize = self.memory.readByte(curAddress) & 0xFF
    if self.ptrSize != 4 and self.ptrSize != 8:
      raise Exception('wrong pclntab header (strange ptrSize value: %d)' % self.ptrSize)
    curAddress+=1    
    return curAddress

class FunctionSymbolTableEntry():
  '''
    Reference: golang.org/s/go12symtab

    struct Func
    {
        uintptr        entry;  // start pc
        int32 name;         // name (offset to C string)
        int32 args;         // size of arguments passed to function
        int32 frame;        // size of function frame, including saved caller PC
        int32        pcsp;                // pcsp table (offset to pcvalue table)
        int32        pcfile;          // pcfile table (offset to pcvalue table)
        int32        pcln;                  // pcln table (offset to pcvalue table)
        int32        nfuncdata;          // number of entries in funcdata list
        int32        npcdata;          // number of entries in pcdata list
    };
  '''
  JEB_NAME = 'FunctionSymbolTableEntry'

  @staticmethod
  def createJebStructure(typeManager, ptrSize):
    primitiveTypeManager =  typeManager.getPrimitives()
    if typeManager.getType(FunctionSymbolTableEntry.JEB_NAME):
      return None
    else:
      jebType = typeManager.createStructure(FunctionSymbolTableEntry.JEB_NAME)
      typeManager.addStructureField(jebType, 'entry', typeManager.getType('void*'))
      typeManager.addStructureField(jebType, 'name', primitiveTypeManager.getExactIntegerBySize(4, False))
      typeManager.addStructureField(jebType, 'args', primitiveTypeManager.getExactIntegerBySize(4, False))
      typeManager.addStructureField(jebType, 'frame', primitiveTypeManager.getExactIntegerBySize(4, False))
      typeManager.addStructureField(jebType, 'pcsp', primitiveTypeManager.getExactIntegerBySize(4, False))
      typeManager.addStructureField(jebType, 'pcfile', primitiveTypeManager.getExactIntegerBySize(4, False))
      typeManager.addStructureField(jebType, 'pcln', primitiveTypeManager.getExactIntegerBySize(4, False))
      typeManager.addStructureField(jebType, 'nfuncdata', primitiveTypeManager.getExactIntegerBySize(4, False))
      typeManager.addStructureField(jebType, 'npcdata', primitiveTypeManager.getExactIntegerBySize(4, False))
      return jebType

  def __init__(self, pclntab, startAddr):
    self.pclntab = pclntab
    self.memory = pclntab.memory
    self.startAddr = startAddr
    self.startPC = 0 # a.k.a. entry
    self.name = ''
    self.codeUnit = pclntab.codeUnit
    self.typeManager = pclntab.typeManager

  def applyJebStructure(self):
    self.codeUnit.setDataAt(self.startAddr, self.typeManager.getType(FunctionSymbolTableEntry.JEB_NAME), self.getSimpleName())

  def parse(self):
    curAddress = self.startAddr
    self.startPC, curAddress = self.pclntab.readNextField(curAddress)

    nameAddress = ((self.memory.readInt(curAddress) & 0xFFFFFFFF) + self.pclntab.startAddr)
    self.name = JebUtils.readNullTerminatedString(self.memory, nameAddress)

    # TODO: all fields

  def getSimpleName(self):
    return 'funcSymbol:%s' % self.name 


class StringHeader():
  '''
    Reference: https://golang.org/pkg/reflect/#StringHeader

    type StringHeader struct {
        Data uintptr
        Len  int
    }
  '''
  JEB_NAME = 'StringHeader'

  @staticmethod
  def createJebStructure(typeManager, ptrSize):
    primitiveTypeManager =  typeManager.getPrimitives()
    if typeManager.getType(StringHeader.JEB_NAME):
      return None
    else:
      jebType = typeManager.createStructure(StringHeader.JEB_NAME)
      typeManager.addStructureField(jebType, 'Data', typeManager.getType('void*'))
      typeManager.addStructureField(jebType, 'Len', primitiveTypeManager.getExactIntegerBySize(ptrSize, True))
      return jebType

  def __init__(self, startAddr, memory, ptrSize):
    self.memory = memory
    self.ptrSize   = ptrSize
    self.startAddr = startAddr
    self.data = 0
    self.len = 0
    self.mySize = 2 * ptrSize

  def parse(self):
    curAddr = self.startAddr
    self.data, curAddr = readPtr(self.memory, self.ptrSize, curAddr)
    self.len, curAddr = readPtr(self.memory, self.ptrSize, curAddr)

class BitVector():
  '''
    Reference: src\\reflect\\type.go

    type bitvector struct {
      n        int32 // # of bits
      bytedata *uint8
    }
  '''
  JEB_NAME = 'BitVector'

  @staticmethod
  def createJebStructure(typeManager, ptrSize):
    primitiveTypeManager =  typeManager.getPrimitives()
    if typeManager.getType(BitVector.JEB_NAME):
      return None
    else:
      jebType = typeManager.createStructure(BitVector.JEB_NAME)
      typeManager.addStructureField(jebType, 'n', primitiveTypeManager.getExactIntegerBySize(4, False))
      typeManager.addStructureField(jebType, 'bytedata', typeManager.getType('void*'))
      return jebType

  def __init__(self, startAddr, memory, ptrSize):
    self.memory = memory
    self.ptrSize   = ptrSize
    self.startAddr = startAddr
    self.n = 0
    self.mySize = 4 + ptrSize

  def parse(self):
    curAddr = self.startAddr
    self.n = self.memory.readInt(curAddr) & 0xFFFFFFFF
    curAddr+=4
    self.bytedata, curAddr = readPtr(self.memory, self.ptrSize, curAddr)

class SliceHeader():
  '''
    Reference: https://golang.org/pkg/reflect/#SliceHeader

    type SliceHeader struct {
      Data uintptr
      Len  int
      Cap  int
    }
  '''
  JEB_NAME = 'SliceHeader'

  @staticmethod
  def createJebStructure(typeManager, ptrSize):
    primitiveTypeManager =  typeManager.getPrimitives()
    if typeManager.getType(SliceHeader.JEB_NAME):
      return None
    else:
      jebType = typeManager.createStructure(SliceHeader.JEB_NAME)
      typeManager.addStructureField(jebType, 'Data', typeManager.getType('void*'))
      typeManager.addStructureField(jebType, 'Len', primitiveTypeManager.getExactIntegerBySize(ptrSize, True))
      typeManager.addStructureField(jebType, 'Cap', primitiveTypeManager.getExactIntegerBySize(ptrSize, True))
      return jebType
     
  def __init__(self, startAddr, memory, ptrSize):
    self.memory = memory
    self.ptrSize   = ptrSize
    self.startAddr = startAddr
    self.data = 0
    self._len = 0
    self.cap  = 0
    self.mySize = 3 * ptrSize

  def parse(self):
    curAddr = self.startAddr
    self.data, curAddr = readPtr(self.memory, self.ptrSize, curAddr)
    self._len, curAddr = readPtr(self.memory, self.ptrSize, curAddr)
    self.cap, curAddr = readPtr(self.memory, self.ptrSize, curAddr)

  def __str__(self):
    return 'data:%x - len:%d - cap:%d' % (self.data, self._len, self.cap)

class ModuleData():
  '''
    Reference: src\\runtime\\symtab.go

    type moduledata struct {
      pclntable    []byte
      ftab         []functab
      filetab      []uint32
      findfunctab  uintptr
      minpc, maxpc uintptr

      text, etext           uintptr
      noptrdata, enoptrdata uintptr
      data, edata           uintptr
      bss, ebss             uintptr
      noptrbss, enoptrbss   uintptr
      end, gcdata, gcbss    uintptr
      types, etypes         uintptr

      textsectmap []textsect
      typelinks   []int32 // offsets from types
      itablinks   []*itab

      ptab []ptabEntry

      pluginpath string
      pkghashes  []modulehash

      modulename   string
      modulehashes []modulehash

      hasmain uint8 // 1 if module contains the main function, 0 otherwise

      gcdatamask, gcbssmask bitvector

      typemap map[typeOff]*_type // offset to *_rtype in previous module

      bad bool // module failed to load and should be ignored

      next *moduledata
    }
  '''
  JEB_NAME = 'ModuleData'

  @staticmethod
  def createJebStructure(typeManager, ptrSize):
    primitiveTypeManager =  typeManager.getPrimitives()
    if typeManager.getType(ModuleData.JEB_NAME):
      return None
    else:
      jebType = typeManager.createStructure(ModuleData.JEB_NAME)
      typeManager.addStructureField(jebType, 'pclntable', typeManager.getType(SliceHeader.JEB_NAME))
      typeManager.addStructureField(jebType, 'ftab', typeManager.getType(SliceHeader.JEB_NAME))
      typeManager.addStructureField(jebType, 'filetab', typeManager.getType(SliceHeader.JEB_NAME))
      typeManager.addStructureField(jebType, 'findfunctab', typeManager.getType('void*'))
      typeManager.addStructureField(jebType, 'minpc', primitiveTypeManager.getExactIntegerBySize(ptrSize, False))
      typeManager.addStructureField(jebType, 'maxpc', primitiveTypeManager.getExactIntegerBySize(ptrSize, False))

      typeManager.addStructureField(jebType, 'text', typeManager.getType('void*'))
      typeManager.addStructureField(jebType, 'etext', typeManager.getType('void*'))          
      typeManager.addStructureField(jebType, 'noptrdata', typeManager.getType('void*'))
      typeManager.addStructureField(jebType, 'enoptrdata', typeManager.getType('void*'))
      typeManager.addStructureField(jebType, 'data', typeManager.getType('void*'))
      typeManager.addStructureField(jebType, 'edata', typeManager.getType('void*'))          
      typeManager.addStructureField(jebType, 'bss', typeManager.getType('void*'))
      typeManager.addStructureField(jebType, 'ebss', typeManager.getType('void*'))            
      typeManager.addStructureField(jebType, 'noptrbss', typeManager.getType('void*'))
      typeManager.addStructureField(jebType, 'enoptrbss', typeManager.getType('void*'))  
      typeManager.addStructureField(jebType, 'end', typeManager.getType('void*'))
      typeManager.addStructureField(jebType, 'gcdata', typeManager.getType('void*'))
      typeManager.addStructureField(jebType, 'gcbss', typeManager.getType('void*'))   
      typeManager.addStructureField(jebType, 'types', typeManager.getType('void*'))
      typeManager.addStructureField(jebType, 'etypes', typeManager.getType('void*'))

      typeManager.addStructureField(jebType, 'textsectmap', typeManager.getType(SliceHeader.JEB_NAME))    
      typeManager.addStructureField(jebType, 'typelinks', typeManager.getType(SliceHeader.JEB_NAME))
      typeManager.addStructureField(jebType, 'itablinks', typeManager.getType(SliceHeader.JEB_NAME))

      typeManager.addStructureField(jebType, 'ptab', typeManager.getType(SliceHeader.JEB_NAME))

      typeManager.addStructureField(jebType, 'pluginpath', typeManager.getType(StringHeader.JEB_NAME))
      typeManager.addStructureField(jebType, 'pkghashes', typeManager.getType(SliceHeader.JEB_NAME))

      typeManager.addStructureField(jebType, 'modulename', typeManager.getType(StringHeader.JEB_NAME))
      typeManager.addStructureField(jebType, 'modulehashes', typeManager.getType(SliceHeader.JEB_NAME))

      typeManager.addStructureField(jebType, 'hasmain', primitiveTypeManager.getExactIntegerBySize(1, False))

      typeManager.addStructureField(jebType, 'gcdatamask', typeManager.getType(BitVector.JEB_NAME))
      typeManager.addStructureField(jebType, 'gcbssmask', typeManager.getType(BitVector.JEB_NAME))

      typeManager.addStructureField(jebType, 'typemap', typeManager.getType('void*'))

      typeManager.addStructureField(jebType, 'bad', typeManager.getType('_Bool'))

      typeManager.addStructureField(jebType, 'next', typeManager.getType('void*'))

      return jebType

  def __init__(self, golangAnalyzer, startAddr):
    self.memory = golangAnalyzer.nativeCodeAnalyzer.getMemory()
    self.ptrSize = golangAnalyzer.pclntab.ptrSize
    self.startAddr = startAddr & 0xFFFFFFFF
    self.codeUnit = golangAnalyzer.codeUnit
    self.typeManager = golangAnalyzer.typeManager

  def applyJebStructure(self):
    self.codeUnit.setDataAt(self.startAddr, self.typeManager.getType(ModuleData.JEB_NAME), 'firstmoduledata')

  def parse(self):
      curAddress = self.startAddr

      self.pclntable = SliceHeader(curAddress, self.memory, self.ptrSize)
      self.pclntable.parse()
      curAddress += self.pclntable.mySize

      self.ftab = SliceHeader(curAddress, self.memory, self.ptrSize)
      self.ftab.parse()
      curAddress += self.ftab.mySize

      self.filetab = SliceHeader(curAddress, self.memory, self.ptrSize)
      self.filetab.parse()
      curAddress += self.filetab.mySize

      self.findfunctab, curAddress = readPtr(self.memory, self.ptrSize, curAddress)
      self.minpc, curAddress = readPtr(self.memory, self.ptrSize, curAddress)
      self.maxpc, curAddress = readPtr(self.memory, self.ptrSize, curAddress)

      self.text, curAddress = readPtr(self.memory, self.ptrSize, curAddress)
      self.etext, curAddress = readPtr(self.memory, self.ptrSize, curAddress)
      self.noptrdata, curAddress = readPtr(self.memory, self.ptrSize, curAddress)
      self.enoptrdata, curAddress = readPtr(self.memory, self.ptrSize, curAddress)
      self.data, curAddress = readPtr(self.memory, self.ptrSize, curAddress)
      self.edata, curAddress = readPtr(self.memory, self.ptrSize, curAddress)
      self.bss, curAddress = readPtr(self.memory, self.ptrSize, curAddress)
      self.ebss, curAddress = readPtr(self.memory, self.ptrSize, curAddress)
      self.noptrbss, curAddress = readPtr(self.memory, self.ptrSize, curAddress)
      self.enoptrbss, curAddress = readPtr(self.memory, self.ptrSize, curAddress)
      self.end, curAddress = readPtr(self.memory, self.ptrSize, curAddress)
      self.gcdata, curAddress = readPtr(self.memory, self.ptrSize, curAddress)
      self.gcbss, curAddress = readPtr(self.memory, self.ptrSize, curAddress)
      self.types, curAddress = readPtr(self.memory, self.ptrSize, curAddress)
      self.etypes, curAddress = readPtr(self.memory, self.ptrSize, curAddress)

      self.textsectmap = SliceHeader(curAddress, self.memory, self.ptrSize)
      self.textsectmap.parse()
      curAddress+=self.textsectmap.mySize

      self.typelinks = SliceHeader(curAddress, self.memory, self.ptrSize)
      self.typelinks.parse()
      curAddress+=self.typelinks.mySize

      self.itablinks = SliceHeader(curAddress, self.memory, self.ptrSize)
      self.itablinks.parse()
      curAddress+=self.itablinks.mySize

      self.ptab = SliceHeader(curAddress, self.memory, self.ptrSize)
      self.ptab.parse()
      curAddress+=self.ptab.mySize

      self.pluginpath = StringHeader(curAddress, self.memory, self.ptrSize)
      self.pluginpath.parse()
      curAddress+=self.pluginpath.mySize

      self.pkghashes = SliceHeader(curAddress, self.memory, self.ptrSize)
      self.pkghashes.parse()
      curAddress+=self.pkghashes.mySize

      self.modulename = StringHeader(curAddress, self.memory, self.ptrSize)
      self.modulename.parse()
      curAddress+=self.modulename.mySize

      self.modulehashes = SliceHeader(curAddress, self.memory, self.ptrSize)
      self.modulehashes.parse()
      curAddress+=self.modulehashes.mySize

      self.hasmain = self.memory.readByte(curAddress) & 0xFF
      curAddress+=1

      self.gcdatamask = BitVector(curAddress, self.memory, self.ptrSize)
      self.gcdatamask.parse()
      curAddress += self.gcdatamask.mySize

      self.gcbssmask = BitVector(curAddress, self.memory, self.ptrSize)
      self.gcbssmask.parse()
      curAddress += self.gcbssmask.mySize

      self.typemap, curAddress = readPtr(self.memory, self.ptrSize, curAddress)

      self.bad = self.memory.readByte(curAddress) & 0xFF
      curAddress+=1

      self.next, curAddress = readPtr(self.memory, self.ptrSize, curAddress)

def readPtr(memory, ptrSize, curAddress):
  val = memory.readInt(curAddress) & 0xFFFFFFFF if ptrSize == 4 else memory.readLong(curAddress) & 0xFFFFFFFFFFFFFFFF
  curAddress = curAddress + 4 if ptrSize == 4 else curAddress + 8
  return val, curAddress