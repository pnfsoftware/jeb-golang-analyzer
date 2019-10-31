from com.pnfsoftware.jeb.core.units import WellKnownUnitTypes
from com.pnfsoftware.jeb.core.units.codeobject import CodeObjectUnitUtil, ProcessorType
from com.pnfsoftware.jeb.core.units.code.asm.items import INativeDataItem, INativeStringItem, INativeInstructionItem
from com.pnfsoftware.jeb.core.units.code.asm.type import StringType
from com.pnfsoftware.jeb.core.units.code.asm.processor import IInstructionOperandGeneric, IInstructionOperandCMA

import string
import os

"""
Define strings referenced by Golang's StringHeader structures. 
(see https://golang.org/pkg/reflect/#StringHeader)

Strings are stored as a series of UTF8 bytes *without* null-terminator. 
Terminator's abscence makes usual strings recognition algorithms fail.

By default, three heuristics are used:

- search for specific assembly patterns building StringHeader structure 
(for x86/x64, ARM, MIPS, see searchAssemblyPatterns()

- search in memory for data blobs looking like a StringHeader structure
(see stringHeaderBruteForceSearch())

- linearly scan memory for series of UTF-8 characters
(two implementations: linearSweepItemBased() and linearSweep()) 

(This file is part of JEB Decompiler's scripts used to analyze Golang executables.)
"""

# (de)activate heuristics
HEUR_PATTERN_MATCHING         = True
HEUR_STRING_HEADER_BRUTEFORCE = True
HEUR_LINEAR_SWEEP_DATA_ITEM   = True
HEUR_LINEAR_SWEEP             = True

DEBUG_MODE = False

class StringsBuilder():

  def __init__(self, golangAnalyzer):
    self.nativeCodeAnalyzer = golangAnalyzer.nativeCodeAnalyzer
    self.codeContainerUnit = golangAnalyzer.codeContainerUnit
    self.codeUnit = golangAnalyzer.codeUnit
    self.typeManager = golangAnalyzer.typeManager
    self.referenceManager = golangAnalyzer.codeUnit.getCodeModel().getReferenceManager()
    self.ptrSize = golangAnalyzer.pclntab.ptrSize
    self.possibleStrings = list() # contains tuples: [string start addr, string size]
    self.buildStringsCounter = 0 # for stats
    self.debugLogs = ''

  def run(self):
    global HEUR_PATTERN_MATCHING, HEUR_LINEAR_SWEEP_DATA_ITEM, HEUR_STRING_HEADER_BRUTEFORCE, HEUR_LINEAR_SWEEP, DEBUG_MODE
      
    print('> %s: building strings...' % self.__class__.__name__),

    if HEUR_PATTERN_MATCHING:
      self.searchAssemblyPatterns()
      self.createFoundStrings(heuristic='HEUR_PATTERN_MATCHING')

    if HEUR_STRING_HEADER_BRUTEFORCE:
      self.stringHeaderBruteForceSearch()
      self.createFoundStrings(heuristic='HEUR_STRING_HEADER_BRUTEFORCE')

    if HEUR_LINEAR_SWEEP_DATA_ITEM:
      self.linearSweepItemBased()
      self.createFoundStrings(heuristic='HEUR_LINEAR_SWEEP_DATA_ITEM')

    if HEUR_LINEAR_SWEEP:
      self.linearSweep()
      self.createFoundStrings(heuristic='HEUR_LINEAR_SWEEP')
    
    if DEBUG_MODE:
      self.printDebugLogs()

    print('OK (%s)' % self.getStats())

  def searchAssemblyPatterns(self):
    if self.codeUnit.getProcessor().getType() == ProcessorType.X86 \
      or self.codeUnit.getProcessor().getType() == ProcessorType.X86_64:
      self.searchX86Patterns()
    elif self.codeUnit.getProcessor().getType() == ProcessorType.ARM:
      self.searchARMPatterns()
    elif self.codeUnit.getProcessor().getType() == ProcessorType.MIPS:
      self.searchMIPSPatterns()
    else:
      print('> %s: pattern matching is not implemented for this architecture' % self.__class__.__name__)

  def createFoundStrings(self, heuristic='UNKNOWN'):
    global DEBUG_MODE
    for foundString in self.possibleStrings:
      stringAddr = foundString[0]
      stringSize = foundString[1]

      curItem = self.codeUnit.getNativeItemAt(stringAddr)
      if isinstance(curItem, INativeStringItem):
        continue

      if not self.checkPossibleString(stringAddr, stringSize):
        print('> %s: heur %s false positive at %x' % (self.__class__.__name__, heuristic, stringAddr))
        continue

      if not self.codeUnit.setStringAt(stringAddr, stringAddr + stringSize, StringType.UTF8_NONZERO, 1, -1):
        print('> %s: warning: failed to define string at %x' % (self.__class__.__name__, stringAddr))
      else:
        if DEBUG_MODE:
          self.debugLogs += '> heur %s: defined str %x (size:%d)\n' % (heuristic, stringAddr, stringSize)
        self.buildStringsCounter+=1

    self.possibleStrings = list()

  def printDebugLogs(self):
    filePath = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'str_debug_log.txt')
    f = open(filePath, 'w')
    f.write(self.debugLogs)
    f.close()

  def searchMIPSPatterns(self):
    '''
      LUI       REG, A
      ADDIU     REG, REG, B       // STRING_ADDRESS
      SW        REG, X($sp)
      LI        REG, STRING_SIZE
      SW        REG, Y($sp)
    '''
    for routine in self.codeUnit.getInternalMethods():
      routineCFG = routine.getData().getCFG()
      for bb in routineCFG.getBlocks():
        i = 0
        while i < bb.size() - 5: # at least four following instructions

          # important: get2 for addressable instructions (to handle PC-relative addressing)
          insn = bb.get2(i) 
          nextInsn = bb.get2(i+1)
          nextNextInsn = bb.get2(i+2)
          nextNextNextInsn = bb.get2(i+3)
          nextNextNextNextInsn = bb.get2(i+4)

          # check first three instructions: LUI REG, A / ADDIU REG, REG, B / SW REG, X($sp)
          if insn.getMnemonic().lower() == 'lui' \
           and insn.getOperands()[1].getOperandType() == IInstructionOperandGeneric.TYPE_IMM \
           and nextInsn.getMnemonic().lower() == 'addiu' \
           and nextInsn.getOperands()[0] == nextInsn.getOperands()[1] \
           and nextInsn.getOperands()[0] == insn.getOperands()[0] \
           and nextNextInsn.getMnemonic().lower() == 'sw' \
           and nextNextInsn.getOperands()[0] == insn.getOperands()[0]:
           a = (insn.getOperands()[1].getOperandValue() << 16) & 0xFFFFFFFF
           b = nextInsn.getOperands()[2].getOperandValue() & 0xFFFFFFFF
           stringAddr = (a + b) & 0xFFFFFFFF
          else:
            i += 1
            continue

          # check next two instructions: LI REG, STRING_SIZE / SW REG, Y($sp)
          if nextNextNextInsn.getMnemonic().lower() == 'li' \
           and nextNextNextInsn.getOperands()[1].getOperandType() == IInstructionOperandGeneric.TYPE_IMM \
           and nextNextNextNextInsn.getMnemonic().lower() == 'sw' \
           and nextNextNextNextInsn.getOperands()[0] == nextNextNextInsn.getOperands()[0]:
           stringSize = nextNextNextInsn.getOperands()[1].getOperandValue()
          else:
            i += 1
            continue

          if not self.checkPossibleString(stringAddr, stringSize):
            i += 1
            continue
          
          # everything is fine, register string
          self.possibleStrings.append([stringAddr, stringSize])
          i += 1

  def searchARMPatterns(self):
    '''
        LDR       REG, [PC, IMM]  // string address
        STR       REG, [SP, X]
        MOV       REG, STRING_SIZE
        STR       REG, [SP, Y]
    '''
    for routine in self.codeUnit.getInternalMethods():
      routineCFG = routine.getData().getCFG()
      for bb in routineCFG.getBlocks():
        i = 0
        while i < bb.size() - 4: # at least three following instructions

          # important: get2 for addressable instructions (to handle PC-relative addressing)
          insn = bb.get2(i) 
          nextInsn = bb.get2(i+1)
          nextNextInsn = bb.get2(i+2)
          nextNextNextInsn = bb.get2(i+3)

          # check first two instructions: LDR REG, [PC, IMM] / STR REG, [SP, X]
          if insn.getMnemonic().lower() == 'ldr' \
           and insn.getOperands()[1].getOperandType() == IInstructionOperandGeneric.TYPE_LIST \
           and 'pc' in insn.toString().lower() \
           and nextInsn.getMnemonic().lower() == 'str' \
           and nextInsn.getOperands()[0] == insn.getOperands()[0]:
           stringAddr = self.nativeCodeAnalyzer.memory.readInt(insn.getOperands()[1].getOperandValue(insn.getOffset()))
          else:
            i += 1
            continue
          
           # check last two instructions:  MOV REG, STRING_SIZE / STR REG, [SP, Y]
          if nextNextInsn.getMnemonic().lower() == 'mov' \
           and nextNextInsn.getOperands()[1].getOperandType() == IInstructionOperandGeneric.TYPE_IMM \
           and nextNextNextInsn.getMnemonic().lower() == 'str' \
           and nextNextNextInsn.getOperands()[0] == nextNextInsn.getOperands()[0]:
            stringSize = nextNextInsn.getOperands()[1].getOperandValue()
          else:
            i += 1
            continue

          if not self.checkPossibleString(stringAddr, stringSize):
            i += 1
            continue
          
          # everything is fine, register string
          self.possibleStrings.append([stringAddr, stringSize])
          i += 1

  def searchX86Patterns(self):
    '''
      Pattern 1 (Go >= 1.8, x86/x64):

        LEA REG, [STRING_ADDR]
        MOV [SP+X], REG
        MOV [SP+Y], STRING_SIZE

      Pattern 2 (Go == 1.7, x86): 

        MOV REG, [STRING_ADDR]
        MOV [SP+X], REG
        MOV [SP+Y], STRING_SIZE
    '''
    for routine in self.codeUnit.getInternalMethods():
      routineCFG = routine.getData().getCFG()
      for bb in routineCFG.getBlocks():
        i = 0
        while i < bb.size() - 3: # at least two following instructions

          # important: get2 for addressable instructions (to handle x64 RIP-relative addressing)
          insn = bb.get2(i) 
          nextInsn = bb.get2(i+1)
          nextNextInsn = bb.get2(i+2)

          # check first instruction: LEA REG, [STRING_ADDR]
          firstInsnOk = False
          if insn.getMnemonic().lower() == 'lea':
            if self.codeUnit.getProcessor().getType() == ProcessorType.X86:
              if insn.getOperands()[1].getOperandType() == IInstructionOperandGeneric.TYPE_CMA \
                              and insn.getOperands()[1].getMemoryBaseRegister() == -1 \
                              and insn.getOperands()[1].getMemoryIndexRegister() == -1 \
                              and insn.getOperands()[1].getMemoryDisplacement() != 0:
                stringAddr = insn.getOperands()[1].getMemoryDisplacement() & 0xFFFFFFFF
                firstInsnOk = True
            elif self.codeUnit.getProcessor().getType() == ProcessorType.X86_64:
              if insn.getOperands()[1].getOperandType() == IInstructionOperandGeneric.TYPE_CMA \
                and insn.getOperands()[1].getMemoryIndexRegister() == -1 \
                and insn.getOperands()[1].getMemoryDisplacement() != 0 \
                and 'rip+' in insn.toString().lower(): # RIP-based addressing on x64
                stringAddr = nextInsn.getOffset() + (insn.getOperands()[1].getMemoryDisplacement() & 0xFFFFFFFF)
                firstInsnOk = True
          # alternatively, check first instruction: MOV REG, STRING_ADDR
          elif insn.getMnemonic().lower() == 'mov' \
              and insn.getOperands()[1].getOperandType() == IInstructionOperandGeneric.TYPE_IMM:
              stringAddr = insn.getOperands()[1].getOperandValue() & 0xFFFFFFFF
              firstInsnOk = True

          if not firstInsnOk:
            i += 1
            continue

          reg = insn.getOperands()[0]

          # check second instruction: MOV [SP+X], REG (same REG)
          # check third instruction : MOV [SP+Y], STRING_SIZE
          if not(nextInsn.getMnemonic().lower() == 'mov' \
                and nextNextInsn.getMnemonic().lower() == 'mov' \
                and nextInsn.getOperands()[0].getOperandType() == IInstructionOperandGeneric.TYPE_CMA \
                and nextInsn.getOperands()[1] == reg \
                and nextNextInsn.getOperands()[0].getOperandType() == IInstructionOperandGeneric.TYPE_CMA \
                and nextNextInsn.getOperands()[1].getOperandType() == IInstructionOperandGeneric.TYPE_IMM):
            i += 1
            continue

          stringSize = nextNextInsn.getOperands()[1].getOperandValue()

          if not self.checkPossibleString(stringAddr, stringSize):
            i += 1
            continue
          
          # everything is fine, register string
          self.possibleStrings.append([stringAddr, stringSize])
          i += 1

  def checkPossibleString(self, stringAddr, stringSize, checkPrintable = False):
    '''
      Check given address and size can correspond to a string.
    '''
    if stringSize <= 0 or stringSize > 0x1000:
      return False

    # string address points to allocated memory
    startAddress = self.codeUnit.getVirtualImageBase() & 0xFFFFFFFF
    endAddress = (startAddress + self.codeUnit.getImageSize()) & 0xFFFFFFFF
    if stringAddr < startAddress or stringAddr >= endAddress:
      return False

    # string address do not point to an instruction
    alreadyDefinedItem = self.codeUnit.getCodeModel().getItemAt(stringAddr)
    if alreadyDefinedItem != None and isinstance(alreadyDefinedItem, INativeInstructionItem):
      return False

    # string characters are printable (i.e. ASCII)
    # (in general, Golang strings are not necessarily printable (UTF-8)
    # this serves to limit false positives)
    if checkPrintable:
      count = 0
      while count < stringSize:
        curByte = self.nativeCodeAnalyzer.getMemory().readByte(stringAddr + count) & 0xFF
        if chr(curByte) not in string.printable:
          return False
        count += 1

    # string is UTF-8 decodable
    count = 0
    buildString = ''
    while count < stringSize:
      curByte = self.nativeCodeAnalyzer.getMemory().readByte(stringAddr + count) & 0xFF
      buildString += chr(curByte)
      count += 1
    try:
        decoded = buildString.decode('utf-8')
    except UnicodeError:
        return False

    return True

  def getStringsMemoryRange(self):
    '''
      Return (start addr, end addr) where strings might be located

      Relies on default section names for data, if present; 
      otherwise, the whole binary.
    '''
    dataSections = list()
    if self.codeContainerUnit.getFormatType() == WellKnownUnitTypes.typeWinPe:
      dataSectionNames = ['.rdata', '.data']
      for dataSectionName in dataSectionNames:
        dataSection = CodeObjectUnitUtil.findSegmentByName(self.codeContainerUnit, dataSectionName)
        if dataSection != None:
          dataSections.append(dataSection)
    elif self.codeContainerUnit.getFormatType() == WellKnownUnitTypes.typeLinuxElf:
      dataSectionNames = ['.rodata', '.data']
      for dataSectionName in dataSectionNames:
        dataSection = CodeObjectUnitUtil.findSectionByName(self.codeContainerUnit, dataSectionName)
        if dataSection != None:
          dataSections.append(dataSection)

    if len(dataSections) != 0:
      rangeStartAddress = self.codeUnit.getVirtualImageBase() + min([dataSection.getOffsetInMemory() for dataSection in dataSections])
      rangeEndAddress = self.codeUnit.getVirtualImageBase() + max([dataSection.getOffsetInMemory() + dataSection.getSizeInMemory() for dataSection in dataSections])
    else:
      print('> %s: cannot find string section, searching on all binary...' % self.__class__.__name__)
      rangeStartAddress = self.codeUnit.getVirtualImageBase() & 0xFFFFFFFF
      rangeEndAddress = (rangeStartAddress + self.codeUnit.getImageSize()) & 0xFFFFFFFF

    return (rangeStartAddress, rangeEndAddress)

  def stringHeaderBruteForceSearch(self):
    '''
      Search for StringHeader structures stored in memory.

      Note that we restrain the search to *printable* StringHeader values.
    '''
    rangeStartAddress, rangeEndAddress = self.getStringsMemoryRange()
    for curAddr in range(rangeStartAddress, rangeEndAddress):
      possibleData = self.nativeCodeAnalyzer.getMemory().readInt(curAddr) & 0xFFFFFFFF
      possibleLen = self.nativeCodeAnalyzer.getMemory().readInt(curAddr + self.ptrSize) & 0xFFFFFFFF

      if possibleLen <= 4 or possibleLen >= 100:
        # try to avoid false positives
        continue

      if self.checkPossibleString(possibleData, possibleLen, checkPrintable = True):
        self.possibleStrings.append([possibleData, possibleLen])
        self.codeUnit.setDataTypeAt(curAddr, self.typeManager.getType('StringHeader'))
        self.referenceManager.recordReference(possibleData, curAddr)

  def linearSweepItemBased(self):
    '''
      Search for 1-byte data items (created by the LEA-like instruction)
      starting a series of *printable* UTF-8 characters. 

      We then create a new string, spanning until the next item.

      This serves to define strings whose instantiation was missed by previous heuristics.
    '''
    rangeStartAddress, rangeEndAddress = self.getStringsMemoryRange()
    itemsMap = self.codeUnit.getNativeItemsOver(rangeStartAddress, rangeEndAddress - rangeStartAddress)
    for entry in itemsMap.entrySet():
      itemAddr = entry.getKey()
      item = entry.getValue()

      if isinstance(item, INativeDataItem) and item.getType().getSize() == 1:
        firstByte = self.nativeCodeAnalyzer.getMemory().readByte(itemAddr) & 0xFF
        if firstByte != 0:
          curAddr = itemAddr+1

          # append next bytes -- stop on next item
          while (curAddr < rangeEndAddress) and (not self.codeUnit.getNativeItemAt(curAddr)):
            curByte = self.nativeCodeAnalyzer.getMemory().readByte(curAddr) & 0xFF
            curAddr+=1

          possibleStringSize = curAddr - itemAddr
          if possibleStringSize <= 2:
            # try to avoid false positives
            continue

          if self.checkPossibleString(itemAddr, possibleStringSize, checkPrintable = True):
            self.possibleStrings.append([itemAddr, possibleStringSize])

  def linearSweep(self):
    '''
      Search for series of *printable* UTF-8 chars contained in-between two string items.

      This serves to define unreferenced strings (but possibly with incorrect 
      length, due to the absence of terminators)
    '''
    rangeStartAddress, rangeEndAddress = self.getStringsMemoryRange()
    lastItemWasString = False
    stringStartAddr = 0
    for curAddr in range(rangeStartAddress, rangeEndAddress):
      curItem = self.codeUnit.getCodeModel().getItemOver(curAddr)
      if curItem:
        if isinstance(curItem, INativeStringItem):
          if stringStartAddr != 0 and lastItemWasString:
            possibleStringSize = curAddr - stringStartAddr
            if possibleStringSize > 2: # try to avoid false positives
              if self.checkPossibleString(stringStartAddr, curAddr - stringStartAddr, checkPrintable = True):
                self.possibleStrings.append([stringStartAddr, curAddr - stringStartAddr])
          lastItemWasString = True
        else:
          lastItemWasString = False
        stringStartAddr = 0
      else:
        if stringStartAddr == 0 and lastItemWasString:
          stringStartAddr = curAddr

  def getStats(self):
    return '%d built strings' % self.buildStringsCounter