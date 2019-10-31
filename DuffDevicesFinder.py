from com.pnfsoftware.jeb.core.units.codeobject import ProcessorType
from com.pnfsoftware.jeb.core.units.code.asm.items import INativeInstructionItem

"""
Identify routines for zeroing/copying memory, generated as Duff devices by Golang compiler.

Only the highest routine has a proper symbol; unnamed routines will be created for each 
other entry points. This script takes care of renaming those, with 'duff_zero/copy_N', where
N is the number of zeroed/copied bytes.

See SUPPORTED_ARCHITECTURE.

Reference: /src/runtime/mkduff.go

(This file is part of JEB Decompiler's scripts used to analyze Golang executables.)
"""
DEBUG_MODE = False
DUFF_ZERO_NAME = 'duff_zero'
DUFF_COPY_NAME = 'duff_copy'

class InstructionSled():
  '''
    Serie of assembly instructions that can be repeated, ending with a specific instruction.
    (instructions are defined by their assembly mnemonics). Also, sleds can begin with prefixes.

    For example:
      - ['mov', 'lea', 'mov', 'lea', 'ret'] is a sled with pattern ['mov', 'lea'] 
        and ending instruction 'ret'
      - ['mov', 'mov', 'lea', 'mov', 'lea', 'mov', 'lea', 'ret'] is a sled with 
        pattern ['mov', 'lea'], prefix ['mov', 'mov', 'lea'], ending instruction 'ret'
  '''
  def __init__(self, name, pattern, endingMnemonic, sizeOfModifiedMemory):
    self.name = name
    self.pattern = pattern # list of mnemonics
    self.endingMnemonic = endingMnemonic
    self.sizeOfModifiedMemory = sizeOfModifiedMemory # modified by *each* pattern
    self.prefixPatterns = list() # list of (pattern, sizeOfModifiedMemory)

  def addPrefix(self, pattern, sizeOfModifiedMemory):
     self.prefixPatterns.append((pattern, sizeOfModifiedMemory))

  def matchesMemory(self, codeUnit, startAddr):
    '''
      Checks memory at the given address matches the sled.

      Return (boolean, total number of bytes zeroed/copied by sled)
    '''
    sledIndex = 0
    sledCounter = 0 # number of times sled is present
    curItem = codeUnit.getNativeItemAt(startAddr)
    prefixModifiedMemory = 0

    # check prefixes: jump over it if present
    if len(self.prefixPatterns) != 0:
      for (prefix, prefixSizeOfModifiedMemory) in self.prefixPatterns:

        curItemPrefix = curItem
        prefixIndex = 0
        while prefixIndex < len(prefix) and isinstance(curItemPrefix, INativeInstructionItem):
          curMnemonic = curItemPrefix.getInstruction().getMnemonic().lower()
          if curMnemonic != prefix[prefixIndex].lower():
            break
          prefixIndex += 1
          curItemPrefix = codeUnit.getNativeItemAt(curItemPrefix.getEnd())

        if prefixIndex == len(prefix):
          # prefix match
          prefixModifiedMemory = prefixSizeOfModifiedMemory
          curItem = curItemPrefix
          break

    # check pattern
    while isinstance(curItem, INativeInstructionItem):
      curMnemonic = curItem.getInstruction().getMnemonic().lower()
      if curMnemonic == self.endingMnemonic:
        return sledCounter != 0, sledCounter * self.sizeOfModifiedMemory + prefixModifiedMemory

      if curMnemonic != self.pattern[sledIndex].lower():
        return False, 0

      sledIndex = (sledIndex + 1) % len(self.pattern)

      if sledIndex == 0:
        sledCounter += 1
      curItem = codeUnit.getNativeItemAt(curItem.getEnd())

    return False, 0

class DuffDevicesFinder():
  SUPPORTED_ARCHITECTURE = [ProcessorType.X86, ProcessorType.X86_64, ProcessorType.ARM]

  def __init__(self, golangAnalyzer):
    self.nativeCodeAnalyzer = golangAnalyzer.nativeCodeAnalyzer
    self.codeContainerUnit = golangAnalyzer.codeContainerUnit
    self.codeUnit = golangAnalyzer.codeUnit
    self.labelManager = golangAnalyzer.codeUnit.getCodeModel().getLabelManager()
    self.identifiedRoutines = 0

  def run(self):
    global DEBUG_MODE, DUFF_ZERO_NAME, DUFF_COPY_NAME

    if self.codeUnit.getProcessor().getType() not in self.SUPPORTED_ARCHITECTURE:
      print('> WARNING: Duff device identifier not supported for this architecture (supported %s)' % self.SUPPORTED_ARCHITECTURE)
      return
      
    print('> %s: finding memory zero/copy routines...' % self.__class__.__name__),

    sleds = list()
    if self.codeUnit.getProcessor().getType() == ProcessorType.X86:
      sleds.append(InstructionSled(DUFF_ZERO_NAME, ['stosd'], 'ret', 4))
      sleds.append(InstructionSled(DUFF_COPY_NAME, ['mov','add','mov','add'], 'ret', 4))

    elif self.codeUnit.getProcessor().getType() == ProcessorType.X86_64:
      zero_sled = InstructionSled(DUFF_ZERO_NAME, ['movups','movups','movups','movups','lea'], 'ret', 64)
      # code can branch directly on one of the movups
      zero_sled.addPrefix(['movups','lea'], 16)
      zero_sled.addPrefix(['movups','movups','lea'], 32)
      zero_sled.addPrefix(['movups','movups','movups','lea'], 48)
      sleds.append(zero_sled)
      sleds.append(InstructionSled(DUFF_COPY_NAME, ['movups','add','movups','add'], 'ret', 16))

    elif self.codeUnit.getProcessor().getType() == ProcessorType.ARM:
      sleds.append(InstructionSled(DUFF_ZERO_NAME, ['str'], 'add', 4))
      sleds.append(InstructionSled(DUFF_COPY_NAME, ['ldr','str'], 'add', 4))

    for routine in self.codeUnit.getInternalMethods():
      routineCFG = routine.getData().getCFG()

      for sled in sleds:
        match, modifiedBytes = sled.matchesMemory(self.codeUnit, routine.getData().getMemoryAddress())
        if match:
          if DEBUG_MODE:
            print('> sled detector: %s routine matches sled %s (%d modified bytes)' % (routine.getAddress(), sled.name, modifiedBytes))
          self.labelManager.setLabel(routine.getData().getMemoryAddress(), '%s_%d' % (sled.name, modifiedBytes), True, True, False)
          self.identifiedRoutines+=1

    print('OK (%d routines identified)' % self.identifiedRoutines)



