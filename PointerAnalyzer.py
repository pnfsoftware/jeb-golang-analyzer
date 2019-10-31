from com.pnfsoftware.jeb.core.units.code.asm.items import INativeDataItem, INativeStringItem

from Commons import readPtr

"""
Search for data items that could be pointers to routines/data items,
and rename them with meaningful names, if possible.

This module should be executed after functions discovery.

(This file is part of JEB Decompiler's scripts used to analyze Golang executables.)
"""
DEBUG_MODE = False

class PointerAnalyzer():

  def __init__(self, golangAnalyzer):
    self.nativeCodeAnalyzer = golangAnalyzer.nativeCodeAnalyzer
    self.codeContainerUnit = golangAnalyzer.codeContainerUnit
    self.codeUnit = golangAnalyzer.codeUnit
    self.typeManager = golangAnalyzer.typeManager
    self.referenceManager = golangAnalyzer.codeUnit.getCodeModel().getReferenceManager()
    self.ptrSize = golangAnalyzer.pclntab.ptrSize
    self.labelManager = golangAnalyzer.codeUnit.getCodeModel().getLabelManager()
    self.memoryStartAddress = self.codeUnit.getVirtualImageBase()
    self.memorySize = self.codeContainerUnit.getLoaderInformation().getImageSize()
    self.pointersFound = 0

  def run(self):
    itemsMap = self.codeUnit.getNativeItemsOver(self.memoryStartAddress, self.memorySize)
    for entry in itemsMap.entrySet():
      itemAddr = entry.getKey()
      item = entry.getValue()

      if isinstance(item, INativeDataItem) and self.hasDefaultName(item):
        possiblePtr, curAddr = readPtr(self.nativeCodeAnalyzer.getMemory(), self.ptrSize, itemAddr)
        if not self.isInMemoryRange(possiblePtr):
          continue

        if self.renamePtrToRoutines(item, itemAddr, possiblePtr):
          self.pointersFound += 1
          continue
        if self.renamePtrToNamedDataItems(item, itemAddr, possiblePtr):
          self.pointersFound += 1
          continue

    print('> %s: %d pointers renamed' % (self.__class__.__name__, self.pointersFound))

  def hasDefaultName(self, item):
    name = item.getName(True)
    return name.startswith('gvar_') or name.startswith('ptr_gvar_')

  def isInMemoryRange(self, ptr):
    return ptr >= self.memoryStartAddress and ptr < (self.memoryStartAddress + self.memorySize) 

  def renamePtrToRoutines(self, item, itemAddr, possiblePtr):
    try:
      pointedRoutine = self.codeUnit.getInternalMethod(possiblePtr, True)
      if pointedRoutine != None:
        self.renameAndTypePtr(item, itemAddr, pointedRoutine, possiblePtr)
        return True
    except Exception as err: 
      pass
    return False

  def renamePtrToNamedDataItems(self, item, itemAddr, possiblePtr):
    global DEBUG_MODE
    try:
      targetItem = self.codeUnit.getCodeModel().getItemAt(possiblePtr)
      if targetItem != None and isinstance(targetItem, INativeDataItem) and not self.hasDefaultName(targetItem):
        self.renameAndTypePtr(item, itemAddr, targetItem, possiblePtr)
        return True
    except Exception as err: 
      pass
    return False

  def renameAndTypePtr(self, ptrItem, ptrAddr, targetItem, targetAddr):
    global DEBUG_MODE
    if DEBUG_MODE:
      print('ptr to named item: %x to %s' % (ptrAddr, targetItem))
    self.labelManager.setLabel(ptrAddr, 'ptr_%s' % targetItem.getName(True), True, False, True)
    self.referenceManager.recordReference(targetAddr, ptrAddr)
    # type pointer only if default 1-byte type
    if ptrItem.getType().getSize() == 1:
      self.codeUnit.setDataTypeAt(ptrAddr, self.typeManager.getType('void*'))
