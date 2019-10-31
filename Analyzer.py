from com.pnfsoftware.jeb.core.units import WellKnownUnitTypes, INativeCodeUnit
from com.pnfsoftware.jeb.core.units.codeobject import ProcessorType, CodeObjectUnitUtil
from java.lang import Runnable
from com.pnfsoftware.jeb.client.api import IScript, IGraphicalClientContext

import os

import JebUtils
from StringsBuilder import StringsBuilder
from FunctionsFinder import FunctionsFinder
from TypesBuilder import TypesBuilder
from DuffDevicesFinder import DuffDevicesFinder
from PointerAnalyzer import PointerAnalyzer
from Commons import StringHeader, SliceHeader, BitVector, ModuleData, PcLineTable, FunctionSymbolTableEntry, getPclntab, buildPclntab, getModuleDataList, buildModuleDataList

"""
JEB Decompiler's script to analyze Golang executables.
Reference: Blog: https://www.pnfsoftware.com/blog/analyzing-golang-executables/
Version 1.0 - Oct 2019 (Joan Calvet - PNF Software)

Modules:
  - FunctionsFinder: recover routines entry points and rename them
  - StringsBuilder: build proper strings
  - TypesBuilder: recover types, and import them in JEB
  - DuffDevicesFinder: rename routines for zeroing/copying memory
  - PointerAnalyzer: improve pointer naming

The script was tested primarily on Go 1.13, most features should work on Go >= 1.5.
You might want to deactivate specific modules on older Go versions (see globals below).
"""

# customize these values to (de)activate features
FIND_FUNCTIONS    = True
BUILD_STRINGS     = True
BUILD_TYPES       = True
FIND_DUFF_DEVICES = True
POINTER_ANALYZER  = True

# manually provide structures addresses if heuristic search fail
PCLNTAB_ADDR           = 0x0
FIRST_MODULE_DATA_ADDR = 0x0

class Analyzer(IScript):

  def run(self, clientContext):
    if not isinstance(clientContext, IGraphicalClientContext):
      print('This script must be run within a graphical client')
      return
    # run analyzer in separate thread
    clientContext.executeAsync('Golang analyzer...', GolangAnalyzerTask(clientContext))

class GolangAnalyzerTask(Runnable):
  SUPPORTED_FILE_FORMATS = [WellKnownUnitTypes.typeWinPe, WellKnownUnitTypes.typeLinuxElf]

  def __init__(self, clientContext):
    self.codeContainerUnit = None
    self.codeUnit = None
    self.nativeCodeAnalyzer = None
    self.typeManager = None
    self.pclntab = None
    self.moduleDataList = None
    self.moduleStats = dict() # module name -> stats
    self.getUnits(clientContext.getMainProject())

  def getUnits(self, mainProject):
    '''
      Retrieves the first supported executable file from JEB project
      and the corresponding child code unit, native code analyzer and type manager.
    '''
    for unit in mainProject.getLiveArtifact(0).getUnits(): # assume first artifact is the good one
      if unit.getFormatType() in self.SUPPORTED_FILE_FORMATS:
        self.codeContainerUnit = unit
        break
    if not self.codeContainerUnit:
      raise Exception('cannot find suitable code container unit (supported=%s)' % self.SUPPORTED_FILE_FORMATS)

    for unit in self.codeContainerUnit.getChildren():
      if isinstance(unit, INativeCodeUnit):
        self.codeUnit = unit
        break
    if not self.codeUnit:
      raise Exception('cannot find native code unit')

    self.nativeCodeAnalyzer = self.codeUnit.getCodeAnalyzer()
    self.typeManager = self.codeUnit.getTypeManager()

  def run(self):
    global FIND_FUNCTIONS, BUILD_STRINGS, BUILD_TYPES, FIND_DUFF_DEVICES, POINTER_ANALYZER

    print('>>> Golang Analyzer <<<')
    metadataFound = self.getMetadata()
    if not metadataFound:
      print('> error: cannot find metadata')
      return
    
    if FIND_FUNCTIONS:
      functionsFinder = FunctionsFinder(self)
      isStripped = False if CodeObjectUnitUtil.findSymbolByName(self.codeContainerUnit, 'runtime.pclntab') else True
      functionsFinder.run(self.pclntab, isStripped)
      self.moduleStats[functionsFinder.__class__.__name__] = functionsFinder.getStats()

    if BUILD_STRINGS:
      stringsBuilder = StringsBuilder(self)
      stringsBuilder.run()
      self.moduleStats[stringsBuilder.__class__.__name__] = stringsBuilder.getStats()

    if BUILD_TYPES:
      typesBuilder = TypesBuilder(self)
      typesBuilder.run()
      self.moduleStats[typesBuilder.__class__.__name__] = typesBuilder.getStats()

    if FIND_DUFF_DEVICES:
      duffDevicesFinder = DuffDevicesFinder(self)
      duffDevicesFinder.run()
    
    if POINTER_ANALYZER:
      ptrAnalyzer = PointerAnalyzer(self)
      ptrAnalyzer.run()

    self.printStats('log.txt')

  def getMetadata(self):
    '''
      Locate and parse needed metadata in memory, depending on the wanted features.

      Return True on success, False otherwise.
    '''
    global BUILD_TYPES

    # pclntab is needed for all modules,
    # because it provides pointer size
    pclntabParsing = self.parsePcntab()
    if pclntabParsing:
      print('> pclntab parsed (0x%X)' % self.pclntab.startAddr)
    else:
      print('> ERROR: cannot find pclntab -- suggestion: provide hardcoded address (Analyzer.PCLNTAB_ADDR)')
      return False

    self.importBasicTypes()

    # types-specific parsing
    if BUILD_TYPES:
      firstMdParsing = self.parseFirstModuleData()
      if firstMdParsing:
        print('> first module data parsed (0x%X)' % self.moduleDataList[0].startAddr)
      else:
        print('> ERROR: cannot find module data list -- suggestions: deactivate types building (Analyzer.BUILD_TYPES)' \
                      ' or provide hardcoded address (Analyzer.FIRST_MODULE_DATA_ADDR)')
        return False
    return True

  def parsePcntab(self):
    global PCLNTAB_ADDR

    if PCLNTAB_ADDR == 0x0:
      self.pclntab = getPclntab(self)
    else:
      print('> using provided address for pclntab (0x%X)' % PCLNTAB_ADDR)
      self.pclntab = buildPclntab(self, PCLNTAB_ADDR)
    if self.pclntab == None:
      return False
    return True

  def parseFirstModuleData(self):
    global FIRST_MODULE_DATA_ADDR
    if FIRST_MODULE_DATA_ADDR == 0x0:
      self.moduleDataList = getModuleDataList(self)
    else:
      print('> using provided address for first module data (0x%X)' % FIRST_MODULE_DATA_ADDR)
      self.moduleDataList = buildModuleDataList(self, FIRST_MODULE_DATA_ADDR)
    if self.moduleDataList == None or len(self.moduleDataList) == 0:
      return False
    return True

  def importBasicTypes(self):
    '''
      Built-in types that are needed by different modules.
    '''
    StringHeader.createJebStructure(self.typeManager, self.pclntab.ptrSize)
    SliceHeader.createJebStructure(self.typeManager, self.pclntab.ptrSize)
    BitVector.createJebStructure(self.typeManager, self.pclntab.ptrSize)
    ModuleData.createJebStructure(self.typeManager, self.pclntab.ptrSize)

  def printStats(self, file):
    STAT_SEPARATOR = '\n======================================\n'

    filePath = os.path.join(os.path.dirname(os.path.abspath(__file__)), file)
    f = open(filePath, 'w')
  
    # generic stats
    statStr = '> General information:\n'
    generalInfo = False
    if self.pclntab != None:
      if len(self.pclntab.sourceFiles) != 0:
        statStr += '\n\t> source files (extracted from pclntab):\n'
        for sourceFile in sorted(self.pclntab.sourceFiles):
          statStr += '\t\t> %s\n' % sourceFile
        generalInfo = True
        statStr += STAT_SEPARATOR
    if not generalInfo:
      statStr = ''

    # module-specific stats
    for module in self.moduleStats:
      statStr += '> %s:\n%s' % (module, self.moduleStats[module])
      statStr += STAT_SEPARATOR

    f.write(statStr)
    f.close()
    print('> see logs (%s)' % filePath)




