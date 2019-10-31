from com.pnfsoftware.jeb.core.units.code import EntryPointDescription
from com.pnfsoftware.jeb.core.units.code.asm.analyzer import INativeCodeAnalyzer

from Commons import PcLineTable, locatePclntab

"""
Recover function entry points from pclntab structure, and disassemble them.

If the binary is stripped, name the functions with the symbols provided in the structure.

Also, print hints when special routines are found (see ROUTINES_OF_INTEREST).

(This file is part of JEB Decompiler's scripts used to analyze Golang executables.)
"""

# name -> point of interest
ROUTINES_OF_INTEREST = {'runtime.GOROOT': 'references Go root path of developer\'s machine (sys.DefaultGoroot)', \
                        'runtime.Version': 'references Go version (sys.TheVersion)', \
                        'runtime.schedinit': 'references Go version (sys.TheVersion)'}

class FunctionsFinder():

  def __init__(self, golangAnalyzer):
    self.golangAnalyzer = golangAnalyzer
    self.nativeCodeAnalyzer = self.golangAnalyzer.nativeCodeAnalyzer
    self.labelManager = self.golangAnalyzer.codeUnit.getCodeModel().getLabelManager()

  def run(self, pclntab, rename):
    global ROUTINES_OF_INTEREST

    for myFunc in pclntab.functionSymbolTable.values():
      self.nativeCodeAnalyzer.enqueuePointerForAnalysis(EntryPointDescription(myFunc.startPC), INativeCodeAnalyzer.PERMISSION_FORCEFUL)
      if rename:
        self.labelManager.setLabel(myFunc.startPC, myFunc.name, True, True, False)

    self.stats = '%d function entry points enqueued %s' % (len(pclntab.functionSymbolTable.values()), '(and renamed)' if rename else '')        
    print('> %s: %s' % (self.__class__.__name__, self.stats))
    print('> %s: running disassembler...' % self.__class__.__name__),
    self.nativeCodeAnalyzer.analyze()
    print('OK')

    # notifications for routines of interest
    for rtnName in ROUTINES_OF_INTEREST:
      rtnAddr = self.labelManager.resolveLabel(rtnName)
      if rtnAddr != None:
        print(' > point of interest: routine %s (0x%x): %s' % (rtnName, rtnAddr, ROUTINES_OF_INTEREST[rtnName]))

  def getStats(self):
    return self.stats
