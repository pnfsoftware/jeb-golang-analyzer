# JEB Decompiler's scripts to analyze Golang executables.

## Information

Main: Analyzer.py

The script was tested primarily on Go 1.13, most features should work on Go >= 1.5.
You might want to deactivate specific modules on older Go versions (see globals in Analyzer.py).

Support Modules:

- FunctionsFinder: recover routines entry points and rename them
- StringsBuilder: build proper strings
- TypesBuilder: recover types, and import them in JEB
- DuffDevicesFinder: rename routines for zeroing/copying memory
- PointerAnalyzer: improve pointer naming

## References

Blog: https://www.pnfsoftware.com/blog/analyzing-golang-executables/

How to run JEB scripts: https://www.pnfsoftware.com/jeb/manual/dev/introducing-jeb-extensions/#executing-scripts

## Version
  
Version 1.0 - Oct 2019 (Joan Calvet - PNF Software - joe@pnfsoftware.com)
