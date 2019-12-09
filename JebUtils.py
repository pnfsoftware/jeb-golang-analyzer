"""
JEB utils

(This file is part of JEB Decompiler's scripts used to analyze Golang executables.)
"""

def readNullTerminatedString(memory, curAddress):
  return readString(memory, curAddress, 0)

def readString(memory, curAddress, maxLen):
  '''
    Read UTF-8 string from memory, using the provided maximum length if non zero, or until next null-byte.
  '''
  DEFAULT_MAX_LENGTH = 0x1000

  curChar = ''
  result = list()
  readLength = 0
  if maxLen == 0:
    maxLen = DEFAULT_MAX_LENGTH

  while curChar != 0x00 and readLength < maxLen:
    curChar = memory.readByte(curAddress) & 0xFF
    result.append(chr(curChar))
    curAddress+=1
    readLength+=1

  if curChar == 0x00:
    result = result[:-1]
    
  return ''.join(result).decode('utf-8')

def searchMemoryFor4BConstant(memory, constant, startAddres, endAddress):
  '''
    Return the address of the first occurence of 4-byte constant in given 
    memory range (assuming it is aligned on 4), or 0 if it could not be found.
  '''
  curAddress = startAddres
  while curAddress < endAddress:
    if memory.readInt(curAddress) & 0xFFFFFFFF == constant:
      return curAddress
    curAddress+=4
  return 0
