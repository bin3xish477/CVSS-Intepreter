#!/usr/bin/env python3

try:
  from sys import argv, exit
  from os import _exit
except ImportError as err:
  print(f"Import Error: {err}")
  
def main():
  pass

if __name__ == '__main__':
  try:
    main()
  except KeyboardInterrupt:
    try:
      exit(1)
    except SystemExit:
      _exit(1)
