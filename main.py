#!/usr/bin/env python3
import argparse
from core.cli import validateFile

if __name__ == '__main__':

    #CLI arguments parsing
    parser = argparse.ArgumentParser(description="Shellcode Emulator", suggest_on_error=True)
    parser.add_argument("filename", help="Process filename", type=validateFile)

    args = parser.parse_args()
