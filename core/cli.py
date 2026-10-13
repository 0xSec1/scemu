import os
import sys
import argparse

# some file checks
def validateFile(filename):
    if not os.path.exists(filename):
        raise argparse.ArgumentTypeError("File does not exists")

    extension = os.path.splitext(filename)[1][1:]
    if extension != "bin":
        raise argparse.ArgumentTypeError("Error: provide a bin file")

    if os.path.getsize(filename) == 0:
        raise argparse.ArgumentTypeError("Error: File is empty!")

    return filename
