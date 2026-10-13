import hashlib

class FileMetadata:
    def __init__(self, filePath: str, maxBytes: int = 10*1024*1024):
        self.filePath = filePath

        with open(filePath, "rb") as f:
            self.rawBytes = f.read()

        self.fileSize = len(self.rawBytes)
        if self.fileSize >  maxBytes:
            raise ValueError(f"File size {self.fileSize} bytes exceed limit of {maxBytes // 1048576}MB")

        self.fileHash = hashlib.sha256(self.rawBytes).hexdigest()

    def __repr__(self):
        return (f"size:{self.fileSize} bytes, sha256: {self.fileHash}")
