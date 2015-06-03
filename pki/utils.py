def bytesToString(bytes):
    return bytes.tostring()

def stringToBytes(s):
    bytes = createByteArrayZeros(0)
    bytes.fromstring(s)
    return bytes

def createByteArrayZeros(howMany):
    return array.array('B', [0] * howMany)

def BytesToBin(bytes):
    """Convert byte string to bit string."""
    return "".join([_PadByte(IntToBin(ord(byte))) for byte in bytes])

def _PadByte(bits):
    """Pad a string of bits with zeros to make its length a multiple of 8."""
    r = len(bits) % 8
    return ((8-r) % 8)*'0' + bits

def IntToBin(n):
    if n == 0 or n == 1:
        return str(n)
    elif n % 2 == 0:
        return IntToBin(n/2) + "0"
    else:
        return IntToBin(n/2) + "1"
