def read_scalar(length, bytes):
    """Return an integer representing the next <length> of bytes"""
    t = 0
    while length:
        length -= 1
        next = bytes.read(8).uint
        t = (t << 8) + next
    return t