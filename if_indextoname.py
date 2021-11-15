import ctypes
import ctypes.util

libc = ctypes.CDLL(ctypes.util.find_library('c'))

def if_nametoindex (name):
    if not isinstance (name, str):
        raise TypeError ('name must be a string.')
    ret = libc.if_nametoindex (name)
    return ret

def if_indextoname (index):
    if not isinstance (index, int):
        index = int(index)
    libc.if_indextoname.argtypes = [ctypes.c_uint32, ctypes.c_char_p]
    libc.if_indextoname.restype = ctypes.c_char_p

    ifname = ctypes.create_string_buffer (32)
    ifname = libc.if_indextoname (index, ifname)
    return ifname