
import ctypes


class KernelSymbol(ctypes.Structure):
    """
    struct kernel_symbol
    {
        unsigned long value;
        const char *name;
    };
    """
    _fields_ = [
        ("crc", ctypes.c_uint64),
        ("name", ctypes.c_void_p)
    ]


class ModVersionInfo(ctypes.Structure):
    """
    struct modversion_info {
        unsigned long crc;
        char name[MODULE_NAME_LEN]; // MODULE_NAME_LEN = 64 - sizeof(unsigned long)
    };
    """
    _fields_ = [
        ("crc", ctypes.c_uint64),
        ("name", ctypes.c_char * 56)
    ]