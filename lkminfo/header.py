
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


class ModuleSignature(ctypes.Structure):
    """
    /*
     * Module signature information block.
     *
     * The constituents of the signature section are, in order:
     *
     *	- Signer's name
     *	- Key identifier
     *	- Signature data
     *	- Information block
     */
    struct module_signature {
        u8	algo;		/* Public-key crypto algorithm [0] */
        u8	hash;		/* Digest algorithm [0] */
        u8	id_type;	/* Key identifier type [PKEY_ID_PKCS7] */
        u8	signer_len;	/* Length of signer's name [0] */
        u8	key_id_len;	/* Length of key identifier [0] */
        u8	__pad[3];
        __be32	sig_len;	/* Length of signature data */
    };
    """
    _fields_ = [
        ("algo", ctypes.c_uint8),
        ("hash", ctypes.c_uint8),
        ("id_type", ctypes.c_uint8),
        ("signer_len", ctypes.c_uint8),
        ("key_id_len", ctypes.c_uint8),
        ("__pad", ctypes.c_uint8 * 3),
        ("sig_len", ctypes.c_uint32),
    ]
