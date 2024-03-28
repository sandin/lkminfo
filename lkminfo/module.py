import ctypes
import struct

import lief
from dataclasses import dataclass, field
from .header import ModVersionInfo, ModuleSignature


@dataclass
class LoadInfo:
    versions: {} = field(default_factory=dict)
    mod_info: [] = field(default_factory=list)
    this_module: bytes = None


def be32_to_cpu(val):
    return struct.unpack("<I", val.to_bytes(4, 'big'))[0]


def idtype2str(val):
    if val == 0:
        return "PKEY_ID_PGP"
    elif val == 1:
        return "PKEY_ID_X509"
    elif val == 2:
        return "PKEY_ID_PKCS7"
    return str(val)


class Module(object):
    def __init__(self):
        self.file_name = ""  # type: str
        self.load_info = None  # type: LoadInfo
        self.imported_symbols = []  # type: list[str]
        self.exported_symbols = []  # type: list[str]
        self.elf = None  # type: lief.ELF.Binary
        self.sig = None  # type: dict

    def dump(self):
        print("Module info:")
        print("File name: %s" % self.file_name)
        print("ELF:")
        print("\tformat: %s" % self.elf.format.__name__)
        print("\tarch: %s" % self.elf.header.machine_type.__name__)
        print("\tsections:")
        for sec in self.elf.sections:
            print("\t\t0x%s - 0x%s %s" % (sec.offset, sec.offset + sec.size, sec.name))
        print("Signature:")
        if self.sig:
            print("\tid_type: %s" % idtype2str(self.sig['id_type']))
            print("\tsig_len: %d" % len(self.sig['sig_buf']))
            print("\tsig_buf: %s" % str(self.sig['sig_buf']))
        else:
            print("\tNot signed")
        print("Modinfo:")
        for key, value in self.load_info.mod_info:
            print("\t%s = %s" % (key, value))
        print("Versions:")
        for sym_name, crc in self.load_info.versions.items():
            is_imported_func = sym_name in self.imported_symbols
            is_exported_func = sym_name in self.exported_symbols
            sym_type = "NORMAL"
            if is_imported_func:
                sym_type = "IMPORT"
            elif is_exported_func:
                sym_type = "EXPORT"
            print("\t[%s] %s crc: %d" % (sym_type, sym_name, crc))
        print("")

    def find_symbol_crc(self, symbol_name):
        if symbol_name in self.load_info.versions:
            return self.load_info.versions[symbol_name]
        return 0

    def get_modinfo(self, name, def_val):
        for key, value in self.load_info.mod_info:
            if name == key:
                return value
        return def_val


def parse_versions(data: memoryview) -> dict:
    versions = {}

    i = 0
    l = len(data)
    item_size = ctypes.sizeof(ModVersionInfo)
    assert item_size == 64
    assert l % item_size == 0
    while i < l:
        info = ctypes.cast(data[i:i + item_size].tobytes(), ctypes.POINTER(ModVersionInfo)).contents
        name = info.name.decode("utf8")
        #print(name, info.crc)
        versions[name] = info.crc
        i += item_size
    return versions


def parse_modinfo(data: memoryview) -> list:
    modinfo = []
    last_str = ""
    for b in data:
        if b == 0:
            if "=" in last_str:
                tmp = last_str.split("=")
                modinfo.append((tmp[0], tmp[1]))
            last_str = ""
        else:
            last_str += chr(b)
    return modinfo


def parse_this_module(data: memoryview):
    return data.tobytes()


def parse_load_info(elf):
    load_info = LoadInfo()

    section = elf.get_section("__versions")  # type: lief.Section
    if section:
        load_info.versions = parse_versions(section.content)

    section = elf.get_section(".modinfo")  # type: lief.Section
    if section:
        load_info.mod_info = parse_modinfo(section.content)

    section = elf.get_section(".gnu.linkonce.this_module")  # type: lief.Section
    if section:
        load_info.this_module = parse_this_module(section.content)

    return load_info


def parse_symbols(elf: lief.ELF.Binary):
    imported_symbols = []
    exported_symbols = []
    for sym in elf.symbols:
        sym = sym  # type: lief.ELF.Symbol
        if sym.shndx == lief.ELF.SYMBOL_SECTION_INDEX.UNDEF:
            imported_symbols.append(sym.name)
    return imported_symbols, exported_symbols


def parse_sig(ko_file: str):
    MODULE_SIG_STRING = b"~Module signature appended~\n"
    with open(ko_file, "rb") as f:
        data = memoryview(f.read())
        size = len(data)
        off = size - len(MODULE_SIG_STRING)
        mark = data[off:].tobytes()
        print("sig mark: ", mark)
        if mark == MODULE_SIG_STRING:
            pass
            off = size - len(MODULE_SIG_STRING) - ctypes.sizeof(ModuleSignature)
            buf = data[off:off+ctypes.sizeof(ModuleSignature)].tobytes()
            sig = ctypes.cast(buf, ctypes.POINTER(ModuleSignature)).contents  # type: ModuleSignature
            #print("id_type", idtype2str(sig.id_type))
            assert sig.id_type == 2  # PKEY_ID_PKCS7
            sig_len = be32_to_cpu(sig.sig_len)
            #print("sig_len", sig_len)
            assert sig_len < 4096
            off = size - len(MODULE_SIG_STRING) - ctypes.sizeof(ModuleSignature) - sig_len
            buf = data[off:off+sig_len].tobytes()
            return {"id_type": sig.id_type, "sig_buf": buf}
    return None


def load_module(ko_file) -> Module:
    binary = lief.parse(ko_file)
    if binary.format != lief.Binary.FORMATS.ELF:
        return None
    elf = binary  # type: lief.ELF.Binary

    module = Module()
    module.elf = elf
    module.file_name = ko_file
    module.sig = parse_sig(ko_file)
    module.load_info = parse_load_info(elf)
    symbols = parse_symbols(elf)
    module.imported_symbols = symbols[0]
    module.exported_symbols = symbols[1]

    return module
