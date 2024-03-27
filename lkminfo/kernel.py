from dataclasses import dataclass, field
import ctypes
import re
import struct
from .header import KernelSymbol
from .module import Module


class BinaryReader(object):

    def __init__(self, filename, bias):
        self._bias = bias
        with open(filename, "rb") as f:
            self.data = memoryview(f.read())

    def size(self):
        return len(self.data)

    def read_bytes(self, offset: int, size: int):
        off = offset - self._bias
        return self.data[off:off+size].tobytes()

    def read_uint64(self, offset: int):
        data = self.read_bytes(offset, 8)
        return struct.unpack("<Q", data)[0]

    def read_c_string(self, offset: int):
        off = offset - self._bias
        buf = bytearray()
        for b in self.data[off:off+4096]:
            if b == 0:
                break
            buf.append(b)
        return buf.decode('utf8')


class Kernel(object):

    def __init__(self, kernel_file, kallsyms_file):
        self.kernel_file = kernel_file
        self.kallsyms_file = kallsyms_file
        self.kallsyms = {}
        self.kallsyms_addr = {}  # cache
        self.symbols: []
        self.vermagic = ""   # type: str

    def dump(self):
        print("Kernel Info:")
        print("File name: %s (size: %d)" % (self.kernel_file, self.reader.size()))
        print("Symbol name: %s" % self.kallsyms_file)
        #print("Symbols in kallsyms:")
        #for sym_name, sym_addr in self.kallsyms.items():
        #    print("\t0x%x: %s" % (sym_addr, sym_name))
        print("Symbols in kernel:")
        for kernel_symbol in self.symbols:
            print("\t%s crc: %d" % (kernel_symbol['name'], kernel_symbol['crc']))
        print("")

    def load(self):
        self.kallsyms = Kernel.parse_kallsyms(self.kallsyms_file)
        for symbol_name, symbol_addr in self.kallsyms.items():
            if symbol_addr not in self.kallsyms_addr:
                self.kallsyms_addr[symbol_addr] = symbol_name
        self.reader = BinaryReader(self.kernel_file, self.find_symbol("_head"))
        self.symbols = self.parse_kernel_symbols()
        self.vermagic = self.parse_vermagic()
        if len(self.symbols) == 0:
            print("Error: can not parse kernel symbols")
            return False
        return True

    @staticmethod
    def parse_kallsyms(kallsyms_file):
        p = re.compile(r'^(\w+) (\w) (\w+)$')
        symbols = {}
        with open(kallsyms_file, "r") as f:
            for line in f:
                # ffffff8d4280082c T start_kernel
                line = line.strip()
                if line:
                    m = p.match(line)
                    if m:
                        address = int(m[1], base=16)
                        type_ = m[2]
                        name = m[3]
                        symbols[name] = address
        #for (addr, name) in symbols.items():
        #    print("%s: %s" % (addr, name))
        return symbols

    def parse_kernel_symbols(self):
        kernel_symbols = []
        symbol_sections = [
            ("__start___ksymtab", "__stop___ksymtab", "__start___kcrctab", "__ksymtab_")
        ]
        for (start_sym, stop_sym, crc_sym, prefix) in symbol_sections:
            start_addr = self.find_symbol(start_sym)
            assert start_addr
            stop_addr = self.find_symbol(stop_sym)
            assert stop_addr
            crc_addr = self.find_symbol(crc_sym)
            assert crc_sym

            item_size = ctypes.sizeof(KernelSymbol)
            offset = start_addr + item_size
            crc_offset = 8  # sizeof(uint64_t)
            while offset < stop_addr:
                symbol_name = self.find_symbol_by_addr(offset)[len(prefix):]
                crc = self.reader.read_uint64(crc_addr + crc_offset)
                #data = self.reader.read_bytes(offset, item_size)
                #kernel_symbol = ctypes.cast(data, ctypes.POINTER(KernelSymbol)).contents
                #print("symbol_name", symbol_name, "crc", crc)
                kernel_symbols.append({"name": symbol_name, "crc": crc})
                offset += item_size
                crc_offset += 8  # sizeof(uint64_t)
        return kernel_symbols

    def find_symbol(self, symbol_name):
        if symbol_name in self.kallsyms:
            return self.kallsyms[symbol_name]
        else:
            print("Error: can not find symbols(`%s`) in %s" % (symbol_name, self.kallsyms_file))
            return None

    def find_symbol_by_addr(self, symbol_addr):
        if symbol_addr in self.kallsyms_addr:
            return self.kallsyms_addr[symbol_addr]
        else:
            print("Error: can not find symbols(`0x%x`) in %s" % (symbol_addr, self.kallsyms_file))
            return None

    def find_symbol_crc(self, symbol_name):
        for kernel_symbol in self.symbols:
            if kernel_symbol['name'] == symbol_name:
                return kernel_symbol['crc']
        return 0

    def parse_vermagic(self):
        offset = self.find_symbol("vermagic")
        return self.reader.read_c_string(offset)

    def verify(self, module: Module):
        print("Verify module by kernel:")
        module_layout_expect = self.find_symbol_crc("module_layout")
        module_layout_actual = module.find_symbol_crc("module_layout")
        if module_layout_actual != module_layout_expect:
            print("[Error]: module_layout mismatch, expect value in kernel: %d, actual value in module: %d" % (module_layout_expect, module_layout_actual))
            return False

        vermagic_expect = self.vermagic
        vermagic_actual = module.get_modinfo("vermagic", None)
        if vermagic_actual != vermagic_expect:
            print("[Error]: vermagic mismatch, expect value in kernel: %s, actual value in module: %s" % (vermagic_expect, vermagic_actual))
            return False

        mismatch_cnt = 0
        for sym_name in module.imported_symbols:
            if not sym_name:
                continue
            crc_expect = self.find_symbol_crc(sym_name)
            if crc_expect == 0:
                print("[Warning]: crc of symbol `%s` do not exists in kernel" % (sym_name,))
                continue
            crc_actual = module.find_symbol_crc(sym_name)
            if crc_actual != crc_expect:
                print("[Error]: crc of symbol `%s` mismatch, expect value in kernel: %d, actual value in module: %d" % (sym_name, crc_expect, crc_actual))
                mismatch_cnt += 0
        if mismatch_cnt > 0:
            return False

        return True
