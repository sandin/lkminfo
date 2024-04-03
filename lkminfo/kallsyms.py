import struct
from dataclasses import dataclass, field


@dataclass
class KernelSymbols:
    kallsyms_addresses: list[int] = field(default_factory=list)
    kallsyms_num_syms: int = 0
    kallsyms_token_table: list[str] = field(default_factory=list)
    kallsyms_names: list[str] = field(default_factory=list)


@dataclass
class KernelOffsetAndSize:
    kallsyms_addresses_off: int
    kallsyms_addresse_size: int
    kallsyms_names_off: int
    kallsyms_token_table_off: int


def parse_kallsyms_token_table(kernel, offset):
    kallsyms_token_table = []
    str_buf = bytearray()
    while True:
        if len(kallsyms_token_table) > 0xFF:
            break
        c = kernel.reader.read_byte(offset)
        if c == 0:
            token = str_buf.decode("utf-8")
            kallsyms_token_table.append(token)
            str_buf.clear()
            nc = kernel.reader.read_byte(offset+1)
            if nc == 0 or nc > 0xFF:
                break
        else:
            str_buf.append(c)
        offset += 1
    #for i, token in enumerate(symbols.kallsyms_token_table):
    #    print(hex(i), token)
    return kallsyms_token_table


def parse_kallsyms_names(kernel, offset, kallsyms_token_table):
    kallsyms_names = []
    while True:
        #if len(kallsyms_names) >= kallsyms_num_syms:
        #    break
        str_len = kernel.reader.read_byte(offset)
        offset += 1
        if str_len == 0 or str_len >= 256:
            break
        sym_name = ""
        for i in range(str_len):
            token_idx = kernel.reader.read_byte(offset)
            assert 0 <= token_idx <= 256
            token = kallsyms_token_table[token_idx]
            sym_name += token
            offset += 1
        kallsyms_names.append(sym_name)
    return kallsyms_names


def compress_symbol_name(kallsyms_token_table: list[str], symbol_type, symbol_name):
    name = symbol_type + symbol_name  # type: str
    start_idx = 0
    end_idx = len(name)
    compressed = bytearray()
    while start_idx <= end_idx:  # len(name):
        token = name[start_idx:end_idx]
        if token in kallsyms_token_table:
            compressed.append(kallsyms_token_table.index(token))
            start_idx += len(token)
            end_idx = len(name)
        else:
            end_idx -= 1
    return compressed


def parse_kallsyms(kernel, offsets: KernelOffsetAndSize) -> KernelSymbols:
    symbols = KernelSymbols()

    # kallsyms_addresses
    offset = offsets.kallsyms_addresses_off
    last_addr = None
    while True:
        addr = kernel.reader.read_uint32(offset, 0)
        if last_addr is not None and (addr < last_addr):
            break
        symbols.kallsyms_addresses.append(addr)
        offset += offsets.kallsyms_addresse_size
        last_addr = addr
    symbols.kallsyms_num_syms = len(symbols.kallsyms_addresses)
    symbols.kallsyms_token_table = parse_kallsyms_token_table(kernel, offsets.kallsyms_token_table_off)
    symbols.kallsyms_names = parse_kallsyms_names(kernel, offsets.kallsyms_names_off, symbols.kallsyms_token_table)
    assert len(symbols.kallsyms_names) == symbols.kallsyms_num_syms
    return symbols


def guess_offsets_for_kallsyms(kernel) -> KernelOffsetAndSize:
    offsets = KernelOffsetAndSize(0, 4, 0, 0)
    data = kernel.reader.data.tobytes()

    # kallsyms_token_table
    magic = bytes([0x61, 0x00, 0x62, 0x00, 0x63, 0x00, 0x64, 0x00, 0x65, 0x00, 0x66, 0x00, 0x67, 0x00, 0x68, 0x00,
                   0x69, 0x00, 0x6A, 0x00, 0x6B, 0x00, 0x6C, 0x00, 0x6D, 0x00, 0x6E, 0x00, 0x6F, 0x00, 0x70, 0x00,
                   0x71, 0x00, 0x72, 0x00, 0x73, 0x00, 0x74, 0x00, 0x75, 0x00, 0x76, 0x00, 0x77, 0x00, 0x78, 0x00,
                   0x79, 0x00, 0x7A, 0x00])  # `a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.`
    start = 0
    offset = data.find(magic, start)
    while offset != -1:
        start = offset + len(magic)
        next_two_bytes = data[start:start+2]
        if next_two_bytes == bytes([0x7B, 0x00]):  # there's no way it could be like `x.y.z.{.`, so keep searching
            offset = data.find(magic, start)
        else:
            break  # found
    if offset == -1:
        print("Error: can not find the kallsym_token_table")
        return offsets
    cnt = 0
    offset -= 1
    # the range of the token table is [0, 255], and we've currently found the element with index 97 ('a'),
    # so we still need to go forward and find the offset of the first element
    while True:
        if cnt >= ord('a'):
            while True:
                if data[offset] == 0:
                    break
                offset -= 1
            offset += 1  # we are looking for `\x00` in reverse order, so we need to +1 when we find the first one
            break
        c = data[offset]
        if c == 0:
            cnt += 1
        offset -= 1
    offsets.kallsyms_token_table_off = offset
    kallsyms_token_table = parse_kallsyms_token_table(kernel, offsets.kallsyms_token_table_off)

    # kallsyms_names
    # now we have the token table, so we can locate the name of the first symbol using the binary
    first_symbol_name_bin = compress_symbol_name(kallsyms_token_table, "t", "_head")
    start = 0
    offset = data.find(first_symbol_name_bin, start)
    while offset != -1:
        start = offset
        pre_byte = struct.unpack("<B", data[offset-1:offset])[0]
        if pre_byte != len(first_symbol_name_bin):
            offset = data.find(first_symbol_name_bin, start)
        else:
            break  # found
    if offset == -1:
        print("Error: can not find the kallsym_names")
        return offsets
    offsets.kallsyms_names_off = offset - 1  # there is a length of name before each symbol name, so we need -1
    kallsyms_names = parse_kallsyms_names(kernel, offsets.kallsyms_names_off, kallsyms_token_table)

    # kallsyms_addresses
    # now that we know the offset of kallsyms_names, let's assume that kallsyms_addresses is not far in front of it,
    # and that kallsyms_addresses consists of an increasing sequence of the number of kallsyms_names.
    offset = offsets.kallsyms_names_off
    cnt = 0
    last_address = 0
    while cnt < len(kallsyms_names) - 1:
        address = struct.unpack("<I", data[offset:offset+offsets.kallsyms_addresse_size])[0]
        if address <= last_address:
            cnt += 1
        else:
            cnt = 0
        last_address = address
        offset -= offsets.kallsyms_addresse_size
    # in the last iteration we subtracted the length of one element redundantly, so we need to add it back here
    offsets.kallsyms_addresses_off = offset + offsets.kallsyms_addresse_size
    if offset == -1:
        print("Error: can not find the kallsym_addresses")
        return offsets

    return offsets
