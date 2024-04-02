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
    kallsyms_token_table_off: int
    kallsyms_names_off: int


def parse_kallsyms(kernel, offsets: KernelOffsetAndSize) -> KernelSymbols:
    symbols = KernelSymbols()

    # kallsyms_addresses
    offset = offsets.kallsyms_addresses_off
    last_addr = 0
    while True:
        addr = kernel.reader.read_uint32(offset, 0)
        if addr == 0 or addr < last_addr:
            break
        symbols.kallsyms_addresses.append(addr)
        offset += offsets.kallsyms_addresse_size
    symbols.kallsyms_num_syms = len(symbols.kallsyms_addresses)

    # kallsyms_token_table
    offset = offsets.kallsyms_token_table_off
    str_buf = bytearray()
    while True:
        if len(symbols.kallsyms_token_table) > 0xFF:
            break
        c = kernel.reader.read_byte(offset)
        if c == 0:
            token = str_buf.decode("utf-8")
            symbols.kallsyms_token_table.append(token)
            str_buf.clear()
            nc = kernel.reader.read_byte(offset+1)
            if nc == 0 or nc > 0xFF:
                break
        else:
            str_buf.append(c)
        offset += 1
    #for i, token in enumerate(symbols.kallsyms_token_table):
    #    print(hex(i), token)

    # kallsyms_names
    offset = offsets.kallsyms_names_off
    while True:
        if len(symbols.kallsyms_names) >= symbols.kallsyms_num_syms:
            break
        str_len = kernel.reader.read_byte(offset)
        offset += 1
        if str_len == 0 or str_len >= 256:
            break
        sym_name = ""
        for i in range(str_len):
            token_idx = kernel.reader.read_byte(offset)
            assert 0 <= token_idx <= 256
            token = symbols.kallsyms_token_table[token_idx]
            sym_name += token
            offset += 1
        symbols.kallsyms_names.append(sym_name)
    #assert len(symbols.kallsyms_names) == len(symbols.kallsyms_addresses)

    return symbols

