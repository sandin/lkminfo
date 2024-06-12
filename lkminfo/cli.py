import argparse
import os.path

from .module import load_module
from .kernel import Kernel
from .patch import patch_module, PatchConfig


def cmd_kallsyms(args):
    kernel = Kernel(args.kernel, None, config={"crc_item_size": 4})
    ok = kernel.load()
    if not ok:
        print("Error: can not load kernel, file: %s with %s" % (args.kernel, args.kallsyms))
        exit(-1)

    offsets = kernel.guess_offsets()
    if args.kallsyms_addresses_off:
        offsets.kallsyms_addresses_off = args.kallsyms_addresses_off
    if args.kallsyms_addresse_size:
        offsets.kallsyms_addresse_size = args.kallsyms_addresse_size
    if args.kallsyms_names_off:
        offsets.kallsyms_names_off = args.kallsyms_names_off
    if args.kallsyms_token_table_off:
        offsets.kallsyms_token_table_off = args.kallsyms_token_table_off

    if offsets.kallsyms_token_table_off == 0 or offsets.kallsyms_addresses_off == 0 or offsets.kallsyms_names_off == 0:
        print("Error: offsets can not be null")
        exit(-1)

    head = int(args.head, base=16)
    symbols = kernel.proc_kallsyms(offsets)
    with open(args.output, "w") as f:
        for index, symbol_addr in enumerate(symbols.kallsyms_addresses):
            if index >= len(symbols.kallsyms_names):
                break  # skip all module symbols
            symbol_name = symbols.kallsyms_names[index]
            symbol_type = symbol_name[0:1]
            symbol_name = symbol_name[1:]
            line = "%x %s %s" % (head + symbol_addr, symbol_type, symbol_name)
            f.write(line + "\n")
    print("Found %d kernel symbols and write them to the file: %s" % (symbols.kallsyms_num_syms, args.output))


def cmd_verify(args):
    kernel = Kernel(args.kernel, args.kallsyms, config={"crc_item_size": 4})
    ok = kernel.load()
    if not ok:
        print("Error: can not load kernel, file: %s with %s" % (args.kernel, args.kallsyms))
        exit(-1)
    kernel.dump()

    if args.module:
        module = load_module(args.module)
        module.dump()
        error_cnt, match_cnt = kernel.verify(module)
        if error_cnt == 0:
            print("Verify result: OK")
        else:
            print("Verify result: Failed, match: %d, mismatch: %d" % (match_cnt, error_cnt))


def cmd_dump(args):
    if args.kernel and args.kallsyms:
        if not os.path.exists(args.modukernelle):
            print("Error: %s file is exists!" % args.kernel)
            exit(-1)
        if not os.path.exists(args.kallsyms):
            print("Error: %s file is exists!" % args.kallsyms)
            exit(-1)
        kernel = Kernel(args.kernel, args.kallsyms, config={"crc_item_size": 4})
        ok = kernel.load()
        if ok:
            kernel.dump()

    if args.module:
        if not os.path.exists(args.module):
            print("Error: %s file is exists!" % args.module)
            exit(-1)
        module = load_module(args.module)
        module.dump()


def cmd_patch(args):
    kernel = Kernel(args.kernel, args.kallsyms, config={"crc_item_size": 4})
    ok = kernel.load()
    if not ok:
        print("Error: can not load kernel, file: %s with %s" % (args.kernel, args.kallsyms))
        exit(-1)

    module = load_module(args.module)
    print("Before patch verify:")
    error_cnt, match_cnt = kernel.verify(module)
    if error_cnt == 0:
        print("No need to patch")
        exit(-1)
    print("")

    patch_config = PatchConfig()
    if args.patch_crc:
        patch_config.patch_versions = True
    ret, err = patch_module(kernel, module, patch_config, args.output)
    if ret:
        print("Patch done, output: %s" % args.output)
        print("After patch verify:")
        module = load_module(args.output)
        error_cnt, match_cnt = kernel.verify(module)
        if error_cnt == 0:
            print("Verify result: OK")
        else:
            print("Verify result: Failed, match: %d, mismatch: %d" % (match_cnt, error_cnt))
    else:
        print("Error: %s" % err)


def main():
    parser = argparse.ArgumentParser(prog="lkminfo")
    subparsers = parser.add_subparsers(required=True)

    parser_verify = subparsers.add_parser("dump")
    parser_verify.add_argument("-k", "--kernel", help="kernel image file", required=False)
    parser_verify.add_argument("-s", "--kallsyms", help="kernel symbol file", required=False)
    parser_verify.add_argument("-m", "--module", help="kernel module file(*.ko)", required=False)
    parser_verify.set_defaults(func=cmd_dump)

    parser_verify = subparsers.add_parser("verify")
    parser_verify.add_argument("-k", "--kernel", help="kernel image file", required=True)
    parser_verify.add_argument("-s", "--kallsyms", help="kernel symbol file", required=True)
    parser_verify.add_argument("-m", "--module", help="kernel module file(*.ko)", required=False)
    parser_verify.set_defaults(func=cmd_verify)

    parser_patch = subparsers.add_parser("patch")
    parser_patch.add_argument("-k", "--kernel", help="kernel image file", required=True)
    parser_patch.add_argument("-s", "--kallsyms", help="kernel symbol file", required=True)
    parser_patch.add_argument("-m", "--module", help="kernel module file(*.ko)", required=True)
    parser_patch.add_argument("-o", "--output", help="output file(*.ko)", required=True)
    parser_patch.add_argument("-c", "--patch_crc", action="store_true", help="patch all crc of symbols", required=False)
    parser_patch.set_defaults(func=cmd_patch)

    kallsyms_verify = subparsers.add_parser("kallsyms")
    kallsyms_verify.add_argument("-k", "--kernel", help="kernel image file", required=True)
    kallsyms_verify.add_argument("-o", "--output", help="output file(kallsyms)", required=True)
    kallsyms_verify.add_argument("--head", help="head offset", type=str, default="0x0", required=False)
    kallsyms_verify.add_argument("--kallsyms_addresses_off", help="kallsyms_addresses offset", type=int, required=False)
    kallsyms_verify.add_argument("--kallsyms_addresse_size", help="kallsyms_addresse size", type=int, required=False)
    kallsyms_verify.add_argument("--kallsyms_names_off", help="kallsyms_names offset", type=int, required=False)
    kallsyms_verify.add_argument("--kallsyms_token_table_off", help="kallsyms_token_table offset", type=int, required=False)
    kallsyms_verify.set_defaults(func=cmd_kallsyms)

    args = parser.parse_args()
    args.func(args)
