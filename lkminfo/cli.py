import argparse
from .module import load_module
from .kernel import Kernel
from .patch import patch_module


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

    ret, err = patch_module(kernel, module, args.output)
    if ret:
        print("Patch done, output: %s" % args.output)
        print("After patch verify:")
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
    parser_patch.set_defaults(func=cmd_patch)

    args = parser.parse_args()
    args.func(args)
