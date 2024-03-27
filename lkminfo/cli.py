import argparse
from .module import load_module
from .kernel import Kernel


def cmd_verify(args):
    kernel = Kernel(args.kernel, args.kallsyms)
    ok = kernel.load()
    if not ok:
        print("Error: can not load kernel, file: %s with %s" % (args.kernel, args.kallsyms))
        exit(-1)
    kernel.dump()

    if args.module:
        module = load_module(args.module)
        module.dump()
        ok = kernel.verify(module)
        print("verify result: %s" % str(ok))


def main():
    parser = argparse.ArgumentParser(prog="lkminfo")
    subparsers = parser.add_subparsers(required=True)

    parser_verify = subparsers.add_parser("verify")
    parser_verify.add_argument("-k", "--kernel", help="kernel image file", required=True)
    parser_verify.add_argument("-s", "--kallsyms", help="kernel symbol file", required=True)
    parser_verify.add_argument("-m", "--module", help="kernel module file(*.ko)", required=False)
    parser_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    args.func(args)
