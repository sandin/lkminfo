import lief
from .kernel import Kernel
from .module import Module, serialize_modinfo, serialize_versions
from dataclasses import dataclass


@dataclass
class PatchConfig:
    patch_vermagic: int = True
    patch_module_layout: int = True
    patch_versions: int = False


def patch_vermagic(kernel: Kernel, module: Module) -> bool:
    section = module.elf.get_section(".modinfo")  # type: lief.Section
    if section is None:
        return False
    #data = section.content.tolist()
    module.set_modinfo("vermagic", kernel.vermagic)
    data = serialize_modinfo(module.load_info.mod_info)
    section.content = data # memoryview(data)
    return True


def patch_versions(kernel: Kernel, module: Module, config: PatchConfig) -> bool:
    section = module.elf.get_section("__versions")  # type: lief.Section
    if section is None:
        return False
    #data = section.content.tolist()

    def filter_sym(sym_name, config):
        if config.patch_module_layout and sym_name == "module_layout":
            return True
        if config.patch_versions:
            return True
        return False

    new_versions = []
    for i in range(0, len(module.load_info.versions)):
        ver = module.load_info.versions[i]
        sym_name = ver[0]
        crc = ver[1]
        if not filter_sym(sym_name, config):
            new_versions.append((sym_name, crc))
            continue

        crc = kernel.find_symbol_crc(sym_name, -1)
        if crc == -1:
            print("[Error]: can not find symbol `%s` in kernel" % sym_name)
            return False
        if crc != ver[1]:
            print("[Warning]: `%s` symbol has a mismatched crc value, forcing a patch on it may cause the kernel to crash" % sym_name)
        new_versions.append((sym_name, crc))
    module.load_info.versions = new_versions
    data = serialize_versions(module.load_info.versions)
    section.content = data # memoryview(data)
    return True


def patch_module(kernel: Kernel, module: Module, config: PatchConfig, output: str) -> (bool, str):
    if config.patch_vermagic:
        if not patch_vermagic(kernel, module):
            return False, "Can not patch vermagic"

    if config.patch_vermagic or config.patch_versions:
        if not patch_versions(kernel, module, config):
            return False, "Can not patch versions"

    module.elf.write(output)
    return True, None


