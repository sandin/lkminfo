import lief
from .kernel import Kernel
from .module import Module, serialize_modinfo


def patch_vermagic(kernel: Kernel, module: Module) -> bool:
    section = module.elf.get_section(".modinfo")  # type: lief.Section
    if section is None:
        return False
    #data = section.content.tolist()
    module.set_modinfo("vermagic", kernel.vermagic)
    data = serialize_modinfo(module.load_info.mod_info)
    section.content = data # memoryview(data)
    return True


def patch_module(kernel: Kernel, module: Module, output: str) -> (bool, str):
    if not patch_vermagic(kernel, module):
        return False, "Can not patch vermagic"

    module.elf.write(output)
    return True, None


