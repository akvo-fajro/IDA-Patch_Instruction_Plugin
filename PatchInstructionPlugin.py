import idautils
import idaapi
import idc
import ida_bytes
import re
from keystone import *
from pwn import *

def write_to_new_code(addr_start,addr_finish,patch_asm):
    patch_asm = patch_asm.encode()
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    binary_name = idaapi.get_root_filename()
    with open(binary_name,'rb') as f:
        source = bytearray(f.read())

    if (addr_finish-addr_start) >= len(ks.asm(patch_asm)[0]):
        new_code = b''.join([bytes([num]) for num in ks.asm(patch_asm)[0]]) + b'\x90'*(addr_finish-addr_start-len(ks.asm(patch_asm)[0]))
        source[addr_start:addr_finish] = new_code
        source = bytes(source)
        with open(binary_name+'_new','wb') as f:
            f.write(source)
        return 0
    else:
        new_code = b''.join([bytes([num]) for num in ks.asm(patch_asm)[0]])
        
        program_header_off = u64(source[0x20:0x28])
        section_header_off = u64(source[0x28:0x30])

        program_header_size = u64(source[0x36:0x38].ljust(8,b'\x00'))
        section_header_size = u64(source[0x3a:0x3c].ljust(8,b'\x00'))

        section_header_num = u64(source[0x3c:0x3e].ljust(8,b'\x00'))

        string_table_idx = u64(source[0x3e:0x40].ljust(8,b'\x00'))
        string_section_off = section_header_off + string_table_idx*section_header_size
        string_table_off = u64(bytes(source[string_section_off + 0x18:string_section_off + 0x20]))

        fini_idx = 0
        for i in range(section_header_num):
            name_off = u64(bytes(source[section_header_off + section_header_size*i:section_header_off + section_header_size*i + 0x4]).ljust(8,b'\x00'))
            if bytes(source[string_table_off+name_off:]).index(b'.fini') == 0:
                fini_idx = i
                break

        fini_size = u64(source[section_header_off + section_header_size*fini_idx + 0x20:section_header_off + section_header_size*fini_idx + 0x28])
        fini_addr = u64(source[section_header_off + section_header_size*fini_idx + 0x10:section_header_off + section_header_size*fini_idx + 0x18])

        if len(ks.asm(f'jmp -{len(new_code) + fini_addr + fini_size + 5 - addr_finish}')[0]) == 5:
            new_code += b''.join([bytes([num]) for num in ks.asm(f'jmp -{len(new_code) + fini_addr + fini_size + 5 - addr_finish}')[0]])
        else:
            new_code += b''.join([bytes([num]) for num in ks.asm(f'jmp -{len(new_code) + fini_addr + fini_size + 3 - addr_finish}')[0]])

        source[section_header_off + fini_idx*section_header_size + 0x20:section_header_off + fini_idx*section_header_size + 0x28] = p64(len(new_code))

        target_program_idx = 3
        target_program_off = program_header_off + target_program_idx*program_header_size

        source[target_program_off+0x20:target_program_off+0x28] = p64(fini_addr%0x1000 + len(new_code) + fini_size)
        source[target_program_off+0x28:target_program_off+0x30] = p64(fini_addr%0x1000 + len(new_code) + fini_size)

        source[fini_addr+fini_size:fini_addr+fini_size+len(new_code)] = new_code
        source[addr_start:addr_finish] = b'\x90'*(addr_finish-addr_start)
        if len(ks.asm(f'jmp +{fini_addr + fini_size - addr_start}')[0]) == 5:
            source[addr_start:addr_start + 5] = b''.join([bytes([num]) for num in ks.asm(f'jmp +{fini_addr + fini_size - addr_start}')[0]])
        else:
            source[addr_start:addr_start + 3] = b''.join([bytes([num]) for num in ks.asm(f'jmp +{fini_addr + fini_size - addr_start}')[0]])
        
        source = bytes(source)
        with open(binary_name + '_new','wb') as f:
            f.write(source)
        return 0


def prompt_change_asm():
    class Change_asm_Form(idaapi.Form):
        def __init__(self):
            idaapi.Form.__init__(self, 
            """STARTITEM 0
                Patch the asssembly

                test line
                <##assembly patch:{asm_patch}>
            """,{
                'asm_patch': idaapi.Form.MultiLineTextControl(),
            })

        def OnFormChange(self):
            return 1

    [select_ok,addr_start,addr_finish] = idaapi.read_range_selection(None)
    if not select_ok:
        raise BaseException("Did not select any instruction")
    f = Change_asm_Form()
    f.Compile()
    ea = addr_start
    asm_ori = ''
    while ea != addr_finish:
        asm_ori += idc.generate_disasm_line(ea, 0) + '\n'
        ea += ida_bytes.get_item_size(ea)
    f.asm_patch.value = asm_ori
    
    ok = f.Execute()
    if ok != 1:
        raise BaseException("User cancel")
    
    patch_asm = f.asm_patch.value
    patch_asm = re.sub(r';.*\n','\n',patch_asm)

    f.Free()
    
    return [addr_start,addr_finish,asm_ori,patch_asm]

class Patch_Instruction(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Patch the instruction"

    wanted_name = "patch_instruction"
    wanted_hotkey = "Alt-F6"
    help = "Coming soon..."

    def init(self):
        idaapi.msg('Patching Started !!!\n')
        return idaapi.PLUGIN_OK
    
    def run(self, arg):
        [addr_start,addr_finish,asm_ori,patch_asm] = prompt_change_asm()
        write_to_new_code(addr_start,addr_finish,patch_asm)

    def term(self):
        new_file = idaapi.get_root_filename() + '_new'
        idaapi.msg(f"Patching Finish , new file is `{new_file}`\n")

def PLUGIN_ENTRY():
    return Patch_Instruction()
