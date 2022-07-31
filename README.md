# IDA: Patch Instruction Plugin

## setup

1. download `python 3` (I use `python 3.10`)
2. `pip install keystone-engine`
3. `pip install pwntools`
4. copy `PatchInstructionPlugin.py` to `{IDA_path}/plugin/`

---
## example

we get a file name `source` , it's a x86_64's elf file
```c
// source.c
#include <stdio.h>

int main(){
    printf("La La La La La !!!!!!");

    return 0;
}
```

the view of ida when we pull the `source` to ida
![](https://github.com/akvo-fajro/IDA-Patch_Instruction_Plugin/blob/main/img/view1.png?raw=true)

if we want to patch
```asm
mov eax,0
call _printf
```
we need to select these two lines
![](https://github.com/akvo-fajro/IDA-Patch_Instruction_Plugin/blob/main/img/view2.png?raw=true)

and select `edit`->`plugins`->`patch_instruction`
![](https://github.com/akvo-fajro/IDA-Patch_Instruction_Plugin/blob/main/img/view3.png?raw=true)

it will pop out a new windows that contains the original assembly of select section
![](https://github.com/akvo-fajro/IDA-Patch_Instruction_Plugin/blob/main/img/view4.png?raw=true)

we can edit the assembly on the windows (i write a assembly that print out `hello world !\n`)
```asm
mov rax,0xa2120646c72
push rax
mov rax,0x6f77206f6c6c6568
push rax
mov rax,1
mov rdi,1
mov rsi,rsp
mov rdx,14
syscall
pop rax
pop rax
```
![](https://github.com/akvo-fajro/IDA-Patch_Instruction_Plugin/blob/main/img/view5.png?raw=true)

and the plugin will create a new elf in the original elf's directory name `<bianry_name>_new`

the different output of `source` and `source_new`
![](https://github.com/akvo-fajro/IDA-Patch_Instruction_Plugin/blob/main/img/view6.png?raw=true)
