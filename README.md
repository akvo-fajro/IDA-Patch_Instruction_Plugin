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
