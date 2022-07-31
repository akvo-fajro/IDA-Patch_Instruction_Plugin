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
