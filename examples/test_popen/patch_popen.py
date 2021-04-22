from pwnpatch import *
from pwn import *

patcher = Patch('./t_popen')
bin = ELF('./t_popen',checksec=False)

code=r'''
typedef int(*f)();
typedef f(*ff)();
ff dynelf(char *,...);

void check(char * arg,char * mode){
    asm("push rdi");
    asm("push rsi");
    char strchr[] = "strchr";
    if(dynelf(strchr)()(arg,'`') || dynelf(strchr)()(arg,'$')){
        char printf[]="printf";
        char fmt[]="find badbad\n";
        dynelf(printf)(fmt);
        char exit[] = "exit";
        dynelf(exit)(0);
    }
    asm("pop rsi");
    asm("pop rdi");
}
'''
patcher.hook(0x000000000040081A,c=code)
patcher.save()