from pwnpatch import patcher

pt = patcher('./t_popen')
c_code=r'''
void main(char * s){
    if(strchr(s,'`') || strchr(s,'$') || strchr(s,'\'')){
        puts("find evil char, exit...");
        exit(0);
    }
}
'''
pt.add_c(c_code,'checker')
asm='''
push rdi
push rsi
push rdx

mov rax,rdx // because of scc's strange call convention
call {checker}

pop rdx
pop rsi
pop rdi
'''
pt.hook_asm(0x12E6,asm)
pt.save()