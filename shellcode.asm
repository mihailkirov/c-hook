bits 64

push rdi
push rdx
push rax
mov rax, 0xffffffffffff 
call rax 
pop rax
pop rdx
pop rdi
nop
nop
nop
nop
nop
nop
nop
nop
jmp 0xffffffffff
