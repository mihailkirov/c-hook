COMPILO=gcc
OPT1=-Wall
OPTSHARED=-shared -fPIC

all: hook 


hook: target injector bad.so

injector: inject.c
	$(COMPILO) $(OPT1) $< -ldl -o $@


bad.so: toinject.c
	$(COMPILO) $(OPT1) -shared $< -o $@ -ldl -export-dynamic

target: target.c
	$(COMPILO) $(OPT1)  $< -o $@ -ldl -export-dynamic 

shellc: shellcode.asm 
	nasm -f elf64 shellcode.asm 

clean-hook:
	rm bad.so
	rm target
	rm injector
