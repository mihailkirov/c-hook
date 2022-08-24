#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>
#include <stdlib.h>
#define SIZE 8
#define BACKUPSIZE 8 // number of instruction bytes to be backed up from the function
//typedef  void (*fptr)(char*);

// swap the string
static void h00ked(char t[]) {
	size_t len = strlen(t)-1;
	int i=0;
	char c1,c2;
	while(i < len){
		c1 = t[len];
		c2 = t[i];
		t[i++] = c1;
		t[len--] = c2;
	}
}
/*
 * Changes the permissions on the page containing the address addr
 */
static int changePerms(void *addr) {
	
	size_t pageSize;
    if ((pageSize=sysconf(_SC_PAGESIZE)) == -1){
		perror("sysconf when changing permissions");
		return -1;	
	}
   	uintptr_t *end =  (uintptr_t*) addr + 1;
   	uintptr_t pageStart = (uintptr_t) addr & -pageSize; // := addr - (addr%pageSiize)
   	if(mprotect((void*)pageStart, end - (uintptr_t*)pageStart, PROT_READ | PROT_WRITE | PROT_EXEC)==-1){
		perror("mprotect");
		return -1;
	}

	return 0;
}

/*
Construct payload function. A shellcode is injected in the heap. It contains a call to 
the replacement function (here h00ked) and context preservation. It contains also a backup of the overwritten instructions
at the original function + a call to the original function itself (instructions after the inserted jump).
@original - pointer to the original function
@replace - pointer for the replacement function
 */
static char *constructPayload(uintptr_t *original, uintptr_t* replace) {
	/*
	 * push rdi
	 * push rdx
	 * push rax
	 * mov rax, ---
	 * call rax
	 * pop rax
	 * pop rdx
	 * pop rdi
	 * 8 bytes backuped instructions (0x90)
	 * mov rax, addr instruction after the 8 byte
	 * push rax
	 * call
	 *pop rax
	 * ret
	 LE representation in memory! 
	*/
	char PAYLOAD[] = {0x57, 0x52, 0x50, 0x48, 0xb8, 0x90, 0x90, 0x90, 0x90, 0x90, \
			  0x90, 0x90, 0x90, 0xff, 0xd0, 0x58, 0x5a, 0x5f, 0x90, 0x90, 0x90,0x90,\
	     		  0x90, 0x90, 0x90, 0x90, 0xe9, 0x90, 0x90,0x90, 0x90};

	// do a backup of 8 instruction bytes (function specific) 
	memcpy(&PAYLOAD[18], original, BACKUPSIZE);
	// allocate heap + make it executable
	char *shc = calloc(sizeof(PAYLOAD), sizeof(char));
	
	if (changePerms(shc) == -1){
		free(shc);
		return NULL;
	}
	// copy the address of the function to be called (hook)
	memcpy(&PAYLOAD[5], &replace, SIZE);
	// copy the address of the next instruction after the backup
	char *tmp = (char *)original; //
	tmp += BACKUPSIZE; // point to the first instruction after the backup
	char *tmp2 = PAYLOAD + sizeof(PAYLOAD);
	int backJump =  (int)((char*)original + BACKUPSIZE - shc - sizeof(PAYLOAD));
	memcpy(&PAYLOAD[27], &backJump, sizeof(int));
	// copy the payload in the heap
	memcpy(shc, PAYLOAD, sizeof(PAYLOAD));
	return shc;	
}

/* 
Code inspired from http://thomasfinch.me/blog/2015/07/24/Hooking-C-Functions-At-Runtime.html && \ 
https://en.wikipedia.org/wiki/Hooking
*/ 	
__attribute__((constructor))
static void init(void)
{	
	/*
	jmp -- (rip + off) ; |off| = 4 
	*/
	char jumpRel[] = {0xe9, 0x90, 0x90, 0x90, 0x90};
	// open a symbol handle for the main program
	// the other program has to expose its symbols (if not stripped)
	void *mainProgramHandle = dlopen(0, RTLD_NOW);
	if (!mainProgramHandle){
		printf("%s\n", dlerror());
		return;
	}
	// get the address of the hooked function & the replacement function
	uintptr_t *origFunc;
	
	if(!(origFunc =  dlsym(mainProgramHandle , "hook"))){
		printf("%s\n", dlerror());
		return;
	}
	
	if(dlclose(mainProgramHandle)){
		dlerror();
		return;
	}
	char *toJumpTo;
    if (!(toJumpTo = constructPayload(origFunc, (uintptr_t*)&h00ked)))
		return;
	// architecture constraint x86_64 -> relative jump on 4 byte address
	uint32_t offset = (uintptr_t)toJumpTo - ((uint64_t)origFunc + 5 * sizeof(char)); 
	// make the page in the text section writable
	if (changePerms(origFunc) == -1) {
		return;
	}
	//// write the offset and the jump
	memcpy(&jumpRel[1], &offset, sizeof(uint32_t));	
	memcpy(origFunc, jumpRel, 5);

	printf("hook injected\n");
}




