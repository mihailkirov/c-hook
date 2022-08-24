#ifndef INJECT_H
#define INJECT_H

#define _GNU_SOURCE
#include </usr/include/x86_64-linux-gnu/sys/mman.h>
#include <dlfcn.h>
#include </usr/include/x86_64-linux-gnu/sys/ptrace.h>
#include </usr/include/x86_64-linux-gnu/sys/types.h>
#include </usr/include/x86_64-linux-gnu/sys/wait.h>
#include <unistd.h>
#include </usr/include/x86_64-linux-gnu/sys/user.h>   
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdarg.h>


// DEFINITIONS
typedef unsigned long long ull;
typedef unsigned int ui;
#define SIZE_INSTR 8
typedef struct user_regs_struct CPUREGS;
#define LIBC "/usr/lib/x86_64-linux-gnu/libc-2.31.so"

// will point at the beginning of the env variables passed to the process
char **ENV;
size_t SIZEENV;
 // shellcode for function call 
const unsigned char *callfunc = "\xff\xd0\xcc\x00\x00\x00\x00\x00";
typedef struct user_regs_struct* regs;

// #############  UTILITY FUNCTIONS ############# 

// convert string to long
long convertNumber(char *n);

/*
Extract the environment passed as argument. Returnes an array of pointers
*/
char **extractEnv();
// frees the matrix generated from the above function
void freeEnv(char **c);

/*
Moves the content pointed by lib to a new location
with size multiple of the size of an instrcution (ptraceRead)
*/
static char* allignLibPath(char *lib);

/*
 * Check if line (extracted from /proc/<some-id>/maps) contains the substring lib and if so it extracts the adress
 */
static ull parse_mapping(char *line, char *lib);

/* 
Gets the start address of the executable map of lib 
from  the process <pid> virtual memory 
*/
static ull get_mapping_lib(pid_t pid, char *lib);

/* 
Find offset of a function (symbol) in the library (lib)
*/
static ull find_offset(char *lib, char *symbol);

// #############  PTRACE #################

// Writes data of size len at dst of process with PID=pid taken from src
static int ptraceWrite(pid_t pid, ull *src, ull *dst, int len);

// Read from address addr of process with PID=pid a data of length len and store it in data
static void ptraceRead(int pid, ull addr, ull *store, int len);


// #############  INJECTOR UTILITIES #################

// restore process pid registers and the old rip value 
static void restore(pid_t pid, struct user_regs_struct *regsb, char *restore);

/* 
Allocate memory of size in the process virtual address space
using mmap system call. Memory is allocated and manipulated in pages (|page| - 4kb) 
The function stores in the regs structure pointer the result of the system call
*/
static int allocateMemory(size_t size, pid_t pid, struct user_regs_struct* regs);


/*
Stop the process pid and backup its registers into regs, stores the rip instruction into rip 
*/
static int stopAndBackup(pid_t pid, struct user_regs_struct *regs, char *rip);

static ull insertEnv(pid_t pid, ull addrLibcF, regs r);

/* Allocate size memory in the virtual memory space of process pid.
 Once allocated the function will load a shared library
 and restore the process's state 
*/
static int inject(pid_t pid, size_t size, char *lib_path, ull __addr__dlopen, ull __addr__setnenv);

#endif