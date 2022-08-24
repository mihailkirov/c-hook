#include "inject.h"

static void usage(char *arg){

	printf("Usage ./%s [pid] [lib-to-inject] [envs := KEY=VALUE]*", arg);
	
}


long convertNumber(char *n) {
    char *endptr;
    int number = strtol(n, &endptr, 10);
    if (!(errno == 0 && n && !*endptr)){
        printf ("Invalid PID %s\n", n);
    	exit(EXIT_FAILURE);
    }

    return number;

}

static ull parse_mapping(char *line, char *lib) {
	
	ull addr;
	char perms[5];

	if(!strstr(line, lib)){
		return -1;
	}
	
	sscanf(line, "%llx-%*lx %s %*s", &addr, perms);
	if(!strstr(perms, "x")){
		return -1;
	}
	return addr;
}
static ull get_mapping_lib(pid_t pid, char *lib){
	
	FILE *f;
	char path[128]; 
    char *line = NULL;
	ssize_t read; // signed 
	size_t len; // unsigned 
	sprintf(path, "/proc/%d/maps", pid);
	
	if (!(f=fopen(path, "r"))){
		fprintf(stderr, "Error opening %d maps: %s", pid, strerror(errno));
		exit(-1);
	}
	
	ull addr=0;	
	while ((read = getline(&line, &len, f)) != -1) {
		if((addr=parse_mapping(line, lib)) != -1 ){
			break;
		}
	}
	// getline allocates it
	if (line) {
		free(line);
	}
	fclose(f);
	return addr;
}

static ull find_offset(char *lib, char *symbol) {

    void* libc_handle = NULL;
    void* __libc_dlopen_mode_addr = NULL;
    libc_handle = dlopen(lib, RTLD_NOW);
    // obtain the symbol using the handle 
    __libc_dlopen_mode_addr = dlsym(libc_handle, symbol);
    if (dlclose(libc_handle)){
    	perror("dlclose");
		exit(-1);
    }
    // get the libc's executable address mapping of the current process
    ull addr;
	if ((addr = get_mapping_lib(getpid(), lib)) == -1){
		fprintf(stderr, "Could not find executable mapping of %s \n", lib);
		exit(-1);
	}	
    
    return (ull)__libc_dlopen_mode_addr - addr;
	
}

// #############  PTRACE #################

// Writes data of size len at dst of process with PID=pid taken from src
static int ptraceWrite(pid_t pid, ull *src, ull *dst, int len) {
	
	// increment by 8 bytes 
	for(int i=0; i<len; i+=sizeof(ull), src++, dst++){
		if(ptrace(PTRACE_POKETEXT, pid, dst, *src) == -1){
			fprintf(stderr, "Error ptrace POKE (write)  %s", strerror(errno));
			exit(-1);
		}
	}
	return 0;
}
// Read from address addr of process with PID=pid a data of length len and store it in data
static void ptraceRead(int pid, ull addr, ull *store, int len) {
	
	ull word; // 8 byte buffer
	for (int i=0; i < len; i+=sizeof(ull), store++, word=0) {
		if ((word = ptrace(PTRACE_PEEKTEXT, pid, addr + i, NULL)) == -1) {;
			printf("[!] Error reading process memory %s \n ", strerror(errno));
			exit(-1);
		}
		*store = word; 
	}
}

// restore process pid registers and the old rip value 
static void restore(pid_t pid, struct user_regs_struct *regsb, char *restore) {
	// Restoring the CPU registers	
	ptraceWrite(pid, (ull*)restore, (void *)regsb->rip, SIZE_INSTR);
	if(ptrace(PTRACE_SETREGS, pid, NULL, regsb) == -1){
		perror("Error setting regs with ptrace restore\n");
	}
	if(ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1){
		perror("Error detaching with ptrace restore");
	}
}


static int allocateMemory(size_t size, pid_t pid, struct user_regs_struct* regs) {
	
	char *mmapinstr = "\x0f\x05\x00\x00\x00\x00\x00\x00"; // execute a mmap syscall- opcode 0x0f05 
	int status;
	// writing the new data for memory allocation
	ptraceWrite(pid, (ull*) mmapinstr, (void*)regs->rip, SIZE_INSTR);
	// set syscall registers
	regs->rax = 9;  // NR_MMAP;
	regs->rsi = size; // size of the mapping
	regs->rdi = 0;
 	regs->rdx = PROT_WRITE | PROT_READ; // read and writable zone
    regs->r10 = MAP_ANONYMOUS | MAP_PRIVATE; // copy on write on the zone
    regs->r8  = 0;
    regs->r9  = 0;	
    // set registers and execute
	if(ptrace(PTRACE_SETREGS, pid, NULL, regs) == -1){
		fprintf(stderr, "Error setting regs with ptrace %s", strerror(errno));
		return -1;
	}
	if(ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1){
		fprintf(stderr, "Error single step with ptrace (allocating memory) %s", strerror(errno));
		return -1;
	}
	waitpid(pid, &status, 0);	
	if(WIFEXITED(status)){
		printf("The process has died after singlestep;(\n");
		return -1;
	}
	if(ptrace(PTRACE_GETREGS, pid, NULL, regs) == -1){
		fprintf(stderr, "Error getting regs with ptrace %s", strerror(errno));
		return -1;
	}
	return 0;
}


static int stopAndBackup(pid_t pid, struct user_regs_struct *regs, char *rip) {
	int status;
	// attaching
	if(ptrace(PTRACE_ATTACH, pid, NULL, NULL) ==  -1){
		perror("Error attaching with ptrace");
		return -1;
	}
	// SIGTRAP -> the process is under the current program control
	wait(&status);
	if(WIFEXITED(status)){
		printf("The process died while restoring registers ;(\n");
		return -1;
	}
	if(ptrace(PTRACE_GETREGS, pid, NULL, regs) == -1){
		perror("Error getting registers");
		return -1;
	}
	// store the next instruction
	ptraceRead(pid, (ull)regs->rip, (ull*) rip, SIZE_INSTR);
	return 0;
}

char **extractEnv() {
	char **t = calloc(2*SIZEENV, sizeof(char*));
	char *t1, *d, *tmp;
	size_t len, p1, p2;
	int j = 0;
	for(int i = 0; i<SIZEENV; i++){
		len = strlen(ENV[i]);
		d = strstr(ENV[i], "="); // first occ of the delimiter
		// calculate two respective sizes
		p1 = (size_t)(d-ENV[i]);
		p2 = len-p1-1;

		t1 = calloc(p1+1, sizeof(char));
		memcpy(t1, ENV[i], p1);
		
		tmp = allignLibPath(t1);
		if (tmp != t1) { free(t1);}
		t[j++] = tmp;
		
		t1 = calloc(p2+1, sizeof(char));
		memcpy(t1, d+1, p2);
		t1[p2] = '\x00';
		tmp = allignLibPath(t1);
		if (tmp != t1) { free(t1);}
		t[j++] = tmp;
	}

	return t;

}

static ull insertEnv(pid_t pid, ull addrLibcF, regs r) {

	unsigned char *callfunc2 = "\xff\xd0\x00\x00\x00\x00\x00\x00"; // call opcode

	char **envs = extractEnv();
	// write the key/value pairs at the address pointeb by rax(heap)
	size_t lenKey, lenValue;
	ull addr = r->rax;
	
	for (int i=0; i < 2*SIZEENV; i+=2){

		lenKey = strlen(envs[i]);
		lenValue =  strlen(envs[i+1]);

		// write the contents of the env value pointers
		ptraceWrite(pid, (ull*)envs[i], (void *)(r->rax), lenKey+1); // insure null bytes is there	; but added alignment .. check this
		ptraceWrite(pid, (ull*)envs[i+1], (void *)(r->rax + lenKey+1), lenValue+1); // insure null bytes is there	
		// prepare regs for execution of the function
		ptraceWrite(pid, (ull*)callfunc2, (void*)r->rip, SIZE_INSTR); // can be optimized (only decrement)
		r->rdi = r->rax; // address of the key value
		r->rsi = r->rax + lenKey+1;
		r->rax = addrLibcF;
		r->rdx = 1; // overwrite
		r->r10 = 0; 
		r->r8  = 0;
		r->r9  = 0;
		// set registers and execute
		if(ptrace(PTRACE_SETREGS, pid, NULL, r) == -1){
			fprintf(stderr, "Error setting regs with ptrace %s", strerror(errno));
			return -1;
		}
		if(ptrace(PTRACE_CONT, pid, NULL, NULL) == -1){
			fprintf(stderr, "Error single step with ptrace (allocating memory) %s", strerror(errno));
			return -1;
		}
		int status;
		waitpid(pid, &status, 0);	
		if(WIFEXITED(status)){
			printf("The process has died after singlestep when setting environment ;( \n");
			return -1;
		}
		if(ptrace(PTRACE_GETREGS, pid, NULL, r) == -1){
			fprintf(stderr, "Error getting regs with ptrace %s", strerror(errno));
			return -1;
		}
		// back to the begining of the segment
		r->rax = addr;
		free(envs[i]);
		free(envs[i+1]);
	}
	
	free(envs);
	return 0;

}


static int inject(pid_t pid, size_t size, char *lib_path, ull __addr__dlopen, ull __addr__setnenv) {
	
	struct user_regs_struct regs, regs2, regs3;
	char restoresegment[8];
	int status;
	// saving old registers + current instruction
	if (stopAndBackup(pid, &regs, restoresegment) == -1) {
		return -1;
	}	
	memcpy(&regs2, &regs, sizeof(struct user_regs_struct));

	// allocate memory for the name of the shared object
	// on x86_64 returns are generally store in the rax register
	if (allocateMemory(size, pid, &regs) == -1 || !regs.rax) {
		fprintf(stderr, "Error allocating memory\n");
		restore(pid, &regs2, restoresegment);
		return -1;
	}

	// set up env is wanted -> inject it
	if (__addr__setnenv){
		memcpy(&regs3, &regs, sizeof(struct user_regs_struct));
		// insert new env variables for the injected lib
		if (insertEnv(pid,  __addr__setnenv, &regs3)) {
			fprintf(stderr, "Bad return code after setting environment ;(");
			restore(pid, &regs2, restoresegment);
			return -1;
		}
	}
	
	// open the library
	// write the library name at the new address (heap)
	ptraceWrite(pid, (ull*)lib_path, (void *)(regs.rax), strlen(lib_path)+1); 
	// set the rip to the value of call
	regs.rip = regs2.rip; // rip points to the next instruction
	ptraceWrite(pid, (ull *)callfunc, (void*)regs.rip, SIZE_INSTR);
	// set registers for call to dlopen (lib_path) 
	regs.rdi = regs.rax; // address where the name/path of the so object is
	regs.rsp = regs.rax + 4096; // middle of the allocated area (regs.rax + 4096)
	regs.rbp = regs.rsp; //set the base pointer to the stack pointer
	regs.rax = __addr__dlopen; // address of dlopen
	regs.rsi = RTLD_LAZY; // options
	// set up registers and call
	if(ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1){
		fprintf(stderr, "Error setting regs with ptrace %s", strerror(errno));
		restore(pid, &regs2, restoresegment);
		return -1;
	}
	if(ptrace(PTRACE_CONT, pid, NULL, NULL) == -1){ // leave dlopen execute?
		fprintf(stderr, "Error continue  with ptrace %s", strerror(errno));
		restore(pid, &regs2, restoresegment);
		return -1;
	}
	waitpid(pid, &status,0); // wait for next sigtrap signal
	if(WIFEXITED(status)){
		fprintf(stderr, "The process has died after dlopen;(\n");
		restore(pid, &regs2, restoresegment);
		return -1;
	}
	// restore and detach -> after that the process has a so opened in memory
	restore(pid, &regs2, restoresegment); 
	// the begining adress of the so is in the rax CPU pointer
	return 0;
}


static char* allignLibPath(char *lib) {
	size_t len_orig = strlen(lib);
	size_t newlen = len_orig;
	// allign the library if needed
	if (len_orig % SIZE_INSTR){
		newlen = len_orig + (SIZE_INSTR - (len_orig % SIZE_INSTR));
		char *buf = (char *) calloc(newlen, sizeof(char));
		strcpy(buf, lib);
		lib = buf;
	}
	return lib;
}

int main(int argc, char* argv[]) {
	if(argc < 2){
		usage(argv[0]);
		exit(-1);
	}

	// pid 
	ui pid = (ui) convertNumber(argv[1]);
	// libraries;
	char *lib = argv[2];
	// find the offset of dlopen in libc	
	ull offset = find_offset(LIBC, "__libc_dlopen_mode");
	ull target_lib_addr = get_mapping_lib(pid, LIBC); // this returns an offset
	ull allocated_addr;
	char *t = allignLibPath(lib);

	// get system system of a page
	size_t pageSize;
    if ((pageSize=sysconf(_SC_PAGESIZE)) == -1){
		perror("sysconf when changing permissions");
		return -1;	
	}
	// there are some env passed
	if (argc > 2){
		ENV = (argv+3);
		SIZEENV = argc - 3;
		ull offset2 = find_offset(LIBC, "setenv");
		allocated_addr = inject(pid, pageSize, t, target_lib_addr + offset, offset2 + target_lib_addr);

	}else {
		allocated_addr = inject(pid, pageSize, t, target_lib_addr + offset, 0);
	}

	if (t != lib) 
		free(t);

	if(allocated_addr == -1) {
	       exit(EXIT_FAILURE); 	
	}
	return 0;
}


