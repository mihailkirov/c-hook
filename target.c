#define _GNU_SOURCE
#include <stdio.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <unistd.h>

void hook(char *t){
	printf("%s\n", t);
}


int main() {
	printf("PID=%d\n", getpid());	
	char hey[16];
	
	dlopen(0, RTLD_NOW|RTLD_GLOBAL);// to fill symbol/got table	
	for (;;){

		scanf("%16s", hey);
		hook(hey);
	}
	return 0;
}
