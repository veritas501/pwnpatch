#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

int func1(){
	return getpid() == 0x1337;
}

int func2(){
	return getpid() == 0xdeadbeef;
}

int func3(){
	char str2[]="this_is_str2";
	return !strcmp("str1",str2);
}

int main(void){
	if(func1() && func2() && func3()){
		return 0;
	}
	return 1;
}
