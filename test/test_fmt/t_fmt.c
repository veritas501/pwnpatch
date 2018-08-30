#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void){
  char buf[0x100];
  memset(buf,0,0x100);
  read(0,buf,0x100);
  printf(buf);
  return 0;
}
