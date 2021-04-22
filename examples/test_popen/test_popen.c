#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main(void){
  char cmd[0x100];
  char buf[0x80];
  memset(buf,0,0x80);
  int r = read(0,buf,0x80);
  if(buf[r-1] == '\n')
    buf[r-1]=0;
  sprintf(cmd,"echo '%s'|bc",buf);
  printf("cmd :%s\n",cmd);
  FILE * fp = popen(cmd,"r");
  fgets(cmd,0x100,fp);
  fclose(fp);
  puts(cmd);
  return 0;
}
