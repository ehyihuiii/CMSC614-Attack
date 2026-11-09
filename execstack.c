
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct A {
  char buffer[32];      // (offset 0)
  char *cmd;            // (offset 32) What system runs
  char *readptr;        // (offset 40) 
};

void arbitrary_write(struct A *job) {
  unsigned long idx, val;
  printf("index (8-byte slots from buffer base): ");
  if (scanf("%lu\n", &idx) != 1) {
    exit(1);
  }
  printf("value (hex, e.g. 0x...): ");
  if (scanf("%lx", &val) != 1) {
      exit(1);
  }
  ((unsigned long *)job->buffer)[idx] = val;
  puts("written");

//  fgets(job->buffer, 300, stdin);
//  puts("written");
}


int main(){
  setuid(0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stdin,  NULL, _IONBF, 0);
  struct A job;
  strcpy(job.buffer, "AAAA");
  job.cmd = "/bin/echo System Command is /bin/echo";
  job.readptr = job.buffer;

  printf("Input Menu:\n"
         "a - stage bytes into buffer\n"
         "b - arbitrary write\n"
         "c - print 8 bytes\n"
         "d - exit\n");

  while(1) {
    char inp[30];
    printf("Enter your input:\n");
    fgets(inp, 300, stdin);

    char ch = inp[0];

    if(ch == 'a') {
      printf("bytes: ");
      read(0, job.buffer, 31);
    }
    else if(ch == 'b') {
      arbitrary_write(&job);
    }
    else if(ch == 'c') {
      printf(job.readptr);
    }
    else if(ch == 'd') {
      system(job.cmd);
      break;
    }
    else {
      printf("Not a valid character\n");
    }
  }

  return 0;
}


