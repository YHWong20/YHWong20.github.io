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

This is the first ret2win challenge in this CTF!

I found John Hammond's [walkthrough video](https://www.youtube.com/watch?v=k4hqdVo3cqk&list=PL1H1sBF1VAKUbRWMCzEBi61Z_7um7V5Sd&index=31&pp=iAQB) for this challenge to be extremely helpful and informative.

## My solution
Since the source file `vuln.c` was provided, I firstly decided to take a look at the file. The provided file had a read buffer size of 32. It also used the `gets` function to retrieve user input.

I then decided to do some experimenting, where I wanted to see how many 'A's will cause the address of printf to be overwritten. What I found was that around 44 'A's were required to clobber the return address.

Since the `vuln` executable is of an ELF type (can be determined by running `file vuln`), we can then run `readelf` to look for the return address of `win()`. From here, we note that the return address is `0x080491f6`.

Now, we can generate the payload. Take note of the endianness when generating the payload. In this case, the executable was compiled, and run on a little-endian system.

Using Python 2.7: 
```python
print 'A'*44 + '\xf6\x91\x04\x08' 
```
I'll need to retry this solution using pwntools and Python 3. Python 2.7 was
more flexible in this case as the string that was piped into the program could
be interpreted as a byte string.


## Learning Takeaways
Some general tips I picked up:
- Play around with the program to test the number of dummy characters required to clobber the return address of our intended functions.
- Get familiar with `readelf`.
- Always make sure to check endianness, so that the payload can be generated correctly.
