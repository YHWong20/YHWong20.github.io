---
layout: single
title:  "HTB Academy - Enumeration and Footprinting"
categories: 
  - OSCP Notes
tags:
  - htb-academy
toc: true
toc_label: "Contents"
toc_icon: "list"  # corresponding Font Awesome icon name (without fa prefix)
excerpt: ""
permalink: /posts/enumeration-and-footprinting-notes
author_profile: false
sidebar:
  nav: "navbar"
---

## Infrastructure-based Enumeration

### Gathering domain information

* Viewing SSL certificates.
* Viewing certificate transparency logs on sites like `crt.sh` (can also view subdomains this way).
* Scanning IoT devices using `Shodan`.
* Doing `DNS` look-ups using tools like `dig`.

Cloud resource usage can be detected as well by viewing subdomains.

* For example, blob storage service usage (like AWS S3) can be detected, and if these buckets and objects are not secured properly, are internet accessible.

Staff enumeration can be done using sites like `LinkedIn` and `Xing`.

## Host-based Enumeration

### Netcat

We can grab service banners by connecting to an address and port.

* Connecting to an IP address over a specific common port (like 22) can leak information of the protocol and version from the banner. For instance, `nc <ip address> 22` could leak info of the SSH service running.

### FTP

Crucially, `anonymous` access can be enabled for FTP. Using `nmap`, we can tell if anonymous authentication is allowed, as well as the directories available.

* To connect, username should be anonymous, and no password is required.

On the remote host, the `/etc/ftpusers` file lists the users that are denied from logging in to the FTP server.

Enumeration can be done using `nmap` scripts as well (`nmap --script ftp*...`).

### SMB

Some versions are vulnerable to RCE exploits like `EternalBlue`.

* Versions can be enumerated using `nmap`.

Interact with `SMB` shares using `smbclient`.

* Enumerate shares anonymously: `smbclient -N -L //<ip address>`
* Connect as Guest: `smbclient //<ip address>/<name of share>`

If connecting to a share as Guest, don't enter any password when prompted.

If we have login credentials, we use the `-U` option to specify username, and `-P` to specify password.

* If enumerating shares, remove the `-N` option to use a valid credential pair.

Alternatively, we can use `rpcclient`, as this gives us more room to interact with the `SMB` server through `RPC`.\

### NFS

Enumerate shares with `showmount -e <ip address>` command.
  
Then, mount these shares to an empty directory using
`sudo mount -t nfs <ip address>:/ <target dir path> -o nolock`.
  
Once done, un-mount the shares using `sudo umount <target dir path>`.

Note: If there are permissions issues when attempting to access mounted `NFS` share (`UID` is nobody), elevate access to root using `sudo su`, as this is due to root squashing.

### DNS

We can query a specific `DNS` server using the `@` character in `dig`: `dig ns <domain name> @<dns server ip>`

If these entries exist on the `DNS` server, then we can query the `DNS` server version as follows: `dig CH TXT version.bind <dns server ip>`

`any` queries will give us all records on the `DNS` server.

`axfr` queries will give us zone transfer data. Subdomains can be brute forced through such queries.

* Tools like `dnsenum` allow us to enumerate subdomains using a provided word list - we can use `SecList` word lists.

### SMTP/IMAP/POP3

SMTP

* Use `telnet` to interact with an `SMTP` server.
* Enumerate a list of commands that can be executed using `nmap` script `smtp-commands`, along with other possible `smtp*` scripts.
* We can also enumerate `SMTP` usernames using `Metasploit`.

Connect to `IMAP`/`POP3` using `openssl s_client -connect <ip_address>:imaps` or `openssl s_client -connect <ip_address>:pop3s`.

Using `IMAP`, once we're signed in, we can select a mailbox and view emails using `1 FETCH <email_id> RFC822`.

### SNMP

Useful for enumerating information about network devices.

Enumerate community strings using `onesixtyone` and `SecLists` word lists.

After community strings are retrieved, view network information using `snmpwalk` or `braa`.

* For `snmpwalk`, specify version of `SNMP` with `-v` and provide community string with `-c`: `snmpwalk -v<version> -c <community_string> <ip_address>`.
* For `braa`:  `braa <community_string>@<ip>:.1.3.6.*`.

### SQL

MySQL

* Enumerate databases: `show databases;`.
* Use a database: `use <database>;`.
* Enumerate tables and columns: `show tables;` and `show columns from <table>;`.

MSSQL

* `master` database contains information for the server instance.
* `sa` administrator account is vulnerable if not disabled.
* Connect to MSSQL instance from Linux using `mssqlclient.py`.

Oracle RDBMS

* `ODAT` can be used to enumerate and find vulnerabilities in Oracle Databases.
* Connect to Oracle DB using `sqlplus`.

### IPMI

Hardware-based management and monitoring, can be enumerated using `nmap` and `Metasploit`.

* `nmap` script: `ipmi-version`
* Metasploit: `auxiliary/scanner/ipmi/ipmi_version`

Default IPMI credentials:

* Dell iDRAC - `root:calvin`
* HP iLO - `Administrator:<8 chr number and uppercase letter string>`
* Supermicro IPMI - `ADMIN:ADMIN`

We can use `hashcat` to crack an 8 character number and uppercase letter string:
`hashcat -m 7300 <hash> -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u`

* Password hashes can be retrieved using `Metasploit` - `auxiliary/scanner/ipmi/ipmi_dumphashes`
