---
layout: single
title:  "HTB Academy - Web Enumeration"
categories: 
  - OSCP Notes
tags:
  - htb-academy
toc: true
toc_label: "Contents"
toc_icon: "list"  # corresponding Font Awesome icon name (without fa prefix)
excerpt: ""
permalink: /posts/web-enumeration-notes
author_profile: false
sidebar:
  nav: "navbar"
---

## Passive Information Gathering

### WHOIS

`whois` allows us to gather information on a specific domain. This includes information like:

* IANA ID number
* Registrant details
* Admin details
* DNS servers

### DNS

DNS look ups can be done using `dig` or `nslookup`.

* `A` records provide mappings of host names to IP addresses (`dig a ...`).
* `NS` records provide details on the DNS servers.
* `PTR` records provide mappings of IP addresses to host names ("reverse" of `A` records - `dig -x ...`).
* `CNAME` records show alias host names for a provided host name.
* `MX` records provide details on mail exchange servers.

`ANY` requests (`dig any ...`) might not provide any information, due to RFC8482.

`TXT` records can be queried to get domain information (stored as text).

### Passive subdomain enumeration

`VirusTotal` can be used to enumerate subdomains, since it maintains results from DNS queries.

`crt.sh` allows us to enumerate subdomains as well, from the issued TLS/SSL certificates.

Automated tool - `TheHarvester`, can take in multiple data sources like `Baidu`, `crt.sh`, `RapidDNS` etc.

### Passive infrastructure enumeration

Useful tools: `Netcraft`, `Internet Archive (WaybackMachine)`

## Active Information Gathering

### Active infrastructure identification

Using `cURL` header requests (`curl -I ...`), we can determine information about the backend (Web server version, language, cookies, etc.)

`Whatweb` can be used to determine web technologies being used (CMS, blogging platforms, JS libraries, web servers etc.).

* Specify scan aggression level using `-a` option, and show verbose output with `-v`.

To check if a WAF is implemented, a tool like `WafW00f` can be used.

If there is a need to actively enumerate many subdomains and get an overview of HTTP attack surfaces, `Aquatone` can be used.

### Active subdomain enumeration

Check Zone Transfers - use online tools like [https://hackertarget.com/zone-transfer/](https://hackertarget.com/zone-transfer/) or `dig`. For the manual `dig` method:

1. Enumerate DNS servers - `dig ns <hostname>`
2. Test for AXFR zone transfers - `dig axfr <hostname> @<dns servername>`

Alternatively, we can use tools like `dnsenum` to enumerate subdomains from a provided word list.

**Gobuster**:
* Brute-force directory enumeration with `dir` option; use a word list in `/usr/share/dirb/wordlists/`.
* Enumerate subdomains using `dns` option; use a word list from the SecLists repository. A pattern can be loaded to `Gobuster` if we are certain that subdomains all follow a specific pattern.

### vHosts

We can fuzz and enumerate vHosts using `ffuf` and a vHost word list (available from SecLists repository):
`ffuf -w ./vhosts -u <hostname/ip address> -H "HOST: FUZZ.<fuzz domain>" -fs <default response size>`

* Default response size can be determined through trial and error using `cURL` requests, where we note the `Content-Length` header for invalid requests.

## Misc

Note that `ffuf` and `Gobuster` can both be used for directory fuzzing/enumeration.

For banner grabbing, use `curl` with `-IL` option.

`robots.txt` is always a low-hanging fruit that we can check.
