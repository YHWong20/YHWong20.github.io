---
layout: single
title:  "osu!gaming CTF 2024 - wysi-baby"
categories: 
  - Reverse Engineering
tags:
  - ctf
toc: true
use_math: true
toc_label: "Contents"
toc_icon: "list"  # corresponding Font Awesome icon name (without fa prefix)
---

Hello!

A few months back, I took part in the inaugural [osu!gaming CTF 2024](https://ctf.osugaming.lol).

As I wasn't able to find anyone else to play with, this ended up as a solo attempt.

As a CTF newbie, I definitely learnt a lot from this competition, though I also have to say that I'm a little upset at my own performance.

This was because most of the challenges I solved were relatively trivial, with the exception of this challenge.

If you're interested, these were the challenges I solved during the competition period:

![](/assets/images/osugamingctf/score.png)

If time permits, I'd certainly like to give the unattempted challenges a try too. If I do solve them, I'll post my writeups for those challenges here as well.

Without further ado, let's dive into the writeup for this challenge!

## Writeup

> [https://web-osu-wysi.surge.sh/](https://web-osu-wysi.surge.sh/)
>
> For non-osu! players: [Aireu 727 WYSI on YouTube](https://youtu.be/AaAF51Gwbxo?si=uDjC7UM9IQ_jUx7o&t=60)
>
> Author: sahuang

If we click on the link provided, we are greeted with a very ugly looking webpage:

![](/assets/images/osugamingctf/webosu.png)

If we try to inspect the page's source, we see the following:

![](/assets/images/osugamingctf/source1.png)

It thus seems that each button has a specific value. For example, the `WYSI` row of buttons map to the values 1-4 respectively.

Scrolling down, we see a piece of interesting JavaScript code:

![](/assets/images/osugamingctf/source2.png)

Copying the code here for better readability:

```javascript
var combos = [];

function wysi() {
    if (combos.length === 8) {
    var cs = combos.join("");
    var csr = cs + cs.split("").reverse().join("");
    var res = CryptoJS.AES.decrypt("5LJJj+x+/cGxhxBTdj/Q2RxkhgbH7v8b/IgX9Kjptpo=", CryptoJS.enc.Hex.parse(csr + csr), { mode: CryptoJS.mode.ECB }).toString(CryptoJS.enc.Utf8);
    // if prefix is "osu{" then its correct
    if (res.startsWith("osu{")) {
        document.getElementById("music").innerHTML = '<audio src="./wysi.mp3" autoplay></audio>';
        console.log(res);
    } else {
        // reset
        console.log("nope.");
        combos = [];
    }
    }
}
```

In essence, each combination of button clicks will get loaded into the `combos` array, as an array of integer values. This array is then processed by the `wysi()` function.

Firstly, it checks that the combo length is `8`. We thus know that we need to click a combination of exactly 8 buttons for this function to work.

Next, this combination formatted into a palindromic sequence. For example, if our input sequence is `[1,2,3,4,5,6,7,8]`, the combination is formatted into `1234567887654321`. We wish to note that this is a 16-byte sequence.

Then, this 16-byte block is decrypted via AES in ECB mode, and converted to a plaintext in UTF-8 encoding. Evidently, if this plaintext is the flag, the win condition of the function is triggered, where it plays an `.mp3` file.

To solve this, we can conduct an exhaustive search.

Taking into consideration the size of the input, we have $10^8$ possible input permutations. This yields a complexity of approximately $2^{27}$, and thus, it is highly feasible to simply do an exhaustive search here.

Hence, we can modify this piece of JS code and use it to run an exhaustive search.

```javascript
// import CryptoJS from 'crypto-js'
const CryptoJS = require('crypto-js');

for (let i = 00000000; i <= 99999999; i++) {
    var cs = "" + i;
    
    try { 
        var csr = cs + cs.split("").reverse().join("");
        var res = CryptoJS.AES.decrypt("5LJJj+x+/cGxhxBTdj/Q2RxkhgbH7v8b/IgX9Kjptpo=", CryptoJS.enc.Hex.parse(csr + csr), { mode: CryptoJS.mode.ECB }).toString(CryptoJS.enc.Utf8);
        // if prefix is "osu{" then its correct
        if (res.startsWith("osu{")) {
            console.log(cs);
            console.log(res);
            break;
        }
    } catch(err) {
        
    }
}
```

This will take a while to run. But eventually, we will get our required input value, as well as the flag.

```bash
$ node solve.js
72709913
osu{baby_js_osu_web_uwu}
```
