---
layout: single
title:  "Cryptography: RSA"
categories: 
  - Notes
tags:
  - crypto
  - notes
toc: true
use_math: true
toc_label: "Contents"
toc_icon: "list"  # corresponding Font Awesome icon name (without fa prefix)
author_profile: false
sidebar:
  nav: "navbar"
---

Hiya! It's been a while since I last made a post here.

I've recently started to learn more about Cryptography (in a formal University lecture setting) and I wanted to share some Crypto-related things that I've learnt here, to consolidate my learning, and to aid my revision for the upcoming midterm exams.

I've really enjoyed learning about Cryptography thus far (at an introductory level), and I find it super interesting! Given my interest, I am therefore planning to take some higher level Crypto-based modules in the future, in order to learn more.

* For example, [CS4236 - Cryptography Theory and Practice](https://nusmods.com/courses/CS4236/cryptography-theory-and-practice).

I am also considering taking some algorithm-centric modules (like [CS3230 - Design and Analysis of Algorithms](https://nusmods.com/courses/CS3230/design-and-analysis-of-algorithms)), though I will say, that my math isn't necessarily the strongest, and I don't really like grinding out DSA leetcode problems either. Of course, I will definitely try to take steps and improve in these aspects before I take a plunge into the deep end 😁.

Apologies for the digression. Without further ado, let's dive right into the first topic on RSA!

## What is RSA?

From [Wikipedia](https://en.wikipedia.org/wiki/RSA_(cryptosystem)):
> RSA (Rivest–Shamir–Adleman) is a public-key cryptosystem, one of the oldest widely used for secure data transmission. The initialism "RSA" comes from the surnames of Ron Rivest, Adi Shamir and Leonard Adleman, who publicly described the algorithm in 1977.

When we think of Public-Key Cryptography (PKC), RSA will probably be the first thing to come to mind. It is probably the most well-known cryptographic method, and is still widely used today.

In spite of its age, RSA is still considered to be secure. This is because the security of RSA stems from the computational difficulty/infeasibility in solving the [RSA problem](https://en.wikipedia.org/wiki/RSA_problem) (more on this later).

## How does RSA work?

Firstly, let's establish the values that we will need for RSA:

* $e$: Exponent value (commonly used values are $3,5,65537$)
* $n$: Modulus value. This value must be very large (Officially, NIST recommends that the $n$ value should be at least 2048 bits in size).
* $d$: Decryption key/exponent. This value must be kept secret.

Our public key consists of the values $(n,e)$, while the private key consists of $(n,d)$.

RSA is based off the idea of modular arithmetic. In essence, to encrypt a message $m$ into a ciphertext $c$, we do the following:
$$c = m^e \mod n$$

Then, to decrypt the ciphertext, we do the following:
$$m = c^d \mod n$$

Let's take a look at the "Textbook" RSA algorithm:

1. Firstly, randomly choose two large **prime** numbers $p$ and $q$. Ensure that $p$ and $q$ remain secret.
2. Then, compute $n=pq$.
3. Compute $\phi(n)$, where $\phi(n)=(p-1)(q-1)$. Likewise, ensure $\phi(n)$ remains secret.
4. Choose an exponent $e$ such that $e$ and $\phi(n)$ are relatively prime/coprime. That is, $gcd(e, \phi(n))=1$.
5. Lastly, compute $d$. Since $e$ and $\phi(n)$ are coprime, the following relation thus holds:<br>$$1 \equiv de \mod \phi(n)$$<br>And therefore,<br>$$d \equiv e^{-1} \mod \phi(n)$$

That's it. The logic here is unnervingly simple. Yet, it remains secure.

This is because of the aforementioned RSA problem. Essentially, if $n$ is a very large number (e.g., 2048 bits in size), then it becomes computationally infeasible to factorize $n$ into $p$ and $q$. Without $p$ and $q$, we will not be able to determine our decryption key $d$. And of course, without $d$, we cannot derive our plaintext message $m$ from the ciphertext $c$.

## Considerations

Of course, in spite of RSA's simple algorithm, there are still some key considerations that need to be made. Some of which, if not followed, will compromise the security of the encryption scheme.

### How should we determine the value and size of $e$?

It was mentioned earlier that $e$ has some commonly used values. First and foremost, it certainly helps if we choose $e$ to be a prime number, as this could help to ensure the condition of $gcd(e,\phi(n))=1$. Of course, this isn't a must. If $e$ and $\phi(n)$ are both composite, but the GCD is still 1, then RSA should still work.

However, we should also take note that $e$ cannot be too small, as this will make our implementation susceptible to attacks (more on this later). Likewise, if $e$ is too large, then exponentiation becomes more difficult, and encryption will take a much longer time.

Therefore, we opt to take a standard value of $e$, which is $65537$.

### How should we find $d$?

If $e$ and $n$ are known, then we can simply apply the Extended Euclidean algorithm to derive the value of $d$.

### Speed of modular exponentiation

Modular exponentiation is computationally expensive, especially if the exponent is large. To speed this process up, there exist some algorithms (e.g., square-and-multiply algorithm) which allow us to do exponentiation quicker.

Likewise, decryption can also take a long time if we do not optimize it. In this case, we can look to apply the Chinese Remainder Theorem to speed up the decryption process.

### Security of unpadded messages

Assuming that our RSA implementation has a flaw, it now becomes easy to determine our plaintext message $m$. To avoid this, we should seek to introduce some randomness into our encryption scheme. This can be done by padding our messages. Padding introduces an additional layer for the attacker to tackle, making it tougher for them to determine $m$.

Padding also mitigates certain attacks, and makes RSA less deterministic in nature.

### How random are the random primes?

In practice, secure random number generators are used to generate our primes $p$ and $q$. But, in the "Textbook" implementation, we will typically use non-secure pseudorandom number generation functions (like the Mersenne Twister) for ease of implementation. Of course, using non-secure methods of random number generation will severely compromise security of RSA.

## Possible Attacks on RSA

Here is a non-exhaustive list of potential RSA attacks:

* Weak Public Key $n$ - easily exploitable. Do a lookup for the factors of $n$ on a number factor database like FactorDB.
* Wiener's attack/Boneh-Durfee's attack, for small values of $d$ (decryption key).
* Coppersmith's attack/Hastad's Broadcast attack, for small exponents $e$. The Chinese Remainder Theorem is utilized in this attack.
* GCD of $e$ and $\phi(n)$ is not 1 - use Euclidean Algorithm to find a common factor for N.
* Exploiting the homomorphic property of RSA: Recall that $enc(m) = m^e \mod n$. Then, given the homomorphic property of RSA,<br>
  $$enc(m_1) \times enc(m_2) = m_1^e \mod n \times m_2^e \mod n \\
  = (m_1^em_2^e) \mod n \\
  = (m_1m_2)^e \mod n \\
  = enc(m_1m_2)$$
* Smooth $p-1$ value - use Pollard's p-1 algorithm
* Fermat's factorization algorithm if $p$ and $q$ are too close
