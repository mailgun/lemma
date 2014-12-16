# lemmacmd

**lemmacmd** is a command-line utility that uses lemma to provide authenticated symmetric cryptography for small files on disk.

*Technical Details:*

* Can be used with either a randomly generated key on disk or a passpharse.
* When used with a passphrase, the key derivation function (KDF) is HMAC-SHA-256 based PBKDF#2 with a randomly generated 128-bit salt and 524,288 iterations (tunable).
* The symmetric cipher used is Salsa20 with Poly1305 as the message authentication code (MAC) from the Networking and Cryptography (NaCl) library.

Usage:

```
lemmacmd encrypt -in foo.txt -out foo.txt.enc
lemmacmd decrypt -in foo.txt.enc -out foo.txt
```
