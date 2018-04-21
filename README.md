# yoyo
OpenBSD encryption utility using
[LibreSSL](https://www.libressl.org/).

### Why not simply use openssl?

openssl uses
[EVP_BytesToKey](https://www.openssl.org/docs/manmaster/man3/EVP_BytesToKey.html)
with 1 round of MD5 and a 64-bit salt to derive your key by default.

### What does yoyo use as password-based key derivation function?

128 rounds of
[bcrypt_pbkdf(3)](https://man.openbsd.org/bcrypt_pbkdf)
and a 128-bit salt.
