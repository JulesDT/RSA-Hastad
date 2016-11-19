# RSA-Chinese-Remainder
Little python tool to use the Chinese Remainder theorem attack on RSA under precise conditions. (Known as Hastad attack or Broadcast Attack)

Three identical messages must be encrypted with three different RSA public keys having all the same public exponent which must be equal to 3.

# Usage

```
python rsaHastad.py <n0 File> <n1 File> <n2 File> <c0 File> <c1 File> <c2 File> [--decimal/--hex/--b64] [-v/--verbose]
```

```
<n0 File>,<n1 File>,<n2 File> : Files containing the different public key (PEM or directly decimal)
<c0 File>,<c1 File>,<c2 File> : Files containing the different ciphers linked with previous public keys. (Decimal, Hexadecimal or base64 encoded)
[--decimal/--hex/--b64] : Without indication, the algorithm will try to detect the cipher encoding format. But you can force the consideration of one mod by using one of these commands.
[-v/--verbose] : Show debug output
```