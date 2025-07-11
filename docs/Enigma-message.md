## Enigma message format

Enigma message is composed of two parts separated by newline character `\n`:

Enigma header (exactly 16 octets) with optional more keys (multiple of 16)
Separator `\n`
Message payload (PGP or RSA)

### Enigma header

Enigma header is exactly 16 octets. 

First 8 octets are Enigma tag `0x454E49474D417631`. It's value can be verified as 32-bit integer or as string `ENIGMAv1`. 

Next 8 octets are hex-encoded 32-bit integer corresponding to enigma key_id in *typmod*. Since typmod is signed integer, maximum key_id value can not be greater than `2,147,483,647`.

This fixed size header is for parsing efficiency.

More keys is reserved for future use as hex-encoded 64-bit PGP IDs or a 32-bit enigma key_ids casted as 64-bit integer.

Separator `\n` ends Enigma header. All keys in header are hex-encoded, so first non-hex character `\n` is non-ambiguous separator for string handling functions.

### Message payload

Enigma supports text-armored PGP encrypted messages as well as more simple encryption using OpenSSL functions, base64 encoded with custom Enigma envelope.

### Example

```sql
pg_enigma=# SELECT * FROM testab;
 a |                                b                                 
---+------------------------------------------------------------------
 1 | ENIGMAv100000002                                                +
   | -----BEGIN PGP MESSAGE-----                                     +
   |                                                                 +
   | wYwDy31dohr4uGABA/9Vx7nR1mOaGnwYQu7q5PTn71c3jOmuH2TgzDaYj77VAuAM+
   | YT5K78n/1mQtjWhbKpJANEF6UuvyDAMBQGLSwfrliqeJZpZks0SE/pHwAixiz3Z4+
   | 89BH4ivO3FFa9Hz0++crCSo5h10HJtuXB+JmrHFNWZDvMp5ogMrsL74nfAEfXtJE+
   | AU7DKyNkf/11b5OCPVlOF+DRmEcW90h6vWjuP0l8mqQxy8FQ1r1HKXxX3ysBeP7X+
   | 5d4tF51WNOAFba8KQtSeVT3FcNQ=                                    +
   | =/iec                                                           +
   | -----END PGP MESSAGE-----                                       +
   | 
(1 row)

```
