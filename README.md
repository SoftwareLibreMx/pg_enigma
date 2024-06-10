# pg_enigma

Encrypted postgres data type for fun and profit

## Build

### Quick start:

Install the Rust toolchain version 1.74.

Initialize pgrx. It only works with version 0.12.0-alpha.1 and newer
but cargo will default to non-alpha versions so we need to specify it
explicitly.

```bash
$ cargo install --locked cargo-pgrx@0.12.0-alpha.1
$ cargo pgrx init
```


Run the extension:

```bash
$ cargo pgrx run
```

SQL example:

```sql
CREATE EXTENSION pg_enigma;
CREATE TABLE testab (
    a SERIAL, 
    b Enigma
);
INSERT INTO testab (b) VALUES ('my first record');
SELECT * FROM testab;
```

Expected result: Postgres shows the encrypted text field

```sql
pg_enigma=# SELECT * FROM testab limit 1;
;
 a |                                b                                 
---+------------------------------------------------------------------
 1 | -----BEGIN PGP MESSAGE-----                                     +
   |                                                                 +
   | wYwDy31dohr4uGABA/0Vl3yMRYwkl0hZ+FkENW5RXJ0PjExcl1xlPVDZXEeFrZEy+
   | 9WwsYuoLnF/UC6fK7tJZvMcgPw5zM3dlJ5Tf4XOGw3eXMJxTvmrRP41KRiyLVU7L+
   | WXvfujaFTdA37CT0mJAr+x5OuUZK30vlP5+ChJUd96PWD9YWuv4WuDNNnEVkO9JE+
   | AXk1/J1kLusQLf0hAPgazCJ6ZnArh9WStZYkHqlgbXZ9YVRjq4+iyLohm/2/OdL9+
   | 1mhsyJ+xn90l2CbKEsFda2Yesbg=                                    +
   | =veYc                                                           +
   | -----END PGP MESSAGE-----                                       +
   | 
(1 row)
```

Now provide the private key using `set_public_key()` function:

```sql
pg_enigma=# select set_private_key('
-----BEGIN PGP PRIVATE KEY BLOCK-----
... ommited key for brevity  ...
-----END PGP PRIVATE KEY BLOCK-----"); 
');
 set_private_key 
-----------------
 Private key set
(1 row)

pg_enigma=# SELECT * FROM testab limit 1;
;
 a |        b        
---+-----------------
 1 | my first record
(1 row)

```

Expected result: Postgres shows the decrypted text field


## Roadmap

### Initial PoC

For encryption/decryption we will use the pgp crate from crates.io [2].
For creating the data type we will use the pgrx framework [1].

1. Create initial data type in pgrx
2. Add function for adding public and private keys to the user session
3. Add function to encrypt the field with the public key
4. Add function to decrypt data using the private key


# References

1. https://github.com/pgcentralfoundation/pgrx
2. https://docs.rs/pgp/latest/pgp/index.html
