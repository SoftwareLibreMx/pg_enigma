# pg_enigma

Encrypted postgres data type for fun and profit

## Build

### Quick start:

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
