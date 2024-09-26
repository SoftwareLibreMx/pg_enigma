# pg_enigma

Encrypted postgres data type for fun and profit

## Build

### Quick start:

Install the Rust toolchain version 1.74 or nwer.

Initialize pgrx. It only works with version 0.12.0-beta.3 and newer
but cargo will default to non-alpha versions so we need to specify it
explicitly.

```bash
$ cargo install --locked cargo-pgrx@0.12.0-beta.3
$ cargo pgrx init
```


Run the extension:

```bash
$ cargo pgrx run
```

### SQL example with PGP key:

```sql
CREATE EXTENSION pg_enigma;
CREATE TABLE testab (
    a SERIAL, 
    b Enigma(2)
);

SELECT set_public_key_from_file(1, '../../pg_enigma/test/public-key.asc'); 

INSERT INTO testab (b) VALUES ('my first record');
SELECT * FROM testab;
```

Expected result: 

```sql
pg_enigma=# SELECT * FROM testab;
 a |                                b                                 
---+------------------------------------------------------------------
 1 | -----BEGIN PGP MESSAGE-----                                     +
   |                                                                 +
   | wYwDy31dohr4uGABA/45KaIlv1ZJXZR95+G3pJ4VWap30O5INnS9JS/BFhGXqi1d+
   | nvFTh6OTLMLdLGtFOMieUM6pxig8I0QtniGmsPjnvP4m71xaMLH4H5S0JeiAgbTL+
   | pIijvCiz3kzu+2lmrk6zRF7+Wlvy1lsFsUZFa/PbxaSzy/uR16z20VgThvlHkdJE+
   | AUgLHhr4lfLn220vbcXsWbZy/3iGikogqbC9d1yuMHr5pMrE6/BVtp6YCuntMEXQ+
   | Fva1L7XrceyNGkci9VgMU8CK3rg=                                    +
   | =COGv                                                           +
   | -----END PGP MESSAGE-----                                       +
   | 
(1 row)
```

Now provide the private key using `set_private_key_from_file()` function:

```sql
SELECT set_private_key_from_file(1, 
	'/path/to/private-key.asc', 'Private key passphrase');
SELECT * FROM testab limit 1;
```

Expected result:

```sql
pg_enigma=# SELECT set_private_key_from_file(1, 
        '../../pg_enigma/test/private-key.asc', 'Prueba123!');
          set_private_key_from_file          
---------------------------------------------
 key 1: secret key CB7D5DA21AF8B860 imported
(1 row)

pg_enigma=# SELECT * FROM testab limit 1;
 a |        b        
---+-----------------
 1 | my first record
(1 row)
```


Now delete the private key using `forget_private_key()` function:

```sql
SELECT forget_private_key(1);
SELECT * FROM testab limit 1;
```
Expected result: 

```sql
pg_enigma=# SELECT forget_private_key(1);
              forget_private_key              
----------------------------------------------
 key 1: secret key CB7D5DA21AF8B860 forgotten
(1 row)

pg_enigma=# SELECT * FROM testab limit 1;
 a |                                b                                 
---+------------------------------------------------------------------
 1 | -----BEGIN PGP MESSAGE-----                                     +
   |                                                                 +
   | wYwDy31dohr4uGABA/45KaIlv1ZJXZR95+G3pJ4VWap30O5INnS9JS/BFhGXqi1d+
   | nvFTh6OTLMLdLGtFOMieUM6pxig8I0QtniGmsPjnvP4m71xaMLH4H5S0JeiAgbTL+
   | pIijvCiz3kzu+2lmrk6zRF7+Wlvy1lsFsUZFa/PbxaSzy/uR16z20VgThvlHkdJE+
   | AUgLHhr4lfLn220vbcXsWbZy/3iGikogqbC9d1yuMHr5pMrE6/BVtp6YCuntMEXQ+
   | Fva1L7XrceyNGkci9VgMU8CK3rg=                                    +
   | =COGv                                                           +
   | -----END PGP MESSAGE-----                                       +
   | 
(1 row)
```
### SQL example with OpenSSL RSA key:

```sql
CREATE EXTENSION pg_enigma;
CREATE TABLE testab (
    a SERIAL, 
    b Enigma
);

SELECT set_public_key_from_file(1, 
    '../../pg_enigma/test/alice_public.pem'); 

INSERT INTO testab (b) VALUES ('my first record');
SELECT * FROM testab;
```

Expected result: 

```sql
pg_enigma=# SELECT * FROM testab;
 a |                                                                                      b                                            
                                           
---+-----------------------------------------------------------------------------------------------------------------------------------
-------------------------------------------
 1 | TpLdFYmTDx1ZHPlTrGMAZAkYD/vsN92SpjsEQUUp6HNgPSpb430yd4/odMbWCmqInWnyE7po5uUEp5O6h2/+uqne8OZPChUt7erb8MshnkhKdUa50yIDrcy0KcJ8tglrND
N2E+xKX1xkxgji7vIKx0XXAXC9pQEC1gMtQYHyOBA=
(1 row)
```

Now provide the private key using `set_private_key_from_file()` function:

```sql
SELECT set_private_key_from_file(1, 
	'/path/to/private-key.asc', 'Private key passphrase');
SELECT * FROM testab limit 1;
```

Expected result:

```sql
pg_enigma=# SELECT set_private_key_from_file(1, 
    '../../pg_enigma/test/alice_private.pem', 'Prueba123!');
   set_private_key_from_file   
-------------------------------
 key 1: private key 6 imported
(1 row)

pg_enigma=# SELECT * FROM testab limit 1;
 a |        b        
---+-----------------
 1 | my first record
(1 row)
```


Now delete the private key using `forget_private_key()` function:

```sql
SELECT forget_private_key(1);
SELECT * FROM testab limit 1;
```
Expected result: 

```sql
pg_enigma=# SELECT forget_private_key(1);
       forget_private_key       
--------------------------------
 key 1: private key 6 forgotten
(1 row)

pg_enigma=# SELECT * FROM testab limit 1;
 a |                                                                                      b                                            
                                           
---+-----------------------------------------------------------------------------------------------------------------------------------
-------------------------------------------
 1 | TpLdFYmTDx1ZHPlTrGMAZAkYD/vsN92SpjsEQUUp6HNgPSpb430yd4/odMbWCmqInWnyE7po5uUEp5O6h2/+uqne8OZPChUt7erb8MshnkhKdUa50yIDrcy0KcJ8tglrND
N2E+xKX1xkxgji7vIKx0XXAXC9pQEC1gMtQYHyOBA=
(1 row)

```


### Cleanup:
```sql
DROP TABLE testab;
DROP EXTENSION pg_enigma;
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
