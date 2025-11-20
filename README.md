# pg_enigma

Encrypted postgres data type for fun and profit

## Build

### Quick start:

Install the Rust toolchain version 1.74 or newer.

```bash
$ cargo install --locked cargo-pgrx
$ cargo pgrx init
```


Run the extension:

```bash
$ cargo pgrx run
```

### SQL example with PGP key:

```sql
CREATE EXTENSION IF NOT EXISTS pg_enigma;
CREATE TABLE test_pgp (
    id SERIAL, 
    val Enigma(2)
);

SELECT set_public_key_from_file(2, '../../pg_enigma/test/public-key.asc'); 

INSERT INTO test_pgp (val) VALUES ('A secret value'::Text);
SELECT * FROM test_pgp;
```

Expected result: 

```sql
pg_enigma=# SELECT * FROM test_pgp;
 id |                               val                                
----+------------------------------------------------------------------
  1 | ENIGMAv100000002                                                +
    | -----BEGIN PGP MESSAGE-----                                     +
    |                                                                 +
    | wYwDy31dohr4uGABA/9iLU8G7m1kJaet4yQiAu1Ew+pj6pzSU8jZ/eZimim6G2zV+
    | SSlT6bR/Uc6UIT9CpOWqhISg/3Tlk+nQRBtbo2VK/8eC+vO2NxSVIVkiCM5Ij+Ak+
    | z6P5AR94QrITggDgn24ztvxFdYivAImXOoazQcEAb+4arTRwpRE37ej66p3L+9I/+
    | AZjU5IvqF/vMVnjxO3XsL7fHPsBVrv1taLEiU5bh5TUfT1b9EXcbX/8YIOlZBUQR+
    | Apxdy5l+vDp2aaNEhF4d                                            +
    | =SlT3                                                           +
    | -----END PGP MESSAGE-----                                       +
    | 
(1 row)
```

Now provide the private key using `set_private_key_from_file()` function:

```sql
SELECT set_private_key_from_file(2, 
        '../../pg_enigma/test/private-key.asc', 'Prueba123!');
SELECT * FROM test_pgp;
```

Expected result:

```sql
pg_enigma=# SELECT set_private_key_from_file(2, 
pg_enigma(#         '../../pg_enigma/test/private-key.asc', 'Prueba123!');
          set_private_key_from_file           
----------------------------------------------
 key 2: private key cb7d5da21af8b860 imported
(1 row)

pg_enigma=# SELECT * FROM test_pgp;

 id |      val       
----+----------------
  1 | A secret value
(1 row)
```


Now delete the private key using `forget_private_key()` function:

```sql
SELECT forget_private_key(2);
SELECT * FROM test_pgp;
```
Expected result: 

```sql
pg_enigma=# SELECT forget_private_key(2);
              forget_private_key               
-----------------------------------------------
 key 2: private key cb7d5da21af8b860 forgotten
(1 row)

pg_enigma=# SELECT * FROM test_pgp;
 id |                               val                                
----+------------------------------------------------------------------
  1 | ENIGMAv100000002                                                +
    | -----BEGIN PGP MESSAGE-----                                     +
    |                                                                 +
    | wYwDy31dohr4uGABA/9iLU8G7m1kJaet4yQiAu1Ew+pj6pzSU8jZ/eZimim6G2zV+
    | SSlT6bR/Uc6UIT9CpOWqhISg/3Tlk+nQRBtbo2VK/8eC+vO2NxSVIVkiCM5Ij+Ak+
    | z6P5AR94QrITggDgn24ztvxFdYivAImXOoazQcEAb+4arTRwpRE37ej66p3L+9I/+
    | AZjU5IvqF/vMVnjxO3XsL7fHPsBVrv1taLEiU5bh5TUfT1b9EXcbX/8YIOlZBUQR+
    | Apxdy5l+vDp2aaNEhF4d                                            +
    | =SlT3                                                           +
    | -----END PGP MESSAGE-----                                       +
    | 
(1 row)
```
### SQL example with OpenSSL RSA key:

```sql
CREATE EXTENSION IF NOT EXISTS pg_enigma;
CREATE TABLE test_rsa (
    id SERIAL, 
    val Enigma(3)
);

SELECT set_public_key_from_file(3, 
    '../../pg_enigma/test/alice_public.pem'); 

INSERT INTO test_rsa (val) VALUES ('Another secret value'::Text);
SELECT * FROM test_rsa;
```

Expected result: 

```sql
pg_enigma=# SELECT * FROM test_rsa;
 id |                                                                           
          val                                                                   
                   
----+---------------------------------------------------------------------------
--------------------------------------------------------------------------------
-------------------
  1 | ENIGMAv100000003                                                          
                                                                                
                  +
    | -----BEGIN RSA ENCRYPTED-----                                             
                                                                                
                  +
    | PgQ2vZ3WH8KclgsbyCdKHEFJeHydAxpa0FFShomabqkdivTMtmV5TMW0Lf31JvdgOPc8m438qS
qYk5L7hAynF4Lp2EH+mxHUp95l1x7RE6B8cPHMATM5Kdgn7Rld2Uh/JLXw0WYBX1SO3qXrseSFsLsMvX
IJk4DuOC4LlS+15IU=+
    | -----END RSA ENCRYPTED-----
(1 row)
```

Now provide the private key using `set_private_key_from_file()` function:

```sql
SELECT set_private_key_from_file(3, 
    '../../pg_enigma/test/alice_private.pem', 'Prueba123!');
SELECT * FROM test_rsa ;
```

Expected result:

```sql
pg_enigma=# SELECT set_private_key_from_file(3, 
pg_enigma(#     '../../pg_enigma/test/alice_private.pem', 'Prueba123!');
     set_private_key_from_file     
-----------------------------------
 key 3: private key Id(6) imported
(1 row)

pg_enigma=# SELECT * FROM test_rsa ;
 id |         val          
----+----------------------
  1 | Another secret value
(1 row)
```


Now delete the private key using `forget_private_key()` function:

```sql
SELECT forget_private_key(3);
SELECT * FROM test_rsa ;
```
Expected result: 

```sql
pg_enigma=# SELECT forget_private_key(3);
         forget_private_key         
------------------------------------
 key 3: private key Id(6) forgotten
(1 row)

pg_enigma=# SELECT * FROM test_rsa ;
 id |                                                                           
          val                                                                   
                   
----+---------------------------------------------------------------------------
--------------------------------------------------------------------------------
-------------------
  1 | ENIGMAv100000003                                                          
                                                                                
                  +
    | -----BEGIN RSA ENCRYPTED-----                                             
                                                                                
                  +
    | PgQ2vZ3WH8KclgsbyCdKHEFJeHydAxpa0FFShomabqkdivTMtmV5TMW0Lf31JvdgOPc8m438qS
qYk5L7hAynF4Lp2EH+mxHUp95l1x7RE6B8cPHMATM5Kdgn7Rld2Uh/JLXw0WYBX1SO3qXrseSFsLsMvX
IJk4DuOC4LlS+15IU=+
    | -----END RSA ENCRYPTED-----
(1 row)
```


### SQL example with both OpenSSL RSA and PGP keys:

```sql
CREATE EXTENSION IF NOT EXISTS pg_enigma;
CREATE TABLE test_both (
    id SERIAL, 
    val1 Enigma(2),
    val2 Enigma(3)
);

INSERT INTO test_both (val1, val2) VALUES (
    'First secret value'::Text,
    'Second secret value'::Text
    );
SELECT * FROM test_both;
```

Expected result: 

```sql
pg_enigma=# \x
Expanded display is on.
pg_enigma=# SELECT * FROM test_both;
-[ RECORD 1 ]----------------------------------------------------------------------------------------------------------------------------------------------------------------------
id   | 1
val1 | ENIGMAv100000002                                                                                                                                                            +
     | -----BEGIN PGP MESSAGE-----                                                                                                                                                 +
     |                                                                                                                                                                             +
     | wYwDy31dohr4uGABA/9iLU8G7m1kJaet4yQiAu1Ew+pj6pzSU8jZ/eZimim6G2zV                                                                                                            +
     | SSlT6bR/Uc6UIT9CpOWqhISg/3Tlk+nQRBtbo2VK/8eC+vO2NxSVIVkiCM5Ij+Ak                                                                                                            +
     | z6P5AR94QrITggDgn24ztvxFdYivAImXOoazQcEAb+4arTRwpRE37ej66p3L+9JD                                                                                                            +
     | AZjU5IvqF/vMVnjxO3XsL7fHPsBZrv1taLEiVN/g8yJNkAn5aWK5MzJvSqvDFQ4x                                                                                                            +
     | Oqd0LjgNiSdrG3VKrfS3RWECag==                                                                                                                                                +
     | =IPIc                                                                                                                                                                       +
     | -----END PGP MESSAGE-----                                                                                                                                                   +
     | 
val2 | ENIGMAv100000003                                                                                                                                                            +
     | -----BEGIN RSA ENCRYPTED-----                                                                                                                                               +
     | zK830KOmFaQ94/PEcfqCpssL6SIhF9xPI8jBqi/gRVyKH29UvTYGQK2QvVHLrSbX2inVJXltBoYOU1AO2ND1bhU8dzCtoUhstRPyzt8Gs2zCIfERHN6zAs6aOI2ao0b06rCBaAFF/xpd8YhDa9lsAkhhPqifPkJmzXBsXxvm6ss=+
     | -----END RSA ENCRYPTED-----
```

Now provide one private key using `set_private_key_from_file()` function:

```sql
SELECT set_private_key_from_file(3, 
    '../../pg_enigma/test/alice_private.pem', 'Prueba123!');
SELECT * FROM test_rsa ;
```

Expected result:

```sql
pg_enigma=# \x
Expanded display is off.
pg_enigma=# SELECT set_private_key_from_file(3, 
pg_enigma(#     '../../pg_enigma/test/alice_private.pem', 'Prueba123!');
     set_private_key_from_file     
-----------------------------------
 key 3: private key Id(6) imported
(1 row)
pg_enigma=# \x
Expanded display is on.
pg_enigma=# SELECT * FROM test_both;
-[ RECORD 1 ]----------------------------------------------------------
id   | 1
val1 | ENIGMAv100000002                                                +
     | -----BEGIN PGP MESSAGE-----                                     +
     |                                                                 +
     | wYwDy31dohr4uGABA/9iLU8G7m1kJaet4yQiAu1Ew+pj6pzSU8jZ/eZimim6G2zV+
     | SSlT6bR/Uc6UIT9CpOWqhISg/3Tlk+nQRBtbo2VK/8eC+vO2NxSVIVkiCM5Ij+Ak+
     | z6P5AR94QrITggDgn24ztvxFdYivAImXOoazQcEAb+4arTRwpRE37ej66p3L+9JD+
     | AZjU5IvqF/vMVnjxO3XsL7fHPsBZrv1taLEiVN/g8yJNkAn5aWK5MzJvSqvDFQ4x+
     | Oqd0LjgNiSdrG3VKrfS3RWECag==                                    +
     | =IPIc                                                           +
     | -----END PGP MESSAGE-----                                       +
     | 
val2 | Second secret value

```

Now provide the other private key using `set_private_key_from_file()` function:

```sql
SELECT set_private_key_from_file(2, 
        '../../pg_enigma/test/private-key.asc', 'Prueba123!');
SELECT * FROM test_both ;
```

Expected result:

```sql
pg_enigma=# SELECT set_private_key_from_file(2, 
pg_enigma(#         '../../pg_enigma/test/private-key.asc', 'Prueba123!');
-[ RECORD 1 ]-------------+---------------------------------------------
set_private_key_from_file | key 2: private key cb7d5da21af8b860 imported

pg_enigma=# SELECT * FROM test_both ;
-[ RECORD 1 ]-------------
id   | 1
val1 | First secret value
val2 | Second secret value
```

Now delete the first private key using `forget_private_key()` function:

```sql
SELECT forget_private_key(3);
SELECT * FROM test_both ;
```
Expected result: 

```sql
pg_enigma=# SELECT forget_private_key(3);
-[ RECORD 1 ]------+-----------------------------------
forget_private_key | key 3: private key Id(6) forgotten

pg_enigma=# SELECT * FROM test_both ;

-[ RECORD 1 ]----------------------------------------------------------------------------------------------------------------------------------------------------------------------
id   | 1
val1 | First secret value
val2 | ENIGMAv100000003                                                                                                                                                            +
     | -----BEGIN RSA ENCRYPTED-----                                                                                                                                               +
     | zK830KOmFaQ94/PEcfqCpssL6SIhF9xPI8jBqi/gRVyKH29UvTYGQK2QvVHLrSbX2inVJXltBoYOU1AO2ND1bhU8dzCtoUhstRPyzt8Gs2zCIfERHN6zAs6aOI2ao0b06rCBaAFF/xpd8YhDa9lsAkhhPqifPkJmzXBsXxvm6ss=+
     | -----END RSA ENCRYPTED-----
```


### Cleanup:
```sql
DROP TABLE test_pgp;
DROP TABLE test_rsa;
DROP TABLE test_both;
DROP EXTENSION pg_enigma CASCADE;
```

## Roadmap

### Release

1. Create PGP-only data type using rPGP
2. Create RSA-only data type using OpenSSL
3. Create ECC-only data type using OpenSSL
4. Line-wrap OpenSSL encrypted values
5. Remove unneeded start/end tags from encrypted payload
6. Keep compatibility with ENIGMAv1 envelope

# References

1. https://github.com/pgcentralfoundation/pgrx
2. https://docs.rs/pgp/latest/pgp/index.html
3. https://docs.rs/openssl/latest/openssl/ssl/index.html
