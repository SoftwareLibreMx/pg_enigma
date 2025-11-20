## Ersa data type

### SQL example

```sql
CREATE EXTENSION IF NOT EXISTS pg_enigma;
CREATE TABLE test_ersa (
    id SERIAL, 
    val Ersa(3)
);

SELECT set_public_key_from_file(3, 
    '../../pg_enigma/test/alice_public.pem'); 

INSERT INTO test_ersa (val) 
    VALUES ('Secret encrypted with only PGP'::Text);
SELECT * FROM test_ersa;
```

Expected result: 

```sql
pg_enigma=# CREATE EXTENSION IF NOT EXISTS pg_enigma;
NOTICE:  extension "pg_enigma" already exists, skipping
CREATE EXTENSION
pg_enigma=# CREATE TABLE test_ersa (
    id SERIAL, 
    val Ersa(3)
);
CREATE TABLE
pg_enigma=# 
SELECT set_public_key_from_file(3, 
    '../../pg_enigma/test/alice_public.pem'); 
          set_public_key_from_file           
---------------------------------------------
 key 3: public key Id(6) replaced with Id(6)
(1 row)

pg_enigma=# INSERT INTO test_ersa (val) 
    VALUES ('Secret encrypted with only PGP'::Text);
INSERT 0 1
pg_enigma=# SELECT * FROM test_ersa;
 id |                                val                                
----+-------------------------------------------------------------------
  1 | PgE_RSA100000003                                                 +
    | wqiwNQRa3DSxRkRUUMntKw6INX+6+I3PxQoSkcvq6YgV5MYduoEZgmRGUqNyax6Fw+
    | 8oyzLjCvyIVURLpDODXM3TK0XUTONB2v66y9aU/J4FKFHeFDPIGZumdXmReBXbTbs+
    | lQa4Pnuo5+usyy+LfOAyKDr6GveC5wpsrtEHtuXOg=
(1 row)
```

### Encryption validation

```sql
SELECT set_private_key_from_file(3, 
    '../../pg_enigma/test/alice_private.pem', 'Prueba123!');
SELECT * FROM test_ersa;
SELECT forget_private_key(3);
SELECT * FROM test_ersa;
```

Expected result: 

```sql
pg_enigma=# SELECT set_private_key_from_file(3, 
    '../../pg_enigma/test/alice_private.pem', 'Prueba123!');
     set_private_key_from_file     
-----------------------------------
 key 3: private key Id(6) imported
(1 row)

pg_enigma=# SELECT * FROM test_ersa;
 id |              val               
----+--------------------------------
  1 | Secret encrypted with only PGP
(1 row)
pg_enigma=# SELECT forget_private_key(3);
         forget_private_key         
------------------------------------
 key 3: private key Id(6) forgotten
(1 row)

pg_enigma=# SELECT * FROM test_ersa;
 id |                                val                                
----+-------------------------------------------------------------------
  1 | PgE_RSA100000003                                                 +
    | wqiwNQRa3DSxRkRUUMntKw6INX+6+I3PxQoSkcvq6YgV5MYduoEZgmRGUqNyax6Fw+
    | 8oyzLjCvyIVURLpDODXM3TK0XUTONB2v66y9aU/J4FKFHeFDPIGZumdXmReBXbTbs+
    | lQa4Pnuo5+usyy+LfOAyKDr6GveC5wpsrtEHtuXOg=
(1 row)
```

### Cleanup:
```sql
DROP TABLE test_ersa;
DROP EXTENSION pg_enigma CASCADE;
```


