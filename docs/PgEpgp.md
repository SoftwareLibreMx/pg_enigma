## PgEpgp data type

### SQL example

```sql
CREATE EXTENSION IF NOT EXISTS pg_enigma;
CREATE TABLE test_pgepgp (
    id SERIAL, 
    val PgEpgp(2)
);


SELECT set_public_key_from_file(2, '../../pg_enigma/test/public-key.asc'); 

INSERT INTO test_pgepgp (val) 
VALUES ('Secret encrypted with only PGP'::Text);
SELECT * FROM test_pgepgp;
```

Expected result: 

```sql
pg_enigma=# CREATE EXTENSION IF NOT EXISTS pg_enigma;
NOTICE:  extension "pg_enigma" already exists, skipping
CREATE EXTENSION
pg_enigma=# CREATE TABLE test_pgepgp (
pg_enigma(#     id SERIAL, 
pg_enigma(#     val PgEpgp(2)
pg_enigma(# );
CREATE TABLE
pg_enigma=# SELECT set_public_key_from_file(2, '../../pg_enigma/test/public-key.asc'); 
                     set_public_key_from_file                      
-------------------------------------------------------------------
 key 2: public key cb7d5da21af8b860 replaced with cb7d5da21af8b860
(1 row)
pg_enigma=# INSERT INTO test_pgepgp (val) 
pg_enigma-# VALUES ('Secret encrypted with only PGP'::Text);
INSERT 0 1
pg_enigma=# SELECT * FROM test_pgepgp;
 id |                               val                                
----+------------------------------------------------------------------
  1 | PgE_PGP100000002                                                +
    | wYwDy31dohr4uGABBACCet4IQWOmSxXvu1UJCXKFH4s5FzJgzqNwtEW2wqN4Obc++
    | 9Kb5JgMACov4vY5Qb39cRSL3g0Dhnao1OAaKZbYfydnViE2WK63O9mq+x2EDrZ56+
    | v8tCwZNlffsNi5G83n6cLxXjT4kJHNmeBZZQdklExGpfBnca3B4zpLNZKZ8ydtJP+
    | AfPAiDBvVjEX0yEupu0jjz8OO8czyOngxSgbz8+/+AeADqAAL8Z2oUnJBkcqxN3N+
    | N4ao8E4BYzhv6KcUV0uSE/u97KGBxe/oZkXByjp/0g==                    +
    | =HyrH                                                           +
    | 
(1 row)
```

### Encryption validation

```sql
SELECT set_private_key_from_file(2, 
        '../../pg_enigma/test/private-key.asc', 'Prueba123!');
SELECT * FROM test_pgepgp;
SELECT forget_private_key(2);
SELECT * FROM test_pgepgp;
```

Expected result: 

```sql
pg_enigma=# SELECT set_private_key_from_file(2, 
pg_enigma(#         '../../pg_enigma/test/private-key.asc', 'Prueba123!');
          set_private_key_from_file           
----------------------------------------------
 key 2: private key cb7d5da21af8b860 imported
(1 row)

pg_enigma=# SELECT * FROM test_pgepgp;
 id |              val               
----+--------------------------------
  1 | Secret encrypted with only PGP
(1 row)

pg_enigma=# SELECT forget_private_key(2);
              forget_private_key               
-----------------------------------------------
 key 2: private key cb7d5da21af8b860 forgotten
(1 row)

pg_enigma=# SELECT * FROM test_pgepgp;
 id |                               val                                
----+------------------------------------------------------------------
  1 | PgE_PGP100000002                                                +
    | wYwDy31dohr4uGABBACCet4IQWOmSxXvu1UJCXKFH4s5FzJgzqNwtEW2wqN4Obc++
    | 9Kb5JgMACov4vY5Qb39cRSL3g0Dhnao1OAaKZbYfydnViE2WK63O9mq+x2EDrZ56+
    | v8tCwZNlffsNi5G83n6cLxXjT4kJHNmeBZZQdklExGpfBnca3B4zpLNZKZ8ydtJP+
    | AfPAiDBvVjEX0yEupu0jjz8OO8czyOngxSgbz8+/+AeADqAAL8Z2oUnJBkcqxN3N+
    | N4ao8E4BYzhv6KcUV0uSE/u97KGBxe/oZkXByjp/0g==                    +
    | =HyrH                                                           +
    | 
(1 row)
```
