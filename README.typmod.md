# pg_enigma typmod bug

## Enigma with no typmod

### Reproduce the bug

Create a table with an `Enigma` column without typmod.
```sql
CREATE EXTENSION pg_enigma;
CREATE TABLE testab (
    a SERIAL, 
    b Enigma -- Enigma with no typmod
);
```

`INSERT` goes directly to the `INPUT` function where tymmod is ambiguous.

```sql
-- do not set any public key
INSERT INTO testab (b) VALUES ('my first record');
-- do not set any private key
SELECT * FROM testab;
```

Using `ASSIGNMENT` cast sets the correct typmod on third argument:
```sql
pg_enigma=# INSERT INTO testab (b) VALUES ('my first record'::Text);
ERROR:  Unknown typmod: -1
original: "my first record"
explicit: false
```

## Enigma with typmod

### Reproducing `INSERT` with typmod on `0.4.0`

```sql
pg_enigma=# CREATE EXTENSION pg_enigma;
CREATE EXTENSION
pg_enigma=# CREATE TABLE testab (
pg_enigma(#     a SERIAL, 
pg_enigma(#     b Enigma(2)
pg_enigma(# );
CREATE TABLE
pg_enigma=# SELECT set_public_key_from_file(2, '../../pg_enigma/test/public-key.asc'); 
                     set_public_key_from_file                      
-------------------------------------------------------------------
 key 2: public key cb7d5da21af8b860 replaced with cb7d5da21af8b860
(1 row)

pg_enigma=# INSERT INTO testab (b) VALUES ('my first record');
INSERT 0 1
pg_enigma=# SELECT * FROM testab;
 a |                                b                                 
---+------------------------------------------------------------------
 1 | ENIGMAv100000002                                                +
   | -----BEGIN PGP MESSAGE-----                                     +
   |                                                                 +
   | wYwDy31dohr4uGABA/0RIrpFe7RRH/+C1oaSJ5StdiIUat3mQQSsRh4nhKLfooXS+
   | sw4CGLVLr0fRiDCZekpc8JM0Pc+BRHLD3TrpZMsshZ/6DUVSKCdhY1QoOeIgP7dL+
   | E/EZjwcqvUcykMn0FW7xF0sQ+0TaGlD9Ipv1aXqvFHpzDFQ/vQ4/mLtI/GDt39JA+
   | AWruc9q6evVdyse3UNwCpoMIXHrvu3a+ciW1/nnKZ1S2sviRGW0Avngw+ZNtA92N+
   | L4QuT3exwl02sOhKVNxSIw==                                        +
   | =iMKY                                                           +
   | -----END PGP MESSAGE-----                                       +
   | 
(1 row)

```

Postgres log while reproducing `INSERT` with typmod:
```
2025-11-12 21:26:37.876 CST [158025] DEBUG:  CREATE TABLE will create implicit sequence "testab_a_seq" for serial column "testab.a"
2025-11-12 21:26:37.877 CST [158025] DEBUG:  TYPMOD_IN at character 44
2025-11-12 21:26:37.877 CST [158025] DEBUG:  typmod_in(2) at character 44
2025-11-12 21:26:37.879 CST [158025] DEBUG:  TYPMOD_IN
2025-11-12 21:26:37.879 CST [158025] DEBUG:  typmod_in(2)
2025-11-12 21:26:53.377 CST [158008] DEBUG:  snapshot of 1+0 running transaction ids (lsn 0/199D6B0 oldest xid 613 latest complete 612 next xid 614)
2025-11-12 21:26:54.188 CST [158011] DEBUG:  received inquiry for database 0
2025-11-12 21:26:54.188 CST [158011] DEBUG:  writing stats file "pg_stat_tmp/global.stat"
2025-11-12 21:26:54.188 CST [158011] DEBUG:  writing stats file "pg_stat_tmp/db_0.stat"
2025-11-12 21:26:54.205 CST [163755] DEBUG:  autovacuum: processing database "template1"
2025-11-12 21:26:54.205 CST [158011] DEBUG:  received inquiry for database 1
2025-11-12 21:26:54.205 CST [158011] DEBUG:  writing stats file "pg_stat_tmp/global.stat"
2025-11-12 21:26:54.205 CST [158011] DEBUG:  writing stats file "pg_stat_tmp/db_1.stat"
2025-11-12 21:26:54.205 CST [158011] DEBUG:  writing stats file "pg_stat_tmp/db_0.stat"
2025-11-12 21:26:54.218 CST [157999] DEBUG:  server process (PID 163755) exited with exit code 0
2025-11-12 21:26:59.103 CST [158025] DEBUG:  Unmatched: my first record at character 32
2025-11-12 21:26:59.104 CST [158025] DEBUG:  Unknown typmod: -1 at character 32
2025-11-12 21:26:59.104 CST [158025] DEBUG:  IntoDatum value:
	PLAINMSG00000000
	my first record at character 32
2025-11-12 21:26:59.104 CST [158025] DEBUG:  Unmatched: my first record at character 32
2025-11-12 21:26:59.104 CST [158025] DEBUG:  Unknown typmod: -1 at character 32
2025-11-12 21:26:59.104 CST [158025] DEBUG:  IntoDatum value:
	PLAINMSG00000000
	my first record at character 32
2025-11-12 21:26:59.105 CST [158025] DEBUG:  FromDatum value:
	PLAINMSG00000000
	my first record
2025-11-12 21:26:59.105 CST [158025] DEBUG:  Plain payload: my first record
2025-11-12 21:26:59.105 CST [158025] DEBUG:  CAST(Enigma AS Enigma): ARGUMENTS: explicit: false,  Typmod: 2
2025-11-12 21:26:59.105 CST [158025] DEBUG:  Encrypting plain message with key ID: 2
2025-11-12 21:26:59.113 CST [158025] DEBUG:  IntoDatum value:
	ENIGMAv100000002
	-----BEGIN PGP MESSAGE-----
	
	wYwDy31dohr4uGABA/0RIrpFe7RRH/+C1oaSJ5StdiIUat3mQQSsRh4nhKLfooXS
	sw4CGLVLr0fRiDCZekpc8JM0Pc+BRHLD3TrpZMsshZ/6DUVSKCdhY1QoOeIgP7dL
	E/EZjwcqvUcykMn0FW7xF0sQ+0TaGlD9Ipv1aXqvFHpzDFQ/vQ4/mLtI/GDt39JA
	AWruc9q6evVdyse3UNwCpoMIXHrvu3a+ciW1/nnKZ1S2sviRGW0Avngw+ZNtA92N
	L4QuT3exwl02sOhKVNxSIw==
	=iMKY
	-----END PGP MESSAGE-----
	
2025-11-12 21:27:05.484 CST [158025] DEBUG:  FromDatum value:
	ENIGMAv100000002
	-----BEGIN PGP MESSAGE-----
	
	wYwDy31dohr4uGABA/0RIrpFe7RRH/+C1oaSJ5StdiIUat3mQQSsRh4nhKLfooXS
	sw4CGLVLr0fRiDCZekpc8JM0Pc+BRHLD3TrpZMsshZ/6DUVSKCdhY1QoOeIgP7dL
	E/EZjwcqvUcykMn0FW7xF0sQ+0TaGlD9Ipv1aXqvFHpzDFQ/vQ4/mLtI/GDt39JA
	AWruc9q6evVdyse3UNwCpoMIXHrvu3a+ciW1/nnKZ1S2sviRGW0Avngw+ZNtA92N
	L4QuT3exwl02sOhKVNxSIw==
	=iMKY
	-----END PGP MESSAGE-----
	
2025-11-12 21:27:05.484 CST [158025] DEBUG:  PGP encrypted message
2025-11-12 21:27:05.484 CST [158025] DEBUG:  Decrypt: Message key_id: 2
2025-11-12 21:27:05.484 CST [158025] DEBUG:  Decrypt: Message key_id: 2
```
