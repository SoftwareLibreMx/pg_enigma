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
 a |        b        
---+-----------------
 1 | my first record
(1 row)

```

Postgres log showing plain message inert on `0.4.0`:
```
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

### `COPY FROM` sets the correct typmod on `INPUT` function 

```
.pgrx/13.21/pgrx-install/bin/psql -p 28813 -h localhost -f pg_enigma-2025-11-12.dump pg_enigma 
SET
SET
SET
SET
SET
 set_config 
------------
 
(1 row)

SET
SET
SET
SET
CREATE EXTENSION
COMMENT
SET
SET
CREATE TABLE
ALTER TABLE
CREATE SEQUENCE
ALTER TABLE
ALTER SEQUENCE
ALTER TABLE
psql:pg_enigma-2025-11-12.dump:85: INFO:  Already encrypted with key ID 2
psql:pg_enigma-2025-11-12.dump:85: INFO:  Already encrypted with key ID 2
COPY 2
 setval 
--------
      2
(1 row)
```

Postgres log when using `COPY FROM`:
```
2025-11-12 21:54:29.098 CST [167410] DEBUG:  INPUT: ARGUMENTS: Input: "ENIGMAv100000002\n-----BEGIN PGP MESSAGE-----\n\nwYwDy31dohr4uGABA/0RIrpFe7RRH/+C1oaSJ5StdiIUat3mQQSsRh4nhKLfooXS\nsw4CGLVLr0fRiDCZekpc8JM0Pc+BRHLD3TrpZMsshZ/6DUVSKCdhY1QoOeIgP7dL\nE/EZjwcqvUcykMn0FW7xF0sQ+0TaGlD9Ipv1aXqvFHpzDFQ/vQ4/mLtI/GDt39JA\nAWruc9q6evVdyse3UNwCpoMIXHrvu3a+ciW1/nnKZ1S2sviRGW0Avngw+ZNtA92N\nL4QuT3exwl02sOhKVNxSIw==\n=iMKY\n-----END PGP MESSAGE-----\n", OID: 33225,  Typmod: 2
2025-11-12 21:54:29.098 CST [167410] CONTEXT:  COPY testab, line 1, column b: "ENIGMAv100000002
	-----BEGIN PGP MESSAGE-----
	
	wYwDy31dohr4uGABA/0RIrpFe7RRH/+C1oaSJ5StdiIUat3mQQSsRh..."
2025-11-12 21:54:29.098 CST [167410] DEBUG:  PGP encrypted message
2025-11-12 21:54:29.098 CST [167410] CONTEXT:  COPY testab, line 1, column b: "ENIGMAv100000002
	-----BEGIN PGP MESSAGE-----
	
	wYwDy31dohr4uGABA/0RIrpFe7RRH/+C1oaSJ5StdiIUat3mQQSsRh..."
2025-11-12 21:54:29.098 CST [167410] INFO:  Already encrypted with key ID 2
2025-11-12 21:54:29.098 CST [167410] CONTEXT:  COPY testab, line 1, column b: "ENIGMAv100000002
	-----BEGIN PGP MESSAGE-----
	
	wYwDy31dohr4uGABA/0RIrpFe7RRH/+C1oaSJ5StdiIUat3mQQSsRh..."
2025-11-12 21:54:29.098 CST [167410] DEBUG:  IntoDatum value:
	ENIGMAv100000002
	-----BEGIN PGP MESSAGE-----
	
	wYwDy31dohr4uGABA/0RIrpFe7RRH/+C1oaSJ5StdiIUat3mQQSsRh4nhKLfooXS
	sw4CGLVLr0fRiDCZekpc8JM0Pc+BRHLD3TrpZMsshZ/6DUVSKCdhY1QoOeIgP7dL
	E/EZjwcqvUcykMn0FW7xF0sQ+0TaGlD9Ipv1aXqvFHpzDFQ/vQ4/mLtI/GDt39JA
	AWruc9q6evVdyse3UNwCpoMIXHrvu3a+ciW1/nnKZ1S2sviRGW0Avngw+ZNtA92N
	L4QuT3exwl02sOhKVNxSIw==
	=iMKY
	-----END PGP MESSAGE-----
	
2025-11-12 21:54:29.098 CST [167410] CONTEXT:  COPY testab, line 1, column b: "ENIGMAv100000002
	-----BEGIN PGP MESSAGE-----
	
	wYwDy31dohr4uGABA/0RIrpFe7RRH/+C1oaSJ5StdiIUat3mQQSsRh..."
2025-11-12 21:54:29.098 CST [167410] DEBUG:  INPUT: ARGUMENTS: Input: "ENIGMAv100000002\n-----BEGIN PGP MESSAGE-----\n\nwYwDy31dohr4uGABA/0RIrpFe7RRH/+C1oaSJ5StdiIUat3mQQSsRh4nhKLfooXS\nsw4CGLVLr0fRiDCZekpc8JM0Pc+BRHLD3TrpZMsshZ/6DUVSKCdhY1QoOeIgP7dL\nE/EZjwcqvUcykMn0FW7xF0sQ+0TaGlD9Ipv1aXqvFHpzDFQ/vQ4/mLtI/GDt39JA\nAWruc9q6evVdyse3UNwCpoMIXHrvu3a+ciW1/nnKZ1S2sviRGW0Avngw+ZNtA92N\nL4QuT3exwl02sOhKVNxSIw==\n=iMKY\n-----END PGP MESSAGE-----\n", OID: 33225,  Typmod: 2
2025-11-12 21:54:29.098 CST [167410] CONTEXT:  COPY testab, line 2, column b: "ENIGMAv100000002
	-----BEGIN PGP MESSAGE-----
	
	wYwDy31dohr4uGABA/0RIrpFe7RRH/+C1oaSJ5StdiIUat3mQQSsRh..."
2025-11-12 21:54:29.098 CST [167410] DEBUG:  PGP encrypted message
2025-11-12 21:54:29.098 CST [167410] CONTEXT:  COPY testab, line 2, column b: "ENIGMAv100000002
	-----BEGIN PGP MESSAGE-----
	
	wYwDy31dohr4uGABA/0RIrpFe7RRH/+C1oaSJ5StdiIUat3mQQSsRh..."
2025-11-12 21:54:29.098 CST [167410] INFO:  Already encrypted with key ID 2
2025-11-12 21:54:29.098 CST [167410] CONTEXT:  COPY testab, line 2, column b: "ENIGMAv100000002
	-----BEGIN PGP MESSAGE-----
	
	wYwDy31dohr4uGABA/0RIrpFe7RRH/+C1oaSJ5StdiIUat3mQQSsRh..."
2025-11-12 21:54:29.099 CST [167410] DEBUG:  IntoDatum value:
	ENIGMAv100000002
	-----BEGIN PGP MESSAGE-----
	
	wYwDy31dohr4uGABA/0RIrpFe7RRH/+C1oaSJ5StdiIUat3mQQSsRh4nhKLfooXS
	sw4CGLVLr0fRiDCZekpc8JM0Pc+BRHLD3TrpZMsshZ/6DUVSKCdhY1QoOeIgP7dL
	E/EZjwcqvUcykMn0FW7xF0sQ+0TaGlD9Ipv1aXqvFHpzDFQ/vQ4/mLtI/GDt39JA
	AWruc9q6evVdyse3UNwCpoMIXHrvu3a+ciW1/nnKZ1S2sviRGW0Avngw+ZNtA92N
	L4QuT3exwl02sOhKVNxSIw==
	=iMKY
	-----END PGP MESSAGE-----
	
2025-11-12 21:54:29.099 CST [167410] CONTEXT:  COPY testab, line 2, column b: "ENIGMAv100000002
	-----BEGIN PGP MESSAGE-----
	
	wYwDy31dohr4uGABA/0RIrpFe7RRH/+C1oaSJ5StdiIUat3mQQSsRh..."
```

### `ASSIGNMENT` cast uses the correct typmod

```sql
pg_enigma=# INSERT INTO testab (b) VALUES ('my first record'::Text);
INSERT 0 1
pg_enigma=# SELECT * FROM testab;
 a |                                b                                 
---+------------------------------------------------------------------
 1 | ENIGMAv100000002                                                +
   | -----BEGIN PGP MESSAGE-----                                     +
   |                                                                 +
   | wYwDy31dohr4uGABBACQTSOwT67dvOBeyXISF8UGlEYGn0tvYQDZSvnkYY3ppS7/+
   | Ozroxm5AJSsaJ3QRPR7Og4qOnMYmjmoyoqUnd0cD0Us2Rx1BLddJYbacghU04lU2+
   | rDJR/ukmiUsjA4X5FpoFCpPukRwTLZmLJ8YtSpQfvPSkk7Nr0O9PipC2ugYzktJA+
   | AQdN+JumV4BLaVzB/Xhn1ecMFlaEMOUJO113BqKM3Blyo9mDGTdiJDlfzbrJyaoJ+
   | gTTxh5TwMTAR59IN7h030g==                                        +
   | =/V4j                                                           +
   | -----END PGP MESSAGE-----                                       +
   | 
(1 row)
```

Postgres log when using `ASSIGNMENT` cast:
```
2025-11-12 22:49:25.254 CST [167388] DEBUG:  string_as_enigma: ARGUMENTS: explicit: false,  Typmod: 2
2025-11-12 22:49:25.254 CST [167388] DEBUG:  Unmatched: my first record
2025-11-12 22:49:25.254 CST [167388] DEBUG:  RNG seed: 1e60fe7c69156355 ones: 33 zeros: 31
2025-11-12 22:49:25.261 CST [167388] DEBUG:  IntoDatum value:
	ENIGMAv100000002
	-----BEGIN PGP MESSAGE-----
	
	wYwDy31dohr4uGABBACQTSOwT67dvOBeyXISF8UGlEYGn0tvYQDZSvnkYY3ppS7/
	Ozroxm5AJSsaJ3QRPR7Og4qOnMYmjmoyoqUnd0cD0Us2Rx1BLddJYbacghU04lU2
	rDJR/ukmiUsjA4X5FpoFCpPukRwTLZmLJ8YtSpQfvPSkk7Nr0O9PipC2ugYzktJA
	AQdN+JumV4BLaVzB/Xhn1ecMFlaEMOUJO113BqKM3Blyo9mDGTdiJDlfzbrJyaoJ
	gTTxh5TwMTAR59IN7h030g==
	=/V4j
	-----END PGP MESSAGE-----
	
2025-11-12 22:49:25.261 CST [167388] DEBUG:  CommitTransaction(1) name: unnamed; blockState: STARTED; state: INPROGRESS, xid/subid/cid: 656/1/0 (used)
2025-11-12 22:49:29.820 CST [167388] DEBUG:  StartTransaction(1) name: unnamed; blockState: DEFAULT; state: INPROGRESS, xid/subid/cid: 0/1/0
2025-11-12 22:49:29.821 CST [167388] DEBUG:  FromDatum value:
	ENIGMAv100000002
	-----BEGIN PGP MESSAGE-----
	
	wYwDy31dohr4uGABBACQTSOwT67dvOBeyXISF8UGlEYGn0tvYQDZSvnkYY3ppS7/
	Ozroxm5AJSsaJ3QRPR7Og4qOnMYmjmoyoqUnd0cD0Us2Rx1BLddJYbacghU04lU2
	rDJR/ukmiUsjA4X5FpoFCpPukRwTLZmLJ8YtSpQfvPSkk7Nr0O9PipC2ugYzktJA
	AQdN+JumV4BLaVzB/Xhn1ecMFlaEMOUJO113BqKM3Blyo9mDGTdiJDlfzbrJyaoJ
	gTTxh5TwMTAR59IN7h030g==
	=/V4j
	-----END PGP MESSAGE-----
	
2025-11-12 22:49:29.821 CST [167388] DEBUG:  PGP encrypted message
2025-11-12 22:49:29.821 CST [167388] DEBUG:  Decrypt: Message key_id: 2
2025-11-12 22:49:29.821 CST [167388] DEBUG:  OUTPUT: ENIGMAv100000002
	-----BEGIN PGP MESSAGE-----
	
	wYwDy31dohr4uGABBACQTSOwT67dvOBeyXISF8UGlEYGn0tvYQDZSvnkYY3ppS7/
	Ozroxm5AJSsaJ3QRPR7Og4qOnMYmjmoyoqUnd0cD0Us2Rx1BLddJYbacghU04lU2
	rDJR/ukmiUsjA4X5FpoFCpPukRwTLZmLJ8YtSpQfvPSkk7Nr0O9PipC2ugYzktJA
	AQdN+JumV4BLaVzB/Xhn1ecMFlaEMOUJO113BqKM3Blyo9mDGTdiJDlfzbrJyaoJ
	gTTxh5TwMTAR59IN7h030g==
	=/V4j
	-----END PGP MESSAGE-----
	
2025-11-12 22:49:29.821 CST [167388] DEBUG:  Decrypt: Message key_id: 2
```
