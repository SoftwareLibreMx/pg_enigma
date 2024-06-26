use pgrx::prelude::*;
use serde::{Serialize, Deserialize};
use pgrx::{StringInfo};
use core::ffi::CStr;
use pgp::{SignedSecretKey, Deserializable};
use pgp::SignedPublicKey;
use pgp::composed::message::Message;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use rand::prelude::*;
use std::collections::BTreeMap;
use std::io::Cursor;
use std::fs;

::pgrx::pg_module_magic!();

//TODO: temporal key for testing

/* Esta ya se puede borrar
static PRV_KEY: Option<&str> =Some("-----BEGIN PGP PRIVATE KEY BLOCK-----

lQIGBGZXG+YBBACpVTBmm+44K5G0g5qtc53jdIckb4FS8N0kiDp4iiC4iST0Ck2D
yxNIPhmIfs18wkaktEFnTqe9NN4v3jiW0TSwlZZF+Kv9Ubl3w6GObuUZbEhF3+qf
myerbWCObAOYd+suwPZu3zwil8HEl1jp+/zon0Aci1kUU9t18EXMjvs8wwARAQAB
/gcDAjp9hSW76Ju57+QsI7mCJlXJB3BOdXmZy0KqP7lQLbZD+LDAI0OX+K3SjLS0
+bAd4gZ41Nqy+Qwvx4a4eDlex9ybVKIeCum0PYBf7AFiEuaz9to+hEvwwcEpigvy
lQr8Y8wM1OitDgBpDmq6dIx7a3umyWkpy9uAPJ45XNnUmxH/nYAn44KGKPRK7YX4
uUhMDann4+NUCsz6BpmLyBaiAuLgzwYW5THUF9vziX99oBhc6D4XJIuKOQTho+11
Bn5eLtYCfQeyxrnLiXPxFuhVb7LbBFPcmpfF6wXVzxgTou2BPY9VLlv529jF6LXo
YctO7FKEedTKpkMgflDbRHFaf8nMX/1qQ7D+J1B/U0NEQLmcFlWXH093gToNok3Y
qPzBNjsUOYhPuuG0as+oQoFlB/KeNpWpoTP0CByY+Kd1pNDTSzKbdEnnKJdc5lzl
Bfo8mzKHsE6VDKPneoTJR3Z1kgbyonHGgJNbiYBoOpVg21PiD0utNES0EnBnX2Vu
aWdtYSB0ZXN0IGtleYjUBBMBCAA+FiEEGAGYSm//v0++hluiy31dohr4uGAFAmZX
G+YCGwMFCQAJOoAFCwkIBwMFFQoJCAsFFgIDAQACHgUCF4AACgkQy31dohr4uGAc
lAQAoAeB/WTnIrWLLLq/izcJGmzlyguReIk3pR93HJcB4CzLOljyrNG/QE7UezN7
bfLp9vqX35LxYhVR22ioROz0jEJM6f23Js1Mt9Nq9GiDxq7dBz4SFiRlPKXnXfOV
GgmmIyMaZ8+GHjYIbSNvDrwB19ojYGI9RcjuotKUj6m72+udAgYEZlcb5gEEAOEp
boygSI/89mU8nBtN6KkX73cpYxAUp6BIwtUFlr213Fy2WwMFclBY9a+6myRfE9jH
z1nt7dlwve+ET1TP7hIE1kWugouEP17VHlWGL6g3V8VuK+lENjlynuFD92M+XDHh
XNuieiGgcjjHyQu4sDZtIolIRlcOlhOBXHwGG3A7ABEBAAH+BwMCEusNDruJ36zv
Ae/VgEtRk/RQrYRekmHt0OAg6XmtAHwlbrgtMZ6D7vsZNLTKZNl+2HTnnpc3eSAY
aA874xm7Z7NiTr7nsc5sIhs8WL0Ub4jI1P20YaDjUHbqMnqzJ01B39bg6ujrCnHz
0aLhfcSgLhAKHfSwGmkV7WnWkDxu4sHe6N9B3H7x+b/oKrxUvmrPboppfwU5avvt
CpeIHdD91sZFTIf1BJNto4y6A3SRxEKKAMLXvYotP5Y1KCjS8LUxYCuia/vXe1jX
2t+h7s1Y+X6Q9LofssZLV/B2LywvqbvnHNygis9bZo+jgdnRZm/JUatBHAL1QZc0
VGaqr3QSLsPOPCTLe1micYWmxS3EX/F4wQB6Vadh+scjJzTPfeR6H1sHHW4JFlG0
fVUxKvdVdG4VI+5jwux8/RZKQEX/+Q2yrWt/wQA97PuiE2u0jyRVrWP/S0IDdSKE
AaYbDeM6UuUxi5AUEKYk4H6Gd3m/e6yVEItOv4i8BBgBCAAmFiEEGAGYSm//v0++
hluiy31dohr4uGAFAmZXG+YCGwwFCQAJOoAACgkQy31dohr4uGB/mgP9FF97K6SO
Vn77XUctBRm0FuLM/S/io8IsNlAivX2vrC7QSZoPbbVqhBPELCnPAAG+dk7y+i1w
dt/epY/+oiyprjgbfygBFet02xyKnCdAtStno8aUCu4hVNmdYcUCezr1AgXnYk2R
DdGpjenMdNnT6b0bjWcwT6cwfdmXKjzaUJs=
=DYQs
-----END PGP PRIVATE KEY BLOCK-----");

static PUB_KEY: Option<&str> = Some("-----BEGIN PGP PUBLIC KEY BLOCK-----

mI0EZlcb5gEEAKlVMGab7jgrkbSDmq1zneN0hyRvgVLw3SSIOniKILiJJPQKTYPL
E0g+GYh+zXzCRqS0QWdOp7003i/eOJbRNLCVlkX4q/1RuXfDoY5u5RlsSEXf6p+b
J6ttYI5sA5h36y7A9m7fPCKXwcSXWOn7/OifQByLWRRT23XwRcyO+zzDABEBAAG0
EnBnX2VuaWdtYSB0ZXN0IGtleYjUBBMBCAA+FiEEGAGYSm//v0++hluiy31dohr4
uGAFAmZXG+YCGwMFCQAJOoAFCwkIBwMFFQoJCAsFFgIDAQACHgUCF4AACgkQy31d
ohr4uGAclAQAoAeB/WTnIrWLLLq/izcJGmzlyguReIk3pR93HJcB4CzLOljyrNG/
QE7UezN7bfLp9vqX35LxYhVR22ioROz0jEJM6f23Js1Mt9Nq9GiDxq7dBz4SFiRl
PKXnXfOVGgmmIyMaZ8+GHjYIbSNvDrwB19ojYGI9RcjuotKUj6m72+u4jQRmVxvm
AQQA4SlujKBIj/z2ZTycG03oqRfvdyljEBSnoEjC1QWWvbXcXLZbAwVyUFj1r7qb
JF8T2MfPWe3t2XC974RPVM/uEgTWRa6Ci4Q/XtUeVYYvqDdXxW4r6UQ2OXKe4UP3
Yz5cMeFc26J6IaByOMfJC7iwNm0iiUhGVw6WE4FcfAYbcDsAEQEAAYi8BBgBCAAm
FiEEGAGYSm//v0++hluiy31dohr4uGAFAmZXG+YCGwwFCQAJOoAACgkQy31dohr4
uGB/mgP9FF97K6SOVn77XUctBRm0FuLM/S/io8IsNlAivX2vrC7QSZoPbbVqhBPE
LCnPAAG+dk7y+i1wdt/epY/+oiyprjgbfygBFet02xyKnCdAtStno8aUCu4hVNmd
YcUCezr1AgXnYk2RDdGpjenMdNnT6b0bjWcwT6cwfdmXKjzaUJs=
=jOmZ
-----END PGP PUBLIC KEY BLOCK-----");
*/

static PRIV_KEYS: BTreeMap<i32,SignedSecretKey> = BTreeMap::new();


/// Value stores entcrypted information
#[derive(Serialize, Deserialize, PostgresType)]
#[inoutfuncs]
struct Enigma {
    value: String,
}


/// Functions for extracting and inserting data
impl InOutFuncs for Enigma {
    // Get from postgres
    fn input(input: &CStr) -> Self {
        let value: String = input
                .to_str()
                .expect("Enigma::input can't convert to str")
                .to_string();
        let HARDCODED_KEY_ID = 1; // TODO: Obtener el ID del modificador
        let pub_key = get_public_key(HARDCODED_KEY_ID)
                     .expect("Error getting public key");
        let encrypted = match pub_key {
            Some(key) => {
                match encrypt(value, &key) {
                    Ok(v) => v,
                    Err(e) => panic!("Encrypt error: {}", e)
                }
            },
            None => panic!("NO KEY DEFINED")
        };

        Enigma {
            value: encrypted,
        }
    }

    // Send to postgres
    fn output(&self, buffer: &mut StringInfo) {
        let mut value: String = self.value.clone();
        let KEY_ID=1; // TODO: Deshardcodear este hardcodeado

        match get_private_key(KEY_ID) {
            Ok(Some((key, pass))) => match decrypt(value, key, pass) {
                Ok(v) => buffer.push_str(&v),
                Err(e) => panic!("Decrypt error: {}", e)
            },
            // TODO: check if we need more granular errors
            Err(e) => panic!("GET PRIVATE KEY ERROR {}", e),
            _ => buffer.push_str(&value),
        }
    }
}

/// Encrypts the value
fn decrypt(value: String, sec_key: SignedSecretKey, pass: String)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    
    //let (sec_key, _) = SignedSecretKey::from_string(key.as_str())?;
    let buf = Cursor::new(value);
    let (msg, _) = Message::from_armor_single(buf)?;
    let (decryptor, _) = msg
    .decrypt(|| pass, &[&sec_key])?;
    let mut clear_text = String::from("NOT DECRYPTED");
    for msg in decryptor {
        let bytes = msg?.get_content()?.unwrap();
        clear_text = String::from_utf8(bytes).unwrap();
    }
    Ok(clear_text)
}

/// Decrypts the value
fn encrypt(value: String, key: &str)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    let (pub_key, _) = SignedPublicKey::from_string(key)?;
    let msg = Message::new_literal("none", value.as_str());
    let mut rng = StdRng::from_entropy();
    let new_msg = msg.encrypt_to_keys(
        &mut rng, SymmetricKeyAlgorithm::AES128, &[&pub_key])?;
    let ret = new_msg.to_armored_string(None)?;
    Ok(ret)
}


/// TODO: add docs
#[pg_extern]
fn set_private_key(id: i32, key: &str, pass: &str)
-> Result<Option<String>, spi::Error> {
    //let (sec_key, _) = SignedSecretKey::from_string(key)?;
    //sec_key.verify()?;
    create_key_table()?;
    Spi::get_one_with_args(
        r#"INSERT INTO temp_keys(id, private_key, pass)
           VALUES ($1, $2, $3)
           ON CONFLICT(id)
           DO UPDATE SET private_key=$2, pass=$3
           RETURNING 'Private key set'"#,
        vec![
            (PgBuiltInOids::INT4OID.oid(), id.into_datum()),
            (PgBuiltInOids::TEXTOID.oid(), key.into_datum()),
            (PgBuiltInOids::TEXTOID.oid(), pass.into_datum())
        ],
    )
}


/// TODO: add docs
#[pg_extern]
fn set_public_key(id: i32, key: &str)
-> Result<Option<String>, spi::Error> {
    create_key_table()?;
    Spi::get_one_with_args(
        r#"INSERT INTO temp_keys(id, public_key)
           VALUES ($1, $2)
           ON CONFLICT(id)
           DO UPDATE SET public_key=$2
           RETURNING 'Public key set'"#,
        vec![
            (PgBuiltInOids::INT4OID.oid(), id.into_datum()),
            (PgBuiltInOids::TEXTOID.oid(), key.into_datum())
        ],
    )
}

/// Get the private key from memory
fn get_private_key(id: i32)
-> Result<Option<(SignedSecretKey,String)>, Box<(dyn std::error::Error + 'static)>> {
    match PRIV_KEYS.get(&id) {
        Some(k) => {
            let pass = match get_private_key_pass(id)? {
                Some(p) => p,
                None => String::from("")
            };
            Ok(Some((k.clone(),pass)))
        },
        None => {
            let (armored, pass) = get_armored_private_key(id)?;
            match armored {
                Some(a) => {
                    let (key, _) = 
                        SignedSecretKey::from_string(a.as_str())?;
                    match pass {
                        Some(p) => {
                            Ok(Some((key,p)))
                        },
                        None => {
                            Ok(Some((key,String::from(""))))
                        }
                    }
                },
                None => Ok(None)
            }   
        }
    }
}

/// Get the armored private key and password from the keys table
fn get_armored_private_key(id: i32)
-> Result<(Option<String>,Option<String>), pgrx::spi::Error> {
    if ! exists_key_table()? { return Ok((None,None)); }
    let query = "SELECT private_key, pass FROM temp_keys WHERE id = $1";
    let args = vec![ (PgBuiltInOids::INT4OID.oid(), id.into_datum()) ];
    Spi::connect(|mut client| {
        let tuple_table = client.update(query, Some(1), Some(args))?;
        if tuple_table.len() == 0 {
            Ok((None, None))
        } else {
            tuple_table.first().get_two::<String, String>()
        }
    })
}

/// Get the private key password from the keys table
fn get_private_key_pass(id: i32)
-> Result<Option<String>, pgrx::spi::Error> {
    if ! exists_key_table()? { return Ok(None); }
    let query = "SELECT pass FROM temp_keys WHERE id = $1";
    let args = vec![ (PgBuiltInOids::INT4OID.oid(), id.into_datum()) ];
    Spi::connect(|mut client| {
        let tuple_table = client.update(query, Some(1), Some(args))?;
        if tuple_table.len() == 0 {
            Ok(None)
        } else {
            tuple_table.first().get_one::<String>()
        }
    })
}

/// Get the public key from the keys table
fn get_public_key(id: i32) -> Result<Option<String>, pgrx::spi::Error> {
    if ! exists_key_table()? { return Ok(None); }
    let query = "SELECT public_key FROM temp_keys WHERE id = $1";
    let args = vec![ (PgBuiltInOids::INT4OID.oid(), id.into_datum()) ];
    Spi::connect(|mut client| {
        let tuple_table = client.update(query, Some(1), Some(args))?;
        if tuple_table.len() == 0 {
            Ok(None)
        } else {
            tuple_table.first().get_one::<String>()
        }
    })

}

#[pg_extern]
fn create_key_table() -> Result<(), spi::Error> {
    Spi::run(
        "CREATE TEMPORARY TABLE IF NOT EXISTS temp_keys (
            id INT PRIMARY KEY,
            private_key TEXT,
            public_key TEXT,
            pass TEXT
         )"
    )
}

#[pg_extern]
// TODO: return bool
fn exists_key_table() -> Result<bool, spi::Error> {
    if let Some(e) = Spi::get_one("SELECT EXISTS (
        SELECT tablename
        FROM pg_catalog.pg_tables WHERE tablename = 'temp_keys'
        )")? {
        return Ok(e);
    }
    Ok(false)
}


/// Sets the private key from a file
#[pg_extern]
fn set_private_key_from_file(id: i32, file_path: &str, pass: &str)
-> Result<String, spi::Error> {
    let contents = fs::read_to_string(file_path)
    .expect("Error reading private key file");
    set_private_key(id, &contents, pass)?;
    Ok(format!("{}\nPrivate key succesfully added", contents))
}

/// Sets the public key from a file
#[pg_extern]
fn set_public_key_from_file(id: i32, file_path: &str)
-> Result<String, spi::Error> {
    let contents = fs::read_to_string(file_path)
        .expect("Error reading public file");
    set_public_key(id, &contents)?;
    Ok(format!("{}\nPublic key succesfully added", contents))
}



#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use pgrx::prelude::*;

    #[pg_test]
    fn test_hello_pg_enigma() {
        assert_eq!("Hello, pg_enigma", crate::hello_pg_enigma());
    }

}

/// This module is required by `cargo pgrx test` invocations.
/// It must be visible at the root of your extension crate.
#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {
        // perform one-off initialization when the pg_test framework starts
    }

    pub fn postgresql_conf_options() -> Vec<&'static str> {
        // return any postgresql.conf settings that are required for your tests
        vec![]
    }
}
