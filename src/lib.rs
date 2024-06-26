use pgrx::prelude::*;
use serde::{Serialize, Deserialize};
use pgrx::{StringInfo};
use core::ffi::CStr;
use pgp::{SignedSecretKey, Deserializable};
use pgp::SignedPublicKey;
use pgp::composed::message::Message;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use rand::prelude::*;
use std::io::Cursor;
use std::fs;

pgrx::pg_module_magic!();


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
        let value: String = self.value.clone();
        let KEY_ID=1; // TODO: Deshardcodear este hardcodeado

        match get_private_key(KEY_ID) {
            Ok((Some(key), Some(pass))) => match decrypt(value, key, pass) {
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
fn decrypt(value: String, key: String, pass: String)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    let (sec_key, _) = SignedSecretKey::from_string(key.as_str())?;
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

/// Get the private key from the keys table
fn get_private_key(id: i32)
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
