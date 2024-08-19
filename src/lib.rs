mod functions;
mod key_map;
mod priv_key;
mod pub_key;

use core::ffi::CStr;
use crate::key_map::{PrivKeysMap};
use lazy_static::lazy_static;
use once_cell::sync::Lazy;
use openssl::base64::{encode_block};
use openssl::encrypt::{Encrypter};
use openssl::pkey::{PKey, Public};
use openssl::rsa::Padding;
use pgp::composed::message::Message;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::{SignedPublicKey,  Deserializable};
use pgrx::prelude::*;
use pgrx::{StringInfo};
use rand::prelude::*;
use regex::Regex;
use serde::{Serialize, Deserialize};
use std::fs;

pgrx::pg_module_magic!();

static PRIV_KEYS: Lazy<PrivKeysMap> = Lazy::new(|| PrivKeysMap::new());



/// Value stores entcrypted information
#[derive(Serialize, Deserialize, Debug, PostgresType)]
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

        match PRIV_KEYS.decrypt(KEY_ID, &value) {
            Ok(Some(v)) => buffer.push_str(&v),
            // TODO: check if we need more granular errors
            Err(e) =>  panic!("Decrypt error: {}", e),
            _ => buffer.push_str(&value),
        }
    }
}


/// Decrypts the value
fn encrypt(value: String, key: &str)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    lazy_static! {
        static ref RE_PGP: Regex = Regex::new(r"BEGIN PGP PUBLIC KEY BLOCK")
            .expect("failed to compile PGP key regex");
        static ref RE_RSA: Regex = Regex::new(r"BEGIN PUBLIC KEY")
            .expect("failed to compile OpenSSL RSA key regex");
    }
    let ret;
    if RE_PGP.captures(&key).is_some() {
        let (pub_key, _) = SignedPublicKey::from_string(key)?;
        let msg = Message::new_literal("none", value.as_str());
        let mut rng = StdRng::from_entropy();
        let new_msg = msg.encrypt_to_keys(
            &mut rng, SymmetricKeyAlgorithm::AES128, &[&pub_key])?;
        ret = new_msg.to_armored_string(None)?;
    } else if RE_RSA.captures(&key).is_some() {
        let pub_key = PKey::<Public>::public_key_from_pem(key.as_bytes())?;
        let mut encrypter = Encrypter::new(&pub_key)?;
        encrypter.set_rsa_padding(Padding::PKCS1)?;
        // Get the length of the output buffer
        let buffer_len = encrypter.encrypt_len(&value.as_bytes())?;
        let mut encoded = vec![0u8; buffer_len];
        // Encode the data and get its length
        let encoded_len = encrypter.encrypt(&value.as_bytes(), 
            &mut encoded)?;
        // Use only the part of the buffer with the encoded data
        let encoded = &encoded[..encoded_len];
        ret = encode_block(encoded);
    } else {
        return Err("key type not supported".into());
    }
    Ok(ret)
}


/// TODO: add docs
#[pg_extern]
fn set_private_key(id: i32, key: &str, pass: &str)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    PRIV_KEYS.set(id, key, pass)
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

/// Delete the private key from memory
#[pg_extern]
fn forget_private_key(id: i32)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    PRIV_KEYS.del(id)
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
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    let contents = fs::read_to_string(file_path)
    .expect("Error reading private key file");
    set_private_key(id, &contents, pass)
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
    fn dummy_test() {
        assert_eq!("Hello, pg_enigma", "Hello, pg_enigma");
    }

    // TODO: (set|get)_(private|public)_key()
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
