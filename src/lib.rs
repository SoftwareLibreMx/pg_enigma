mod functions;
mod key_map;
mod priv_key;
mod pub_key;

use core::ffi::CStr;
use crate::functions::*;
use crate::key_map::{PrivKeysMap,PubKeysMap};
use once_cell::sync::Lazy;
use pgrx::prelude::*;
use pgrx::{StringInfo};
use serde::{Serialize, Deserialize};
use std::fs;

pgrx::pg_module_magic!();

static PRIV_KEYS: Lazy<PrivKeysMap> = Lazy::new(|| PrivKeysMap::new());
static PUB_KEYS: Lazy<PubKeysMap> = Lazy::new(|| PubKeysMap::new());



/// Value stores entcrypted information
#[derive(Serialize, Deserialize, Debug, PostgresType)]
#[typmod_inoutfuncs]
struct Enigma {
    value: String,
}


/// Functions for extracting and inserting data
impl TypmodInOutFuncs for Enigma {
    // Get from postgres
    fn input(input: &CStr, oid: Option<i32>, typmod: Option<i32>) -> Self {
        let value: String = input
                .to_str()
                .expect("Enigma::input can't convert to str")
                .to_string();
        let HARDCODED_KEY_ID = 1; // TODO: Obtener el ID del modificador
        let pub_key = match PUB_KEYS.get(HARDCODED_KEY_ID)
                .expect("Get from key map") {
            Some(k) => k,
            None => {
                let key = match get_public_key(HARDCODED_KEY_ID)
                    .expect("Get public key from SQL") {
                    Some(k) => k,
                    None => panic!("No public key with id: {}", 
                        HARDCODED_KEY_ID)
                };
                PUB_KEYS.set(HARDCODED_KEY_ID, &key)
                    .expect("Set into key map");
                PUB_KEYS.get(HARDCODED_KEY_ID)
                    .expect("Get (just set) from key map").unwrap()
            }
        };

        Enigma {
            value: pub_key.encrypt(&value).expect("Encrypt"),
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



/// TODO: add docs
#[pg_extern]
fn set_private_key(id: i32, key: &str, pass: &str)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    PRIV_KEYS.set(id, key, pass)
}   


/// TODO: add docs
#[pg_extern]
fn set_public_key(id: i32, key: &str)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    match insert_public_key(id, key)? {
        Some(_) => PUB_KEYS.set(id, key),
        None => Err(format!("No key ({}) inserted", id).into())
    }
}

/// Delete the private key from memory
#[pg_extern]
fn forget_private_key(id: i32)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    PRIV_KEYS.del(id)
}

/// Delete the public key from memory
#[pg_extern]
fn forget_public_key(id: i32)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    PUB_KEYS.del(id)
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
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    let contents = fs::read_to_string(file_path)
        .expect("Error reading public file");
    set_public_key(id, &contents)
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
