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
use pgrx::ffi::CString;
use pgrx::pg_sys::Oid;
use serde::{Serialize, Deserialize};
use std::fs;
use pgrx_macros::extension_sql;

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
    fn input(input: &CStr, _oid: Oid, typmod: i32) -> Self {
        if typmod < 0 {
            panic!("Unknown typmod: {}\ninput:{:?}\noid: {:?}", 
                typmod, input, _oid);
        }
        let value: String = input
                .to_str()
                .expect("Enigma::input can't convert to str")
                .to_string();
        // let HARDCODED_KEY_ID = 1; // TODO: Obtener el ID del modificador
        let mut key_id = typmod;
        //if key_id < 0 {key_id = 0}
        let pub_key = match PUB_KEYS.get(key_id)
                .expect("Get from key map") {
            Some(k) => k,
            None => {
                let key = match get_public_key(key_id)
                    .expect("Get public key from SQL") {
                    Some(k) => k,
                    None => panic!("No public key with id: {}", 
                        key_id)
                };
                PUB_KEYS.set(key_id, &key)
                    .expect("Set into key map");
                PUB_KEYS.get(key_id)
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

    // convert typmod from cstring to i32
    fn typmod_in(input: Array<&CStr>) -> i32 {
        if input.len() != 1 {
            panic!("Enigma type modifier must be a single integer value");
        }
        // TODO: handle unwrap errors ellegantly using expect()
        input.iter() // iterator
        .next() // Option<Item>
        .unwrap() // Item
        .unwrap() // &Cstr
        .to_str() // Option<&Str>
        .unwrap() // &$tr
        .parse::<i32>() // Result<i32>
        .unwrap() // i32
    }
}
    

#[::pgrx::pgrx_macros::pg_extern(immutable,parallel_safe)]
fn type_enigma_out(typmod: i32) -> CString {
    log!("Typmodout: {}", typmod);
    let output = format!(" Key pair index: {}", typmod);
    CString::new(output.as_bytes())
        .expect("Can't convert typmod to CString!!")
}


/*
extension_sql!(
    r#"
    ALTER TYPE Enigma  SET (TYPMOD_IN = 'type_enigma_in', TYPMOD_OUT='type_enigma_out');
    "#,
    name = "type_enigma",
    finalize,
);
*/

/*
extension_sql!(
    r#"
    ALTER TYPE Enigma  SET (TYPMOD_IN = 'type_enigma_in');
    "#,
    name = "type_enigma",
    finalize,
);
*/

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
