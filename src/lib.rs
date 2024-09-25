use lazy_static::lazy_static;
use pgrx::prelude::*;
use serde::{Serialize, Deserialize};
use pgrx::{StringInfo};
use core::ffi::CStr;
use once_cell::sync::Lazy;
use openssl::base64::{encode_block,decode_block};
use openssl::encrypt::{Encrypter,Decrypter};
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Padding;
use pgp::{SignedSecretKey, Deserializable};
use pgp::SignedPublicKey;
use pgp::composed::message::Message;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{KeyId, KeyTrait};
use rand::prelude::*;
use regex::Regex;
use std::collections::BTreeMap;
use std::fs;
use std::io::Cursor;
use std::sync::RwLock;
//use pgrx_macros::extension_sql;

pgrx::pg_module_magic!();

static PRIV_KEYS: Lazy<PrivKeysMap> = Lazy::new(|| PrivKeysMap::new());


pub struct PrivKeysMap {
    /// each `BTreeMap` entry is a reference to a `PrivKey` structure
    keys: RwLock<BTreeMap<i32,&'static PrivKey>>,
}

/// Functions for private keys map
/// Lifetimes are handled here, so these functions can be called safely
/// from elsewhere.
impl PrivKeysMap {
    /// Creates new (empty) PrivKeys struct
    pub fn new() -> Self {
        let keys = RwLock::new(BTreeMap::new());
        PrivKeysMap {
            keys: keys // new empty BTreeMap
        }
    }

    /// Sets the `PrivKeysMap` `id` to the `PrivKey` obtained from the
    /// provides armored key and plain text password
    pub fn set(&self, id: i32, armored_key: &str, pw: &str)
    -> Result<String, Box<(dyn std::error::Error + 'static)>> {
        let key = PrivKey::new(armored_key, pw)?; // key with '1 lifetime
        let key_id = key.key_id();
        // put the key into the box to allow change it's lifetime
        let boxed_key = Box::new(key);
        // leaked key is the same address, but now with 'static lifetime
        let static_key: &'static PrivKey = Box::leak(boxed_key);
        // need write lock to insert the key on the BTreeMap
        let old = match self.keys.write() {
            // RwLock::insert() returns Some(old_value) if replaced
            Ok(mut m) => m.insert(id, &static_key),
            Err(e) => return Err(
                format!("PrivKeysMap: set: could not get write lock: {}", e)
                .into()),
        };

        let msg = match old {
            Some(o) => { // the old key was replaced
                let old_id = o.key_id();
                // TODO: drop(o); // free old key (explicitly)
                format!("key {}: private key {} replaced with {}",
                    id, old_id, key_id)
            },
            None => { // No previous key was replaced
                format!("key {}: private key {} imported", id, key_id)
            }
        };
        Ok(msg)
    }

    pub fn del(&'static self, id: i32)
    -> Result<String, Box<(dyn std::error::Error + 'static)>> {
        let old = match self.keys.write() {
            Ok(mut m) => {
                m.remove(&id)
            },
            Err(e) => return Err(
                format!("PrivKeysMap: del: could not get write lock: {}", e)
                .into()),
        };

        let msg = match old {
            Some(o) => {
                let key_id = o.key_id();
                // TODO: drop(o); // free old key (explicitly)
                format!("key {}: private key {} forgotten", id, key_id)
            },
            None => format!("key {}: not set", id)
        };
        Ok(msg)
    }

    /// Gets reference to `PrivKey` from `PrivKeysMap` entry with `id`
    pub fn get(self: &'static PrivKeysMap, id: &i32)
    -> Result<Option<&'static PrivKey>,
    Box<(dyn std::error::Error + 'static)>> {
        let binding = self.keys.read()?;
        let key = match binding.get(id) {
            Some(k) => k,
            None => return Ok(None)
        };
        Ok(Some(key))
    }
}


pub struct PrivKey {
    /// Enigma private key
    key: EnigmaPrivKey,
    /// Secret key password, used for decryption
    pass: String
}

impl PrivKey {
    /// Creates a `PrivKey` struct with the `SignedSecretKey` obtained
    /// from the `armored key` and the provided plain text password
    pub fn new(armored_key: &str, pw: &str)
    -> Result<Self, Box<(dyn std::error::Error + 'static)>> {
        lazy_static! {
            static ref RE_pgp: Regex =
                Regex::new(r"BEGIN PGP PRIVATE KEY BLOCK")
                .expect("failed to compile PGP key regex");
            static ref RE_rsa: Regex =
                Regex::new(r"BEGIN ENCRYPTED PRIVATE KEY")
                .expect("failed to compile OpenSSL RSA key regex");
        }
        if RE_pgp.captures(&armored_key).is_some() {
            // https://docs.rs/pgp/latest/pgp/composed/trait.Deserializable.html#method.from_string
            let (sec_key, _) = SignedSecretKey::from_string(armored_key)?;
            sec_key.verify()?;
            Ok(PrivKey {
                key: EnigmaPrivKey::PGP(sec_key),
                pass: pw.to_string()
            })
        } else if RE_rsa.captures(&armored_key).is_some() {
            let priv_key =
                PKey::<Private>::private_key_from_pem_passphrase(
                    armored_key.as_bytes(), pw.as_bytes())?;
           Ok(PrivKey {
                key: EnigmaPrivKey::RSA(priv_key),
                pass: pw.to_string()
            })
        } else {
            Err("key type not supported".into())
        }
    }

    pub fn key_id(&self) -> String {
        match &self.key {
            EnigmaPrivKey::PGP(p) => {
                String::from(format!("{:X}", p.key_id()))
            },
            EnigmaPrivKey::RSA(r) => {
                 String::from(format!("{:X}", r.id().as_raw()))
            }
        }
    }

    pub fn pass(&self)  -> String {
        self.pass.clone()
    }
}

pub enum EnigmaPrivKey {
    /// PGP secret key
    PGP(SignedSecretKey),
    /// OpenSSL RSA
    RSA(PKey<Private>)
}

impl EnigmaPrivKey {
    pub fn key_id(&self) -> KeyId {
        match self {
            EnigmaPrivKey::PGP(k) => k.key_id(),
            _ => todo!()
        }
    }

}

use pgrx::TypmodInOutFuncs;

/// Value stores entcrypted information
//#[derive(Serialize, Deserialize, Debug, PostgresType)]
#[derive(PostgresType, Serialize, Deserialize, Debug, Eq, PartialEq)]
//#[inoutfuncs(type_enigma_in, type_enigma_out)]
#[typmodinoutfuncs]
struct Enigma {
    value: String,
}

#[::pgrx::pgrx_macros::pg_extern(immutable,parallel_safe)]
pub fn type_enigma_in(input: Option<&::core::ffi::CStr>) -> Option<Enigma> {
    Some(Enigma {
        value: "Test value".to_string(),
    })
}


#[::pgrx::pgrx_macros::pg_extern(immutable,parallel_safe)]
fn type_enigma_out(input: Option<&::core::ffi::CStr>, oid: i32, typmod: i32) {
    panic!("TYPMOD? {}", typmod);
    todo!()
}

/// Functions for extracting and inserting data
impl TypmodInOutFuncs for Enigma {
    // Get from postgres
    fn input(input: &CStr, oid: pg_sys::Oid, typmod: i32) -> Self {
        info!("ARGUMENTS: Input: {:?}, OID: {:?},  Typmod: {}", input, oid, typmod);
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
            Ok(Some(sec_key)) => match decrypt(value, sec_key) {
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
fn decrypt(value: String, sec_key: &PrivKey)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    match &sec_key.key {
        EnigmaPrivKey::PGP(key) => {
            let buf = Cursor::new(value);
            let (msg, _) = Message::from_armor_single(buf)?;
            let (decryptor, _) = msg
            .decrypt(|| sec_key.pass(), &[&key])?;
            let mut clear_text = String::from("NOT DECRYPTED");
            for msg in decryptor {
                let bytes = msg?.get_content()?.unwrap();
                clear_text = String::from_utf8(bytes).unwrap();
            }
            Ok(clear_text)
        },
        EnigmaPrivKey::RSA(pkey) => {
            let input = decode_block(value.as_str())?;
            let mut decrypter = Decrypter::new(&pkey)?;
            decrypter.set_rsa_padding(Padding::PKCS1)?;
            // Get the length of the output buffer
            let buffer_len = decrypter.decrypt_len(&input)?;
            let mut decoded = vec![0u8; buffer_len];
            // Decrypt the data and get its length
            let decoded_len = decrypter.decrypt(&input, &mut decoded)?;
            // Use only the part of the buffer with the decrypted data
            let decoded = &decoded[..decoded_len];
            let clear_text = String::from_utf8(decoded.to_vec())?;
            Ok(clear_text)
        },
        _ => Err("Llave no soportada".into())
    }
}

/// Decrypts the value
fn encrypt(value: String, key: &str)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    lazy_static! {
        static ref RE_pgp: Regex = Regex::new(r"BEGIN PGP PUBLIC KEY BLOCK")
            .expect("failed to compile PGP key regex");
        static ref RE_rsa: Regex = Regex::new(r"BEGIN PUBLIC KEY")
            .expect("failed to compile OpenSSL RSA key regex");
    }
    let ret;
    if RE_pgp.captures(&key).is_some() {
        let (pub_key, _) = SignedPublicKey::from_string(key)?;
        let msg = Message::new_literal("none", value.as_str());
        let mut rng = StdRng::from_entropy();
        let new_msg = msg.encrypt_to_keys(
            &mut rng, SymmetricKeyAlgorithm::AES128, &[&pub_key])?;
        ret = new_msg.to_armored_string(None)?;
    } else if RE_rsa.captures(&key).is_some() {
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

/// Get the private key from the keys table
fn get_private_key(id: i32)
-> Result<Option<&'static PrivKey>,
Box<(dyn std::error::Error + 'static)>> {
   PRIV_KEYS.get(&id)
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
