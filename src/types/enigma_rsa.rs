use core::ffi::CStr;
use crate::common::*;
use crate::{PRIV_KEYS,PUB_KEYS};
use crate::crypt::openssl::*;
use crate::pub_key::PubKey;
use crate::priv_key::PrivKey;
use enigma_macros::EnigmaType;
use pgrx::callconv::{ArgAbi, BoxRet};
use pgrx::datum::Datum;
use pgrx::{
    debug1, debug2, debug5, error, info,
    Array, FromDatum, Internal, IntoDatum, pg_extern, pg_sys, 
    rust_regtypein, StringInfo
};
use pgrx::pgrx_sql_entity_graph::metadata::{
    ArgumentError, Returns, ReturnsError, SqlMapping, SqlTranslatable
};
use std::fmt::{Display, Formatter};
use super::enigma::Enigma;
use super::legacy::*;

pub const E_RSA_TAG: &str = "PgE_RSA1"; // 0x5067455F52534131
pub const E_RSA_INT: u64  = 0x5067455F52534131; // "PgE_RSA1"

/// Value stores RSA-encrypted message
#[derive( Clone, Debug, EnigmaType)]
#[enigma_impl( FullBoilerplate )]
pub enum Ersa {
    /// RSA message
    RSA(u32,String),
    /// Plain unencrypted message
    Plain(String)
}

impl TryFrom<&str> for Ersa {
    type Error = Box<dyn std::error::Error + 'static>;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if let Some((header, payload)) = value.split_once(SEPARATOR) {
            if let Ok(Header{tag,key}) = Header::try_from(header) {
                match tag {
                    PLAIN_INT => {
                        debug2!{"Plain unencrypted message"}
                        debug5!{"Payload: {payload}"}
                        return Ok(Self::plain(payload.to_string()));
                    },
                    E_RSA_INT => {
                        debug2!("RSA encrypted message");
                        return Ok(Self::rsa(key, payload.to_string()));
                    },
                    ENIGMA_INT => {
                        return Self::try_from(Legacy::try_from(value)?);
                    },
                    _ => return Err(
                        format!("Unknown Enigma header: {}", header).into())
                }
            } // non-parseable header is plain message
        } // no header is plain message

        debug2!("Not an Enigma message");
        debug5!("Value: {value}");
        Ok(Self::plain(value.to_string()))
    }
} 

impl TryFrom<Enigma> for Ersa {
    type Error = Box<dyn std::error::Error + 'static>;

    fn try_from(value: Enigma) -> Result<Self, Self::Error> {
        match value {
            Enigma::RSA(key,msg) => Ok(Ersa::RSA(key,msg)),
            _ => Err("Not an Enigma RSA message".into())
        }
    }
}

impl TryFrom<&Enigma> for Ersa {
    type Error = Box<dyn std::error::Error + 'static>;

    fn try_from(value: &Enigma) -> Result<Self, Self::Error> {
        Self::try_from(value.clone())
    }
}

impl TryFrom<Legacy> for Ersa {
    type Error = Box<dyn std::error::Error + 'static>;

    fn try_from(value: Legacy) -> Result<Self, Self::Error> {
        match value {
            Legacy::RSA(key,msg) => Ok(Self::RSA(key,msg)),
            _ => Err("Not a legacy Enigma RSA message".into())
        }
    }
}

impl Display for Ersa {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Ersa::RSA(key,msg) => {
                write!(f, "{}{:08X}{}{}", 
                E_RSA_TAG, key, SEPARATOR, msg)
            },
            Ersa::Plain(s) => {
                write!(f, "{}", s)
            }
        }        
    }
}

impl Ersa {
    pub fn rsa(id: u32, value: String) -> Self {
        Self::RSA(id, rsa_trim_envelope(value))
    }

    #[allow(dead_code)]
    pub fn is_rsa(&self) -> bool {
        matches!(*self, Self::RSA(_,_))
    }

    pub fn key_id(&self) -> Option<u32> {
        match self {
            Self::RSA(k,_) => Some(*k),
            Self::Plain(_) => None
        }
    }

    #[allow(dead_code)]
    pub fn value(&self) -> String {
        self.to_string()
    }

    /// Will look for the encryption key in it's key map and call
    /// the key's `encrypt()` function to encrypt the message.
    /// If no encrypting key is found, returns an error message.
    pub fn encrypt(self, id: i32) 
    -> Result<Self, Box<dyn std::error::Error + 'static>> {
        if id < 0 { 
            return Err("Key id must be zero or greater".into());
        }
        let key_id: u32 = id as u32;
        if let Some(msgid) = self.key_id() { // message is encrypted
            if msgid == key_id {
                info!("Already encrypted with key ID {msgid}"); 
                return  Ok(self);
            };
            // TODO: try to decrypt
            return Err("Nested encryption not supported".into());
        }

        if let Some(pub_key) = PUB_KEYS.get(key_id)? {
            match pub_key {
                PubKey::RSA(_) => pub_key.encrypt(key_id, self),
                _ => return Err(
                    format!("Public key {} is not RSA", key_id).into())

            }
        } else {
            Err(format!("No public key with key_id: {}", key_id).into())
        }
    }

    /// Will look for the decryption key in it's key map and call
    /// the key's `decrypt()` function to decrypt the message.
    /// If no decrypting key is found, returns the same encrypted message.
    pub fn decrypt(self)
    -> Result<Self, Box<dyn std::error::Error + 'static>> {
        let key_id = match self.key_id() {
            Some(k) => k,
            None => return Ok(self) // Not encrypted
        };
        debug2!("Decrypt: Message key_id: {key_id}");
        match PRIV_KEYS.get(key_id)? {
            Some(sec_key) => {
                debug2!("Decrypt: got secret key");
                match sec_key {
                    PrivKey::RSA(_) => sec_key.decrypt(self),
                    _ => return Err(
                        format!("Private key {} is not RSA", key_id).into())
                }
            },
            None => Ok(self)
        }
    }
}


