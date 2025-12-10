use core::ffi::CStr;
use crate::common::*;
use crate::{PRIV_KEYS,PUB_KEYS};
use crate::crypt::pgp::*;
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

pub const E_PGP_TAG: &str = "PgE_PGP1"; // 0x5067455F50475031
pub const E_PGP_INT: u64  = 0x5067455F50475031; // "PgE_PGP1"

/// Value stores PGP-encrypted message
#[derive( Clone, Debug, EnigmaType)]
#[enigma_impl( FullBoilerplate )]
pub enum Epgp {
    /// PGP message
    PGP(u32,String),
    /// Plain unencrypted message
    Plain(String)
}

impl TryFrom<&str> for Epgp {
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
                    E_PGP_INT => {
                        debug2!("PGP encrypted message");
                        return Ok(Self::pgp(key, payload.to_string()));
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

impl TryFrom<Enigma> for Epgp {
    type Error = Box<dyn std::error::Error + 'static>;

    fn try_from(value: Enigma) -> Result<Self, Self::Error> {
        match value {
            Enigma::PGP(key,msg) => Ok(Epgp::PGP(key,msg)),
            _ => Err("Not an Enigma PGP message".into())
        }
    }
}

impl TryFrom<&Enigma> for Epgp {
    type Error = Box<dyn std::error::Error + 'static>;

    fn try_from(value: &Enigma) -> Result<Self, Self::Error> {
        Self::try_from(value.clone())
    }
}

impl TryFrom<Legacy> for Epgp {
    type Error = Box<dyn std::error::Error + 'static>;

    fn try_from(value: Legacy) -> Result<Self, Self::Error> {
        match value {
            Legacy::PGP(key,msg) => Ok(Self::PGP(key,msg)),
            _ => Err("Not a legacy Enigma PGP message".into())
        }
    }
}

impl Display for Epgp {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Epgp::PGP(key,msg) => {
                write!(f, "{}{:08X}{}{}", 
                E_PGP_TAG, key, SEPARATOR, msg)
            },
            Epgp::Plain(s) => {
                write!(f, "{}", s)
            }
        }        
    }
}

impl Epgp {
    pub fn pgp(id: u32, value: String) -> Self {
        Self::PGP(id, pgp_trim_envelope(value))
    }

    /* pub fn is_pgp(&self) -> bool {
        matches!(*self, Self::PGP(_,_))
    } */

    pub fn key_id(&self) -> Option<u32> {
        match self {
            Self::PGP(k,_) => Some(*k),
            Self::Plain(_) => None
        }
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
                PubKey::PGP(_) => pub_key.encrypt(key_id, self),
                _ => return Err(
                    format!("Public key {} is not PGP", key_id).into())

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
                    PrivKey::PGP(_,_) => sec_key.decrypt(self),
                    _ => return Err(
                        format!("Private key {} is not PGP", key_id).into())
                }
            },
            None => Ok(self)
        }
    }
}


