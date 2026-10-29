use core::ffi::CStr;
use crate::common::*;
use crate::{PRIV_KEYS,PUB_KEYS};
use crate::crypt::pgp;
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
    PGP(pgp::Message),
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
                        debug2!{"Epgp: Plain unencrypted message"}
                        debug5!{"Payload: {payload}"}
                        return Ok(Self::plain(payload.to_string()));
                    },
                    E_PGP_INT => {
                        debug2!("Epgp: PGP encrypted message");
                        //debug5!{"Payload: {payload}"}
                        let msg=pgp::Message::new_encrypted(key, payload);
                        return Ok(Self::PGP(msg));
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
            Enigma::PGP(val) => Ok(Self::PGP(val)),
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
            Legacy::PGP(msg) => Ok(Self::PGP(msg)),
            _ => Err("Not a legacy Enigma PGP message".into())
        }
    }
}

impl Display for Epgp {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PGP(msg) => {
                write!(f, "{}{}", 
                E_PGP_TAG, msg)
            },
            Self::Plain(s) => {
                write!(f, "{}", s)
            }
        }        
    }
}

impl Epgp {
    pub fn key_num(&self) -> Option<u32> {
        match self {
            Self::PGP(pgp_msg) => Some(pgp_msg.key_num()),
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
        let key_num: u32 = id as u32;
        if let Self::Plain(plain) = self {
            if let Some(pub_key) = PUB_KEYS.get(key_num)? {
                if let PubKey::PGP(k) = pub_key {
                    let encrypted = pgp::Message::encrypt(
                        plain, key_num, k)?;
                    Ok(Self::PGP(encrypted))
                } else {
                    Err(format!("Public key {} is not PGP", key_num).into())
                }
            } else {
                Err(format!("No public key with key_num: {}", key_num)
                    .into())
            }
        } else { // message is encrypted
            let msgid = self.key_num()
                        .ok_or("Epgp: encrypted with no key_num")?; 
            if msgid == key_num {
                info!("Already encrypted with key ID {msgid}"); 
                Ok(self)
            } else {
            // TODO: try to decrypt
                Err("Nested encryption not supported".into())
            }
        }
    }

    /// Will look for the decryption key in it's key map and call
    /// the key's `decrypt()` function to decrypt the message.
    /// If no decrypting key is found, returns the same encrypted message.
    pub fn decrypt(self)
    -> Result<Self, Box<dyn std::error::Error + 'static>> {
        if let Self::PGP(ref msg) = self {
            let key_num = msg.key_num();
            debug2!("Epgp Decrypt: Message key_num: {key_num}");
            if let Some(sec_key) = PRIV_KEYS.get(key_num)? {
                //debug2!("Epgp Decrypt got key: {key_num}");
                if let PrivKey::PGP(k) = sec_key {
                    //debug2!("Epgp key: {key_num} is PGP");
                    Ok(Self::plain(
                        msg.decrypt(k)?
                    ))
                } else {
                    Err(format!("Private key {} is not PGP", key_num)
                        .into())
                }
            } else {
                Ok(self) // No Private key found
            }
        } else {
            Ok(self) // Not encrypted
        }
    }
}


