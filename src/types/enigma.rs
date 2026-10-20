use core::ffi::CStr;
use crate::common::*;
use crate::{PRIV_KEYS,PUB_KEYS};
use crate::crypt::openssl::*;
use crate::crypt::pgp::*;
//use crate::crypt::pgp::{PgpMessage};
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
use super::enigma_pgp::{E_PGP_INT,E_PGP_TAG,Epgp};
use super::enigma_rsa::{E_RSA_INT,E_RSA_TAG,Ersa};
use super::legacy::{ENIGMA_INT,Legacy};

/// Value stores entcrypted information
#[derive( Clone, Debug, EnigmaType)]
#[enigma_impl( FullBoilerplate )]
pub enum Enigma {
    /// PGP message
    //PGP(u32,String),
    PGP(PgpMessage),
    /// OpenSSL RSA encrypted message
    RSA(u32,String), 
    /// Plain unencrypted message
    Plain(String)
}

impl TryFrom<&str> for Enigma {
    type Error = Box<dyn std::error::Error + 'static>;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if let Some((header, payload)) = value.split_once(SEPARATOR) {
            if let Ok(Header{tag,..}) = Header::try_from(header) {
                match tag {
                    PLAIN_INT => {
                        debug2!{"Enigma: Plain unencrypted message"}
                        debug5!{"Payload: {payload}"}
                        return Ok(Self::plain(payload.to_string()));
                    },
                    E_PGP_INT => {
                        debug2!("Enigma: PGP encrypted message");
                        return Ok(Self::from(Epgp::try_from(value)?));
                    },
                    E_RSA_INT => {
                        debug2!("Enigma: RSA encrypted message");
                        return Ok(Self::from(Ersa::try_from(value)?));
                    },
                    ENIGMA_INT => {
                        return Ok(Self::from(Legacy::try_from(value)?));
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

impl From<Epgp> for Enigma {
    fn from(value: Epgp) -> Self {
        match value {
            Epgp::PGP(val) => Self::PGP(val),
            Epgp::Plain(msg) => Self::Plain(msg),
        }
    }
}

impl From<Ersa> for Enigma {
    fn from(value: Ersa) -> Self {
        match value {
            Ersa::RSA(key,msg) => Self::RSA(key,msg),
            Ersa::Plain(msg) => Self::Plain(msg),
        }
    }
}

impl From<Legacy> for Enigma {
    fn from(value: Legacy) -> Self {
        match value {
            Legacy::PGP(key,msg) => Self::pgp(key,msg),
            Legacy::RSA(key,msg) => Self::RSA(key,msg),
            //Legacy::Plain(msg) => Self::Plain(msg),
        }
    }
}

/*impl TryFrom<Enigma> for PgpMessage {
   type Error = Box<dyn std::error::Error + 'static>;

    fn try_from(value: Enigma) -> Result<Self, Self::Error> {
        match value {
            Enigma::PgpMessage{key_id,message} => {
                Ok(PgpMessage{key_id,message})
            },
            _ => {
                Err("Not a PgpMessage variant".into())
            }
        }
    }

} */

impl Display for Enigma {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PGP(msg) => {
                //let val: &PgpMessage = self.0;
                write!(f, "{}{}", E_PGP_TAG, msg)
            },
            Self::RSA(key,msg) => {
                // Use new Ersa header
                write!(f, "{}{:08X}{}{}", 
                E_RSA_TAG, key, SEPARATOR, msg)
            },
            Self::Plain(s) => {
                write!(f, "{}", s)
            }
        }        
    }
}

impl Enigma {
    pub fn pgp(id: u32, value: String) -> Self {
        Self::PGP(PgpMessage::new(id, pgp_trim_envelope(value)))
    }

    pub fn rsa(id: u32, value: String) -> Self {
        Self::RSA(id, rsa_trim_envelope(value))
    }

    pub fn is_pgp(&self) -> bool {
        matches!(*self, Self::PGP(_))
    }

    pub fn is_rsa(&self) -> bool {
        matches!(*self, Self::RSA(_,_))
    }

    pub fn key_id(&self) -> Option<u32> {
        match self {
            Self::RSA(k,_) => Some(*k),
            Self::PGP(pgp_msg) => Some(pgp_msg.key_id()),
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
            pub_key.encrypt(key_id, self)
        } else {
            Err(format!("No public key with key_id: {}", key_id).into())
        }
    }

    /// Will look for the decryption key in it's key map and call
    /// the key's `decrypt()` function to decrypt the message.
    /// If no decrypting key is found, returns the same encrypted message.
    pub fn decrypt(self)
    -> Result<Enigma, Box<dyn std::error::Error + 'static>> {
        if let Some(key_id) = self.key_id() {
            debug2!("Enigma Decrypt: Message key_id: {key_id}");
            if let Some(sec_key) = PRIV_KEYS.get(key_id)? {
                debug2!("Enigma Decrypt got key: {key_id}");
                if let Self::RSA(_,_) = self {
                    return sec_key.decrypt(self);
                }
                if let Self::PGP(ref msg) = self {
                    if let PrivKey::PGP(key,pass) = sec_key {
                        debug2!("Enigma key: {key_id} is PGP");
                        return Ok(Self::plain(
                            msg.decrypt(key,pass.clone())?
                        ));
                    } else {
                        return Err(format!("Private key {} is not PGP", 
                            key_id).into());
                    }
                }
            }
        }
        Ok(self) // No Private key found
    }
}

