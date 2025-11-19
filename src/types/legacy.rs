use crate::common::*;
use crate::crypt::pgp::*;
use crate::crypt::rsa::*;
use pgrx::{debug2};
use std::fmt::{Display, Formatter};


pub const ENIGMA_TAG: &str = "ENIGMAv1"; // 0x454E49474D417631
pub const ENIGMA_INT: u64  = 0x454E49474D417631; // "ENIGMAv1"

/// Value stores entcrypted information
#[derive( Clone, Debug)]
pub enum Legacy {
    /// PGP message
    PGP(u32,String),
    /// OpenSSL RSA encrypted message
    RSA(u32,String), 
    /// Plain unencrypted message
    Plain(String)
}

impl TryFrom<&str> for Legacy {
    type Error = Box<dyn std::error::Error + 'static>;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if let Some((header, payload)) = value.split_once(SEPARATOR) {
            if let Ok(Header{tag,key}) = Header::try_from(header) {
                match tag {
                    /* PLAIN_INT => {
                        debug2!{"Plain unencrypted message"}
                        debug5!{"Payload: {payload}"}
                        return Ok(Self::plain(payload.to_string()));
                    }, */
                    ENIGMA_INT => {
                        if pgp_match_msg(payload) {
                            debug2!("PGP encrypted message");
                            return Ok(Self::pgp(key, payload.to_string()));
                        }

                        /* if payload.starts_with(RSA_BEGIN)
                        && payload.ends_with(RSA_END) {
                            debug2!("RSA encrypted message");
                            return Ok(from_rsa_envelope(key, payload));
                        } */
                        if rsa_match_msg(payload) {
                            debug2!("RSA encrypted message");
                            return Ok(Self::rsa(key, payload.to_string()));
                        }

                    },
                    _ => return Err(
                        format!("Unknown Enigma header: {}", header).into())
                }
            }
        }
        Err("Not a legacy Enigma message".into())
    }
} 

impl Display for Legacy {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Legacy::PGP(key,msg) => {
                write!(f, "{}{:08X}{}{}", 
                ENIGMA_TAG, key, SEPARATOR, pgp_add_envelope(msg))
            },
            Legacy::RSA(key,msg) => {
                write!(f, "{}{:08X}{}{}",
                ENIGMA_TAG, key, SEPARATOR, rsa_add_envelope(msg))
            },
            Legacy::Plain(s) => {
                write!(f, "{}", s)
            }
        }        
    }
}

// TODO: #[derive(EnigmaPlain)]
impl Plain for Legacy {
    fn plain(value: String) -> Self {
        Self::Plain(value)
    }

    fn is_plain(&self) -> bool {
        matches!(*self, Self::Plain(_))
    }
}

/*********************
 * PRIVATE FUNCTIONS *
 * *******************/


impl Legacy {
    fn pgp(id: u32, value: String) -> Self {
        Self::PGP(id, pgp_trim_envelope(value))
    }

    fn rsa(id: u32, value: String) -> Self {
        Self::RSA(id, rsa_trim_envelope(value))
    }
}


