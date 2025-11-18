use core::ffi::CStr;
use crate::common::*;
use crate::{PRIV_KEYS,PUB_KEYS};
use pgrx::callconv::{ArgAbi, BoxRet};
use pgrx::datum::Datum;
use pgrx::{debug2,debug5,info};
use pgrx::{FromDatum,IntoDatum,pg_sys,rust_regtypein};
use pgrx::pgrx_sql_entity_graph::metadata::{
    ArgumentError, Returns, ReturnsError, SqlMapping, SqlTranslatable
};
use pgrx::StringInfo;
use std::fmt::{Display, Formatter};

const PGP_BEGIN: &str = "-----BEGIN PGP MESSAGE-----\n";
const PGP_END: &str = "-----END PGP MESSAGE-----\n";
const RSA_BEGIN: &str = "-----BEGIN RSA ENCRYPTED-----\n";
const RSA_END: &str = "\n-----END RSA ENCRYPTED-----";
const ENIGMA_TAG: &str = "ENIGMAv1"; // 0x454E49474D417631
const ENIGMA_INT: u64  = 0x454E49474D417631; // "ENIGMAv1"

/// Value stores entcrypted information
#[derive( Clone, Debug)]
pub enum Enigma {
    /// PGP message
    PGP(u32,String),
    /// OpenSSL RSA encrypted message
    RSA(u32,String), 
    /// Plain unencrypted message
    Plain(String)
}

impl TryFrom<&str> for Enigma {
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
                    ENIGMA_INT => {
                        if payload.starts_with(PGP_BEGIN) 
                        && payload.ends_with(PGP_END) {
                            debug2!("PGP encrypted message");
                            return Ok(from_pgp_armor(key, payload));
                        }

                        if payload.starts_with(RSA_BEGIN)
                        && payload.ends_with(RSA_END) {
                            debug2!("RSA encrypted message");
                            return Ok(from_rsa_envelope(key, payload));
                        }
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

impl TryFrom<String> for Enigma {
    type Error = Box<dyn std::error::Error + 'static>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl TryFrom<&String> for Enigma {
    type Error = Box<dyn std::error::Error + 'static>;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl TryFrom<StringInfo> for Enigma {
    type Error = Box<dyn std::error::Error + 'static>;

    fn try_from(value: StringInfo) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str()?)
    }
}

impl TryFrom<&CStr> for Enigma {
    type Error = Box<dyn std::error::Error + 'static>;

    fn try_from(value: &CStr) -> Result<Self, Self::Error> {
        Self::try_from(value.to_str()?)
    }
}

impl Display for Enigma {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // TODO: Specific PGP or RSA Enigma tags to remove _BEGIN and _END
        match self {
            Enigma::PGP(key,msg) => {
                write!(f, "{}{:08X}{}{}{}{}", 
                ENIGMA_TAG, key, SEPARATOR, PGP_BEGIN, msg, PGP_END)
            },
            Enigma::RSA(key,msg) => {
                write!(f, "{}{:08X}{}{}{}{}",
                ENIGMA_TAG, key, SEPARATOR, RSA_BEGIN, msg, RSA_END)
            },
            Enigma::Plain(s) => {
                //write!(f, "{}{:08X}{}{}", PLAIN_TAG, 0, SEPARATOR, s)
                write!(f, "{}", s)
            }
        }        
    }
}

// TODO: #[derive(Plain)]
impl Plain for Enigma {
    fn plain(value: String) -> Self {
        Self::Plain(value)
    }

    fn is_plain(&self) -> bool {
        matches!(*self, Self::Plain(_))
    }
}

impl Enigma {
    pub fn pgp(id: u32, value: String) -> Self {
        Self::PGP(id, value
                    .trim_start_matches(PGP_BEGIN)
                    .trim_end_matches(PGP_END)
                    .to_string())
    }

    pub fn rsa(id: u32, value: String) -> Self {
        Self::RSA(id, value)
    }

    #[allow(dead_code)]
    pub fn is_pgp(&self) -> bool {
        matches!(*self, Self::PGP(_,_))
    }

    #[allow(dead_code)]
    pub fn is_rsa(&self) -> bool {
        matches!(*self, Self::RSA(_,_))
    }

    pub fn key_id(&self) -> Option<u32> {
        match self {
            Self::RSA(k,_) => Some(*k),
            Self::PGP(k,_) => Some(*k),
            Self::Plain(_) => None
        }
    }

    #[allow(dead_code)]
    pub fn value(&self) -> String {
        self.to_string()
    }

    /* PGP specific functions commented-out for future use
    pub fn pgp_encrypting_keys(&self)
    -> Result<Vec<KeyId>, Box<dyn std::error::Error + 'static>> {
        let mut keys = Vec::new();
        if let Self::PGP(_,pgp::Message::Encrypted{ esk, .. }) = self {
            for each_esk in esk {
                if let PublicKeyEncryptedSessionKey(skey) = each_esk {
                    let pgp_id = skey.id()?;
                    debug1!("Encrypting key: {:?}", pgp_id);
                    keys.push(pgp_id.clone());
                }
            }
        }
        Ok(keys)
    }

    pub fn pgp_encrypting_key(&self)
    -> Result<KeyId, Box<dyn std::error::Error + 'static>> {
        let mut keys = self.pgp_encrypting_keys()?;
        if keys.len() > 1 {
            return Err("More than one encrypting key".into());
        }
        keys.pop().ok_or("No encrypting key found".into())
    }

    pub fn pgp_encrypting_key_as_string(&self)
    -> Result<String, Box<dyn std::error::Error + 'static>> {
        let pgp_id = self.pgp_encrypting_key()?;
        Ok(format!("{:x}", pgp_id))
    } */

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
            return pub_key.encrypt(key_id, self);
        }
        Err(format!("No public key with key_id: {}", key_id).into())
    }

    /// Will look for the decryption key in it's key map and call
    /// the key's `decrypt()` function to decrypt the message.
    /// If no decrypting key is found, returns the same encrypted message.
    pub fn decrypt(self)
    -> Result<Enigma, Box<dyn std::error::Error + 'static>> {
        let key_id = match self.key_id() {
            Some(k) => k,
            None => return Ok(self) // Not encrypted
        };
        debug2!("Decrypt: Message key_id: {key_id}");
        match PRIV_KEYS.get(key_id)? {
            Some(sec_key) => {
                debug2!("Decrypt: got secret key");
                sec_key.decrypt(self)
            },
            None => Ok(self)
        }
    }
}

/* not being used
pub fn is_enigma_hdr(hdr: &str) -> bool {
    // TODO: optimize: just first [u8; 8] cast to u64
    if let Ok((tag, _)) = split_hdr(hdr) {
        if tag == ENIGMA_INT {
            return true;
        }
    }
    false
} */

/*********************
 * PRIVATE FUNCTIONS *
 * *******************/

fn from_pgp_armor(key_id: u32, value: &str) -> Enigma {
    Enigma::PGP(key_id, value
        .trim_start_matches(PGP_BEGIN)
        .trim_end_matches(PGP_END)
        .to_string() )
}

fn from_rsa_envelope(key_id: u32, value: &str) -> Enigma {
    Enigma::RSA(key_id, value
        .trim_start_matches(RSA_BEGIN)
        .trim_end_matches(RSA_END)
        .to_string() )
}


/**************************************************************************
*                                                                         *
*                                                                         *
*                B O I L E R P L A T E  F U N C T I O N S                 *
*                                                                         *
*                                                                         *
**************************************************************************/

// Boilerplate traits for converting type to postgres internals
// Needed for the FunctionMetadata trait
unsafe impl SqlTranslatable for Enigma {
    fn argument_sql() -> Result<SqlMapping, ArgumentError> {
        // this is what the SQL type is called when used in a function argument position
        Ok(SqlMapping::As("enigma".into()))
    }

    fn return_sql() -> Result<Returns, ReturnsError> {
        // this is what the SQL type is called when used in a function return type position
        Ok(Returns::One(SqlMapping::As("enigma".into())))
    }
}


unsafe impl<'fcx> ArgAbi<'fcx> for Enigma
where
    Self: 'fcx,
{
    unsafe fn unbox_arg_unchecked(arg: ::pgrx::callconv::Arg<'_, 'fcx>) -> Self {
        unsafe { arg.unbox_arg_using_from_datum().unwrap() }
    }
}


unsafe impl BoxRet for Enigma {
    unsafe fn box_into<'fcx>(self, 
    fcinfo: &mut pgrx::callconv::FcInfo<'fcx>) 
    -> Datum<'fcx> {
        fcinfo.return_raw_datum(
           self.into_datum()
                .expect("BoxRet IntoDatum error")
        )
    }
}

impl FromDatum for Enigma {
    unsafe fn from_polymorphic_datum(datum: pg_sys::Datum, 
    is_null: bool, _: pg_sys::Oid) 
    -> Option<Self>
    where
        Self: Sized,
    {
        if is_null {
            return None;
        }  
        let value = match String::from_datum(datum, is_null) {
            None => return None,
            Some(v) => v
        };
        debug2!("FromDatum value:\n{value}");
        let enigma = Enigma::try_from(value).expect("Corrupted Enigma");
        //debug2!("FromDatum: Encrypted message: {:?}", enigma);
        let decrypted = enigma.decrypt()
                                .expect("FromDatum: Decrypt error");
        //debug2!("FromDatum: Decrypted message: {:?}", decrypted);
        Some(decrypted)
    }
}

impl IntoDatum for Enigma {
    fn into_datum(self) -> Option<pg_sys::Datum> {
        /* if self.is_plain() {
            error!("Enigma is not encrypted");
        } */

        // TODO: Specific PGP or RSA Enigma tags to remove _BEGIN and _END
        let value = match self {
            Enigma::PGP(key,msg) => {
                format!("{}{:08X}{}{}{}{}", 
                ENIGMA_TAG, key, SEPARATOR, PGP_BEGIN, msg, PGP_END)
            },
            Enigma::RSA(key,msg) => {
                format!("{}{:08X}{}{}{}{}",
                ENIGMA_TAG, key, SEPARATOR, RSA_BEGIN, msg, RSA_END)
            },
            Enigma::Plain(s) => {
                format!("{}{:08X}{}{}", PLAIN_TAG, 0, SEPARATOR, s)
            }
        };
        debug2!("IntoDatum value:\n{value}");
        Some( value.into_datum().expect("IntoDatum error") )
    }

    fn type_oid() -> pg_sys::Oid {
        rust_regtypein::<Self>()
    }
}

