use core::ffi::CStr;
use crate::common::*;
use crate::enigma::{Enigma,ENIGMA_INT};
use crate::{PRIV_KEYS,PUB_KEYS};
use crate::pgp::*;
use pgrx::callconv::{ArgAbi, BoxRet};
use pgrx::datum::Datum;
use pgrx::{debug2,debug5,error,info};
use pgrx::{FromDatum,IntoDatum,pg_sys,rust_regtypein};
use pgrx::pgrx_sql_entity_graph::metadata::{
    ArgumentError, Returns, ReturnsError, SqlMapping, SqlTranslatable
};
use pgrx::StringInfo;
//use crate::pub_key::PubKey;
use crate::priv_key::PrivKey;
use std::fmt::{Display, Formatter};

const PGE_PGP_TAG: &str = "PGE_PGP1"; // 0x5067455F50475031
const PGE_PGP_INT: u64  = 0x5067455F50475031; // "PGE_PGP1"

/// Value stores PGP-encrypted message
#[derive( Clone, Debug)]
pub enum PgEpgp {
    /// PGP message
    PGP(u32,String),
    /// Plain unencrypted message
    Plain(String)
}

impl TryFrom<&str> for PgEpgp {
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
                    PGE_PGP_INT => {
                        debug2!("PGP encrypted message");
                        return Ok(Self::pgp(key, payload.to_string()));
                    },
                    ENIGMA_INT => {
                        return Self::try_from(Enigma::try_from(value)?);
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

impl TryFrom<String> for PgEpgp {
    type Error = Box<dyn std::error::Error + 'static>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl TryFrom<&String> for PgEpgp {
    type Error = Box<dyn std::error::Error + 'static>;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl TryFrom<StringInfo> for PgEpgp {
    type Error = Box<dyn std::error::Error + 'static>;

    fn try_from(value: StringInfo) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str()?)
    }
}

impl TryFrom<&CStr> for PgEpgp {
    type Error = Box<dyn std::error::Error + 'static>;

    fn try_from(value: &CStr) -> Result<Self, Self::Error> {
        Self::try_from(value.to_str()?)
    }
}

impl TryFrom<Enigma> for PgEpgp {
    type Error = Box<dyn std::error::Error + 'static>;

    fn try_from(value:Enigma) -> Result<Self, Self::Error> {
        match value {
            Enigma::PGP(key,msg) => Ok(PgEpgp::PGP(key,msg)),
            _ => Err("Not an Enigma PGP message".into())
        }
    }
}

impl Display for PgEpgp {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            PgEpgp::PGP(key,msg) => {
                write!(f, "{}{:08X}{}{}", 
                PGE_PGP_TAG, key, SEPARATOR, msg)
            },
            PgEpgp::Plain(s) => {
                write!(f, "{}", s)
            }
        }        
    }
}

// TODO: #[derive(EnigmaPlain)]
impl Plain for PgEpgp {
    fn plain(value: String) -> Self {
        Self::Plain(value)
    }

    fn is_plain(&self) -> bool {
        matches!(*self, Self::Plain(_))
    }
}

impl PgEpgp {
    pub fn pgp(id: u32, value: String) -> Self {
        Self::PGP(id, pgp_trim_envelope(value))
    }

    #[allow(dead_code)]
    pub fn is_pgp(&self) -> bool {
        matches!(*self, Self::PGP(_,_))
    }

    pub fn key_id(&self) -> Option<u32> {
        match self {
            Self::PGP(k,_) => Some(*k),
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
            pub_key.encrypt(key_id, self)
        } else {
            Err(format!("No public key with key_id: {}", key_id).into())
        }
    }

    /// Will look for the decryption key in it's key map and call
    /// the key's `decrypt()` function to decrypt the message.
    /// If no decrypting key is found, returns the same encrypted message.
    pub fn decrypt(self)
    -> Result<PgEpgp, Box<dyn std::error::Error + 'static>> {
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
                        format!("Key {} is not PGP", key_id).into())
                }
            },
            None => Ok(self)
        }
    }
}


/**************************************************************************
*                                                                         *
*                                                                         *
*                B O I L E R P L A T E  F U N C T I O N S                 *
*                                                                         *
*                                                                         *
**************************************************************************/

// TODO: #[derive(EnigmaBoilerplate)]
// Boilerplate traits for converting type to postgres internals
// Needed for the FunctionMetadata trait
unsafe impl SqlTranslatable for PgEpgp {
    fn argument_sql() -> Result<SqlMapping, ArgumentError> {
        // this is what the SQL type is called when used in a function argument position
        Ok(SqlMapping::As("PgEpgp".into()))
    }

    fn return_sql() -> Result<Returns, ReturnsError> {
        // this is what the SQL type is called when used in a function return type position
        Ok(Returns::One(SqlMapping::As("PgEpgp".into())))
    }
}


unsafe impl<'fcx> ArgAbi<'fcx> for PgEpgp
where
    Self: 'fcx,
{
    unsafe fn unbox_arg_unchecked(arg: ::pgrx::callconv::Arg<'_, 'fcx>) -> Self {
        unsafe { arg.unbox_arg_using_from_datum().unwrap() }
    }
}


unsafe impl BoxRet for PgEpgp {
    unsafe fn box_into<'fcx>(self, 
    fcinfo: &mut pgrx::callconv::FcInfo<'fcx>) 
    -> Datum<'fcx> {
        fcinfo.return_raw_datum(
           self.into_datum()
                .expect("BoxRet IntoDatum error")
        )
    }
}

impl FromDatum for PgEpgp {
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
        let enigma = PgEpgp::try_from(value).expect("Corrupted PgEpgp");
        //debug2!("FromDatum: Encrypted message: {:?}", enigma);
        let decrypted = enigma.decrypt()
                                .expect("FromDatum: Decrypt error");
        //debug2!("FromDatum: Decrypted message: {:?}", decrypted);
        Some(decrypted)
    }
}

impl IntoDatum for PgEpgp {
    fn into_datum(self) -> Option<pg_sys::Datum> {
        let value = match self {
            Self::Plain(s) => {
                //format!("{}{:08X}{}{}", PLAIN_TAG, 0, SEPARATOR, s)
                debug5!("Plain value: {}", s);
                error!("PgEpgp is not encrypted");
            },
            _ => self.to_string()
        };
        debug2!("IntoDatum value:\n{value}");
        Some( value.into_datum().expect("IntoDatum error") )
    }

    fn type_oid() -> pg_sys::Oid {
        rust_regtypein::<Self>()
    }
}


