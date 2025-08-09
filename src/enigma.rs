use crate::{PRIV_KEYS,PUB_KEYS};
use pgp::Deserializable;
use pgp::Message;
use pgrx::callconv::{ArgAbi, BoxRet};
use pgrx::datum::Datum;
use pgrx::{debug1,debug2};
use pgrx::{FromDatum,IntoDatum,pg_sys,rust_regtypein};
use pgrx::pgrx_sql_entity_graph::metadata::{
    ArgumentError, Returns, ReturnsError, SqlMapping, SqlTranslatable,
};
use std::fmt::{Display, Formatter};
use std::io::Cursor;

const PGP_BEGIN: &str = "-----BEGIN PGP MESSAGE-----\n";
const PGP_END: &str = "-----END PGP MESSAGE-----\n";
const RSA_BEGIN: &str = "-----BEGIN RSA ENCRYPTED-----\n";
const RSA_END: &str = "\n-----END RSA ENCRYPTED-----";
const ENIGMA_TAG: &str = "ENIGMAv1"; // 0x454E49474D417631
const ENIGMA_INT: u64  = 0x454E49474D417631; // "ENIGMAv1"
const PLAIN_TAG: &str  = "PLAINMSG"; // 0x504C41494E4D5347
const PLAIN_INT: u64   = 0x504C41494E4D5347; // "PLAINMSG"
const SEPARATOR: char = '\n';

/// Value stores entcrypted information
#[derive( Clone, Debug)]
pub enum Enigma {
    /// PGP message
    PGP(u32,pgp::Message),
    /// OpenSSL RSA encrypted message
    RSA(u32,String), 
    /// Plain unencrypted message
    Plain(String)
}

impl TryFrom<String> for Enigma {
    type Error = Box<(dyn std::error::Error + 'static)>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if let Some((header, payload)) = value.split_once(SEPARATOR) {
            let (tag,key_id) = split_hdr(header)?;

            if tag == PLAIN_INT {
                //debug2!{"Plain payload: {payload}"}
                return Ok(Self::plain(payload.to_string()));
            }

            if tag == ENIGMA_INT {
                if payload.starts_with(PGP_BEGIN) 
                && payload.ends_with(PGP_END) {
                    //debug2!("PGP encrypted message");
                    return try_from_pgp_armor(key_id, payload);
                }

                if payload.starts_with(RSA_BEGIN)
                && payload.ends_with(RSA_END) {
                    //debug2!("RSA encrypted message");
                    return Ok(from_rsa_envelope(key_id, payload));
                }
            }
        }

        debug2!("Unmatched: {value}");
        unreachable!("Use Enigma::plain() instead");
        //Ok(Self::plain(value))
    }
} 

/// TryFrom with key_id and value returns encrypted Enigma
impl TryFrom<(i32,String)> for Enigma {
    type Error = Box<(dyn std::error::Error + 'static)>;

    fn try_from((typmod,value): (i32,String)) -> Result<Self, Self::Error> {
        if is_enigma_hdr(&value) {
            return Enigma::try_from(value);
        }
        let plain = Enigma::plain(value); 
        let key_id = match typmod {
            -1 => 0, // No typmod, use key_id 0
            _ => typmod
        };        
        PUB_KEYS.encrypt(key_id, plain)
    }
}

impl TryFrom<&String> for Enigma {
    type Error = Box<(dyn std::error::Error + 'static)>;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Self::try_from(value.clone())
    }
}

impl Display for Enigma {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Enigma::PGP(key,m) => {
                let msg = m.to_armored_string(None.into())
                            .expect("PGP armor");
                write!(f, "{}{:08X}{}{}", ENIGMA_TAG, key, SEPARATOR, msg)
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

impl Enigma {
    pub fn plain(value: String) -> Self {
        Self::Plain(value)
    }

    pub fn pgp(id: u32, value: pgp::Message) -> Self {
        // TODO: u32 key_id
        Self::PGP(id, value)
    }

    pub fn rsa(id: u32, value: String) -> Self {
        // TODO: u32 key_id
        Self::RSA(id, value)
    }

    pub fn is_encrypted(&self) -> bool {
        !self.is_plain()
    }

    #[allow(dead_code)]
    pub fn is_pgp(&self) -> bool {
        matches!(*self, Self::PGP(_,_))
    }

    #[allow(dead_code)]
    pub fn is_rsa(&self) -> bool {
        matches!(*self, Self::RSA(_,_))
    }

    pub fn is_plain(&self) -> bool {
        matches!(*self, Self::Plain(_))
    }

    pub fn key_id(&self) -> Option<u32> {
        match self {
            // TODO: u32 key_id
            Self::RSA(k,_) => Some(*k),
            // TODO: u32 key_id
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
    -> Result<Vec<KeyId>, Box<(dyn std::error::Error + 'static)>> {
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
    -> Result<KeyId, Box<(dyn std::error::Error + 'static)>> {
        let mut keys = self.pgp_encrypting_keys()?;
        if keys.len() > 1 {
            return Err("More than one encrypting key".into());
        }
        keys.pop().ok_or("No encrypting key found".into())
    }

    pub fn pgp_encrypting_key_as_string(&self)
    -> Result<String, Box<(dyn std::error::Error + 'static)>> {
        let pgp_id = self.pgp_encrypting_key()?;
        Ok(format!("{:x}", pgp_id))
    } */
}

pub fn is_enigma_hdr(hdr: &str) -> bool {
    // TODO: optimize: just first [u8; 8] cast to u64
    if let Ok((tag, _)) = split_hdr(hdr) {
        if tag == ENIGMA_INT {
            return true;
        }
    }
    false
}

/*********************
 * PRIVATE FUNCTIONS *
 * *******************/

fn split_hdr(full_header: &str) 
-> Result<(u64,u32), Box<(dyn std::error::Error + 'static)>> {
    if full_header.len() < 16 {
        return Err("Wrong header".into());
    }
    let (hdr,_) = full_header.split_at(16);
    let (stag, skey) = hdr.split_at(8);
    let tag = u64::from_be_bytes(stag.as_bytes().try_into()?);
    let key = u32::from_str_radix(skey, 16)?;
    Ok((tag,key))
}

fn try_from_pgp_armor(key_id: u32, value: &str) 
-> Result<Enigma, Box<(dyn std::error::Error + 'static)>> {
    let buf = Cursor::new(value);
    let (msg, _) = Message::from_armor_single(buf)?;
    Ok(Enigma::PGP(key_id, msg))
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
        //debug2!("FromDatum value:\n{value}");
        let enigma = Enigma::try_from(value).expect("Corrupted Enigma");
        //debug2!("FromDatum: Encrypted message: {:?}", enigma);
        let decrypted = PRIV_KEYS.decrypt(enigma)
                                .expect("FromDatum: Decrypt error");
        //debug2!("FromDatum: Decrypted message: {:?}", decrypted);
        Some(decrypted)
    }
}

impl IntoDatum for Enigma {
    fn into_datum(self) -> Option<pg_sys::Datum> {
        let value = match self {
            Enigma::PGP(key,m) => {
                let msg = m.to_armored_string(None.into())
                            .expect("PGP armor");
                format!("{}{:08X}{}{}", ENIGMA_TAG, key, SEPARATOR, msg)
            },
            Enigma::RSA(key,msg) => {
                format!("{}{:08X}{}{}{}{}",
                ENIGMA_TAG, key, SEPARATOR, RSA_BEGIN, msg, RSA_END)
            },
            Enigma::Plain(s) => {
                error!("IntoDatum: Enigma is not encrypted");
            }
        };
        //debug2!("IntoDatum value:\n{value}");
        Some( value.into_datum().expect("IntoDatum error") )
    }

    fn type_oid() -> pg_sys::Oid {
        rust_regtypein::<Self>()
    }
}

