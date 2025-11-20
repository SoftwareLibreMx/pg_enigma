use core::ffi::CStr;
use crate::common::*;
use crate::{PRIV_KEYS,PUB_KEYS};
use crate::crypt::openssl::*;
use crate::pub_key::PubKey;
use crate::priv_key::PrivKey;
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
#[derive( Clone, Debug)]
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

impl TryFrom<String> for Ersa {
    type Error = Box<dyn std::error::Error + 'static>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl TryFrom<&String> for Ersa {
    type Error = Box<dyn std::error::Error + 'static>;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl TryFrom<StringInfo> for Ersa {
    type Error = Box<dyn std::error::Error + 'static>;

    fn try_from(value: StringInfo) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str()?)
    }
}

impl TryFrom<&CStr> for Ersa {
    type Error = Box<dyn std::error::Error + 'static>;

    fn try_from(value: &CStr) -> Result<Self, Self::Error> {
        Self::try_from(value.to_str()?)
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

// TODO: #[derive(EnigmaPlain)]
impl Plain for Ersa {
    fn plain(value: String) -> Self {
        Self::Plain(value)
    }

    fn is_plain(&self) -> bool {
        matches!(*self, Self::Plain(_))
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


/**********************
 * POSTGRES FUNCTIONS *
 * ********************/

/* 
/// Functions for extracting and inserting data
#[pg_extern(stable, parallel_safe, requires = [ "shell_type" ])]
fn ersa_input(input: &CStr, oid: pg_sys::Oid, typmod: i32) 
-> Result<Ersa, Box<dyn std::error::Error + 'static>> {
	//debug2!("INPUT: OID: {:?},  Typmod: {}", oid, typmod);
	debug5!("INPUT: ARGUMENTS: \
            Input: {:?}, OID: {:?},  Typmod: {}", input, oid, typmod);
    let enigma =  Ersa::try_from(input)?;
    if enigma.is_encrypted() {
        info!("Already encrypted"); 
        return Ok(enigma);
    }
    if typmod == -1 { // unknown typmod 
        //debug1!("Unknown typmod: {typmod}");
        return Err("INPUT: Ersa Typmod is ambiguous.\n\
            You should cast the value as ::Text\n\
            More details in issue #4 \
        https://git.softwarelibre.mx/SoftwareLibreMx/pg_enigma/issues/4\
            ".into());
    }
    enigma.encrypt(typmod)
}

/// Assignment cast is called before the INPUT function.
#[pg_extern]
fn string_as_ersa(original: String, typmod: i32, explicit: bool) 
-> Result<Ersa, Box<dyn std::error::Error + 'static>> {
    debug2!("string_as_ersa: \
        ARGUMENTS: explicit: {},  Typmod: {}", explicit, typmod);
    let key_id = match typmod {
        -1 => { debug1!("Unknown typmod; using default key ID 0");
            0 },
        _ => typmod
    };
    Ersa::try_from(original)?.encrypt(key_id)
}

/// Cast Ersa to Ersa is called after ersa_input_with_typmod(). 
/// This function is passed the correct known typmod argument.
#[pg_extern(stable, parallel_safe)]
fn ersa_as_ersa(original: Ersa, typmod: i32, explicit: bool) 
-> Result<Ersa, Box<dyn std::error::Error + 'static>> {
    debug2!("CAST(Ersa AS Ersa): \
        ARGUMENTS: explicit: {},  Typmod: {}", explicit, typmod);
    debug5!("Original: {:?}", original);
    if original.is_encrypted() {
        // TODO: if original.key_id != key_id {try_reencrypt()} 
        return Ok(original);
    } 
    let key_id = match typmod {
        -1 => match explicit { 
            false => return Err( // Implicit is not called when no typmod
                format!("Unknown typmod: {}", typmod).into()),
            true => { debug1!("Unknown typmod; using default key ID 0");
            0}
        },
        _ => typmod
    };
    debug2!("Encrypting plain message with key ID: {key_id}");
    original.encrypt(key_id)
}

/// Ersa RECEIVE function
#[pg_extern(stable, parallel_safe, requires = [ "shell_type" ])]
fn ersa_receive(mut internal: Internal, oid: pg_sys::Oid, typmod: i32) 
-> Result<Ersa, Box<dyn std::error::Error + 'static>> {
    debug2!("RECEIVE: OID: {:?},  Typmod: {}", oid, typmod);
    let buf = unsafe { 
        internal.get_mut::<::pgrx::pg_sys::StringInfoData>().unwrap() 
    };
    let mut serialized = ::pgrx::StringInfo::new();
    // reserve space for the header
    serialized.push_bytes(&[0u8; ::pgrx::pg_sys::VARHDRSZ]); 
    serialized.push_bytes(unsafe {
        core::slice::from_raw_parts(
            buf.data as *const u8,
            buf.len as usize )
    });
    debug5!("RECEIVE value: {}", serialized);
    let enigma =  Ersa::try_from(serialized)?;
    // TODO: Repeated: copied from ersa_input()
    if enigma.is_encrypted() {
        info!("Already encrypted"); 
        return Ok(enigma);
    }
    if typmod == -1 { // unknown typmod 
        return Err("RECEIVE: Ersa Typmod is ambiguous.\n\
            You should cast the value as ::Text\n\
            More details in issue #4\
        https://git.softwarelibre.mx/SoftwareLibreMx/pg_enigma/issues/4\
            ".into());
    }
    enigma.encrypt(typmod)

} 

/// Ersa OUTPUT function
/// Sends Ersa to Postgres converted to `&Cstr`
#[pg_extern(stable, parallel_safe, requires = [ "shell_type" ])]
fn ersa_output(enigma: Ersa) 
-> Result<&'static CStr, Box<dyn std::error::Error + 'static>> {
	//debug2!("OUTPUT");
	debug5!("OUTPUT: {}", enigma);
    let decrypted = enigma.decrypt()?;
	let mut buffer = StringInfo::new();
    buffer.push_str(decrypted.to_string().as_str());
	//TODO try to avoid this unsafe
	let ret = unsafe { buffer.leak_cstr() };
    Ok(ret)
}

/// Ersa SEND function
#[pg_extern(stable, parallel_safe, requires = [ "shell_type" ])]
fn ersa_send(enigma: Ersa) 
-> Result<Vec<u8>, Box<dyn std::error::Error + 'static>> {
	//debug2!("SEND");
	debug5!("SEND: {}", enigma);
    let decrypted = enigma.decrypt()?;
    Ok(decrypted.to_string().into_bytes())
}


/// Ersa TYPMOD_IN function.
/// converts typmod from cstring to i32
#[pg_extern(immutable, parallel_safe, requires = [ "shell_type" ])]
fn ersa_typmod_in(input: Array<&CStr>) 
-> Result<i32, Box<dyn std::error::Error + 'static>> {
	debug2!("TYPMOD_IN");
    if input.len() != 1 {
        return Err(
            "Ersa type modifier must be a single integer value".into());
    }
    let typmod = input.iter() // iterator
    .next() // Option<Item>
    .ok_or("No Item")? // Item
    .ok_or("Null item")? // &Cstr
    .to_str()? //&str
    .parse::<i32>()?; // i32
    debug1!("typmod_in({typmod})");
    if typmod < 0 {
        return Err(
            "Ersa type modifier must be a positive integer".into());
    }
    Ok(typmod)
}
*/

/**************************************************************************
*                                                                         *
*                                                                         *
*                B O I L E R P L A T E  F U N C T I O N S                 *
*                                                                         *
*                                                                         *
**************************************************************************/

/*
// TODO: #[derive(EnigmaBoilerplate)]
// Boilerplate traits for converting type to postgres internals
// Needed for the FunctionMetadata trait
unsafe impl SqlTranslatable for Ersa {
    fn argument_sql() -> Result<SqlMapping, ArgumentError> {
        // this is what the SQL type is called when used in a function argument position
        Ok(SqlMapping::As("Ersa".into()))
    }

    fn return_sql() -> Result<Returns, ReturnsError> {
        // this is what the SQL type is called when used in a function return type position
        Ok(Returns::One(SqlMapping::As("Ersa".into())))
    }
}


unsafe impl<'fcx> ArgAbi<'fcx> for Ersa
where
    Self: 'fcx,
{
    unsafe fn unbox_arg_unchecked(arg: ::pgrx::callconv::Arg<'_, 'fcx>) -> Self {
        unsafe { arg.unbox_arg_using_from_datum().unwrap() }
    }
}


unsafe impl BoxRet for Ersa {
    unsafe fn box_into<'fcx>(self, 
    fcinfo: &mut pgrx::callconv::FcInfo<'fcx>) 
    -> Datum<'fcx> {
        fcinfo.return_raw_datum(
           self.into_datum()
                .expect("BoxRet IntoDatum error")
        )
    }
}

impl FromDatum for Ersa {
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
        let enigma = Ersa::try_from(value).expect("Corrupted Ersa");
        //debug2!("FromDatum: Encrypted message: {:?}", enigma);
        let decrypted = enigma.decrypt()
                                .expect("FromDatum: Decrypt error");
        //debug2!("FromDatum: Decrypted message: {:?}", decrypted);
        Some(decrypted)
    }
}

impl IntoDatum for Ersa {
    fn into_datum(self) -> Option<pg_sys::Datum> {
        let value = match self {
            Self::Plain(s) => {
                debug5!("Plain value: {}", s);
                error!("Ersa is not encrypted");
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
*/

