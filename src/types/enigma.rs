use core::ffi::CStr;
use crate::common::*;
use crate::{PRIV_KEYS,PUB_KEYS};
use crate::crypt::openssl::*;
use crate::crypt::pgp::*;
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
use super::enigma_pgp::{E_PGP_INT,E_PGP_TAG,Epgp};
use super::enigma_rsa::{E_RSA_INT,E_RSA_TAG,Ersa};
use super::legacy::{ENIGMA_INT,Legacy};

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
            if let Ok(Header{tag,..}) = Header::try_from(header) {
                match tag {
                    PLAIN_INT => {
                        debug2!{"Plain unencrypted message"}
                        debug5!{"Payload: {payload}"}
                        return Ok(Self::plain(payload.to_string()));
                    },
                    E_PGP_INT => {
                        debug2!("PGP encrypted message");
                        return Ok(Self::from(Epgp::try_from(value)?));
                    },
                    E_RSA_INT => {
                        debug2!("RSA encrypted message");
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

// TODO: #[derive(EnigmaTryFrom)]
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

impl From<Epgp> for Enigma {
    fn from(value: Epgp) -> Self {
        match value {
            Epgp::PGP(key,msg) => Self::PGP(key,msg),
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
            Legacy::PGP(key,msg) => Self::PGP(key,msg),
            Legacy::RSA(key,msg) => Self::RSA(key,msg),
            Legacy::Plain(msg) => Self::Plain(msg),
        }
    }
}

impl Display for Enigma {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Enigma::PGP(key,msg) => {
                // Use new Epgp header
                write!(f, "{}{:08X}{}{}", 
                E_PGP_TAG, key, SEPARATOR, msg)
            },
            Enigma::RSA(key,msg) => {
                // Use new Ersa header
                write!(f, "{}{:08X}{}{}", 
                E_RSA_TAG, key, SEPARATOR, msg)
            },
            Enigma::Plain(s) => {
                write!(f, "{}", s)
            }
        }        
    }
}

// TODO: #[derive(EnigmaPlain)]
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
        Self::PGP(id, pgp_trim_envelope(value))
    }

    pub fn rsa(id: u32, value: String) -> Self {
        Self::RSA(id, rsa_trim_envelope(value))
    }

    #[allow(unused)]
    pub fn is_pgp(&self) -> bool {
        matches!(*self, Self::PGP(_,_))
    }

    #[allow(unused)]
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

    #[allow(unused)]
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

/**********************
 * POSTGRES FUNCTIONS *
 * ********************/

/// Functions for extracting and inserting data
#[pg_extern(stable, parallel_safe, requires = [ "shell_type" ])]
fn enigma_input(input: &CStr, oid: pg_sys::Oid, typmod: i32) 
-> Result<Enigma, Box<dyn std::error::Error + 'static>> {
	//debug2!("INPUT: OID: {:?},  Typmod: {}", oid, typmod);
	debug5!("INPUT: ARGUMENTS: \
            Input: {:?}, OID: {:?},  Typmod: {}", input, oid, typmod);
    let enigma =  Enigma::try_from(input)?;
    if enigma.is_encrypted() {
        info!("Already encrypted"); 
        return Ok(enigma);
    }
    if typmod == -1 { // unknown typmod 
        //debug1!("Unknown typmod: {typmod}");
        return Err("INPUT: Enigma Typmod is ambiguous.\n\
            You should cast the value as ::Text\n\
            More details in issue #4 \
        https://git.softwarelibre.mx/SoftwareLibreMx/pg_enigma/issues/4\
            ".into());
    }
    enigma.encrypt(typmod)
}

/// Assignment cast is called before the INPUT function.
#[pg_extern]
fn string_as_enigma(original: String, typmod: i32, explicit: bool) 
-> Result<Enigma, Box<dyn std::error::Error + 'static>> {
    debug2!("string_as_enigma: \
        ARGUMENTS: explicit: {},  Typmod: {}", explicit, typmod);
    let key_id = match typmod {
        -1 => { debug1!("Unknown typmod; using default key ID 0");
            0 },
        _ => typmod
    };
    Enigma::try_from(original)?.encrypt(key_id)
}

/*
#[pg_extern]
fn str_as_enigma<'fcx>(original: &'fcx str, typmod: i32, explicit: bool) 
-> Enigma {
    debug2!("str_as_enigma: \
        ARGUMENTS: explicit: {},  Typmod: {}", explicit, typmod);
    if typmod == -1 {
        panic!("Unknown typmod: {}\noriginal: {:?}\nexplicit: {}", 
            typmod, original, explicit);
    }
    
    let value = String::from(original);
    Enigma::try_from((typmod,value)).expect("ASSIGNMENT CAST: &str")
}

#[pg_extern]
fn u8_as_enigma<'fcx>(original: &'fcx [u8], typmod: i32, explicit: bool) 
-> Enigma {
    debug2!("u8_as_enigma: \
        ARGUMENTS: explicit: {},  Typmod: {}", explicit, typmod);
    if typmod == -1 {
        panic!("Unknown typmod: {}\noriginal: {:?}\nexplicit: {}", 
            typmod, original, explicit);
    }
    
    let value = String::from_utf8(original.to_vec()).expect("from_utf8");
    Enigma::try_from((typmod,value)).expect("ASSIGNMENT CAST: &[u8]")
}
*/

/// Cast enigma to enigma is called after enigma_input_with_typmod(). 
/// This function is passed the correct known typmod argument.
#[pg_extern(stable, parallel_safe)]
fn enigma_as_enigma(original: Enigma, typmod: i32, explicit: bool) 
-> Result<Enigma, Box<dyn std::error::Error + 'static>> {
    debug2!("CAST(Enigma AS Enigma): \
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

/// Enigma RECEIVE function
#[pg_extern(stable, parallel_safe, requires = [ "shell_type" ])]
fn enigma_receive(mut internal: Internal, oid: pg_sys::Oid, typmod: i32) 
-> Result<Enigma, Box<dyn std::error::Error + 'static>> {
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
    let enigma =  Enigma::try_from(serialized)?;
    // TODO: Repeated: copied from enigma_input()
    if enigma.is_encrypted() {
        info!("Already encrypted"); 
        return Ok(enigma);
    }
    if typmod == -1 { // unknown typmod 
        return Err("RECEIVE: Enigma Typmod is ambiguous.\n\
            You should cast the value as ::Text\n\
            More details in issue #4\
        https://git.softwarelibre.mx/SoftwareLibreMx/pg_enigma/issues/4\
            ".into());
    }
    enigma.encrypt(typmod)

} 

/// Enigma OUTPUT function
/// Sends Enigma to Postgres converted to `&Cstr`
#[pg_extern(stable, parallel_safe, requires = [ "shell_type" ])]
fn enigma_output(enigma: Enigma) 
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

/// Enigma SEND function
#[pg_extern(stable, parallel_safe, requires = [ "shell_type" ])]
fn enigma_send(enigma: Enigma) 
-> Result<Vec<u8>, Box<dyn std::error::Error + 'static>> {
	//debug2!("SEND");
	debug5!("SEND: {}", enigma);
    let decrypted = enigma.decrypt()?;
    Ok(decrypted.to_string().into_bytes())
}


/// Enigma TYPMOD_IN function.
/// converts typmod from cstring to i32
#[pg_extern(immutable, parallel_safe, requires = [ "shell_type" ])]
fn enigma_typmod_in(input: Array<&CStr>) 
-> Result<i32, Box<dyn std::error::Error + 'static>> {
	debug2!("TYPMOD_IN");
    if input.len() != 1 {
        return Err(
            "Enigma type modifier must be a single integer value".into());
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
            "Enigma type modifier must be a positive integer".into());
    }
    Ok(typmod)
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
unsafe impl SqlTranslatable for Enigma {
    fn argument_sql() -> Result<SqlMapping, ArgumentError> {
        // this is what the SQL type is called when used in a function argument position
        Ok(SqlMapping::As("Enigma".into()))
    }

    fn return_sql() -> Result<Returns, ReturnsError> {
        // this is what the SQL type is called when used in a function return type position
        Ok(Returns::One(SqlMapping::As("Enigma".into())))
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
        let value = match self {
            Self::Plain(s) => {
                //format!("{}{:08X}{}{}", PLAIN_TAG, 0, SEPARATOR, s)
                debug5!("Plain value: {}", s);
                error!("Enigma is not encrypted");
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


