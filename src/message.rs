use crate::Enigma;
use pgp::Deserializable;
use pgp::Message;
use pgrx::{debug2};
use std::fmt::{Display, Formatter};
use std::io::Cursor;

//const PLAIN_BEGIN: &str = "-----BEGIN PLAIN NOT ENCRYPTED MESSAGE-----\n";
//const PLAIN_END: &str = "\n-----END PLAIN NOT ENCRYPTED MESSAGE-----";
const PGP_BEGIN: &str = "-----BEGIN PGP MESSAGE-----\n";
const PGP_END: &str = "-----END PGP MESSAGE-----\n";
const RSA_BEGIN: &str = "-----BEGIN RSA ENCRYPTED-----\n";
const RSA_END: &str = "\n-----END RSA ENCRYPTED-----";
const ENIGMA_TAG: &str = "ENIGMAv1"; // 0x454E49474D417631
const ENIGMA_INT: u64  = 0x454E49474D417631; // "ENIGMAv1"
const PLAIN_TAG: &str  = "PLAINMSG"; // 0x504C41494E4D5347
const PLAIN_INT: u64   = 0x504C41494E4D5347; // "PLAINMSG"
const SEPARATOR: char = '\n';

// TODO: KEY ID in envelope header
#[derive( Clone, Debug)]
pub enum EnigmaMsg {
    /// PGP message
    PGP(u32,pgp::Message),
    /// OpenSSL RSA encrypted message
    RSA(u32,String), 
    /// Plain unencrypted message
    Plain(String)
}


impl TryFrom<String> for EnigmaMsg {
    type Error = Box<(dyn std::error::Error + 'static)>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if let Some((header, payload)) = value.split_once(SEPARATOR) {
            let (tag,key_id) = split_hdr(header)?;

            if tag == PLAIN_INT {
                debug2!{"Plain payload: {payload}"}
                return Ok(Self::plain(payload.to_string()));
            }

            if tag == ENIGMA_INT {
                if payload.starts_with(PGP_BEGIN) 
                && payload.ends_with(PGP_END) {
                    return try_from_pgp_armor(key_id, payload);
                }

                if payload.starts_with(RSA_BEGIN)
                && payload.ends_with(RSA_END) {
                    return Ok(from_rsa_envelope(key_id, payload));
                }
            }
        }

        //debug5!("Unmatched: {value}");
        //unreachable!("Use EnigmaMsg::plain() instead");
        // FromDatum removes PLAIN_BEGIN and PLAIN_END before enigma_cast()
        Ok(Self::plain(value))
    }
} 

impl TryFrom<&String> for EnigmaMsg {
    type Error = Box<(dyn std::error::Error + 'static)>;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Self::try_from(value.clone())
    }
}

impl TryFrom<Enigma> for EnigmaMsg {
    type Error = Box<(dyn std::error::Error + 'static)>;

    fn try_from(enigma: Enigma) -> Result<Self, Self::Error> {
        Self::try_from(enigma.value)
    }
}

impl From<EnigmaMsg> for Enigma {
    fn from(msg: EnigmaMsg) -> Self {
        let value = match msg {
            EnigmaMsg::PGP(key,m) => {
                let msg = m.to_armored_string(None.into())
                            .expect("PGP armor");
                format!("{}{:08X}{}{}", ENIGMA_TAG, key, SEPARATOR, msg)
            },
            EnigmaMsg::RSA(key,msg) => {
                format!("{}{:08X}{}{}{}{}",
                    ENIGMA_TAG, key, SEPARATOR, RSA_BEGIN, msg, RSA_END)
            },
            EnigmaMsg::Plain(s) => {
                format!("{}{:08X}{}{}", PLAIN_TAG, 0, SEPARATOR, s)
            }
        };
        Enigma{ value: value }
    }
}

impl Display for EnigmaMsg {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PGP(id,m) => {
                debug2!("PGP({id},message)");
                let armored = m.to_armored_string(None.into())
                    .expect("PGP error");
                let out = armored.trim_start_matches(PGP_BEGIN)
                    .trim_end_matches(PGP_END);
                write!(f, "{}", out)
            },
            Self::RSA(id,m) => {
                debug2!("RSA({id},message)");
                write!(f, "{}", m)
            },
            Self::Plain(s) => {
                debug2!("Plain(message)");
                write!(f, "{}", s)
            }
        }
    }
}

impl EnigmaMsg {
    pub fn plain(value: String) -> Self {
        Self::Plain(value)
    }

    pub fn pgp(id: i32, value: pgp::Message) -> Self {
        // TODO: u32 key_id
        Self::PGP(id as u32, value)
    }

    pub fn rsa(id: i32, value: String) -> Self {
        // TODO: u32 key_id
        Self::RSA(id as u32, value)
    }

    pub fn is_encrypted(&self) -> bool {
        !self.is_plain()
    }

    #[allow(dead_code)]
    pub fn is_pgp(&self) -> bool {
        matches!(*self, Self::PGP(_,_))
    }

    pub fn is_rsa(&self) -> bool {
        matches!(*self, Self::RSA(_,_))
    }

    pub fn is_plain(&self) -> bool {
        matches!(*self, Self::Plain(_))
    }

    pub fn key_id(&self) -> Option<i32> {
        match self {
            // TODO: u32 key_id
            Self::RSA(k,_) => Some(*k as i32),
            // TODO: u32 key_id
            Self::PGP(k,_) => Some(*k as i32),
            Self::Plain(_) => None
        }
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

#[allow(dead_code)]
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
-> Result<EnigmaMsg, Box<(dyn std::error::Error + 'static)>> {
    let buf = Cursor::new(value);
    let (msg, _) = Message::from_armor_single(buf)?;
    Ok(EnigmaMsg::PGP(key_id, msg))
}

fn from_rsa_envelope(key_id: u32, value: &str) -> EnigmaMsg {
    EnigmaMsg::RSA(key_id, value
        .trim_start_matches(RSA_BEGIN)
        .trim_end_matches(RSA_END)
        .to_string() )
}


