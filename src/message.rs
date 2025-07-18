use crate::Enigma;
use pgp::Deserializable;
use pgp::Message;
use pgrx::{debug2};
use std::fmt::{Display, Formatter};
use std::io::Cursor;

const PLAIN_BEGIN: &str = "-----BEGIN PLAIN NOT ENCRYPTED MESSAGE-----\n";
const PLAIN_END: &str = "\n-----END PLAIN NOT ENCRYPTED MESSAGE-----";
const PGP_BEGIN: &str = "-----BEGIN PGP MESSAGE-----\n";
const PGP_END: &str = "-----END PGP MESSAGE-----\n";
const RSA_BEGIN: &str = "-----BEGIN RSA ENCRYPTED-----\n";
const RSA_END: &str = "\n-----END RSA ENCRYPTED-----";
const KEY_TAG: &str = "KEY:";
const SEPARATOR: &str = "\n";

// TODO: KEY ID in envelope header
#[derive( Clone, Debug)]
pub enum EnigmaMsg {
    /// PGP message
    PGP(i32,pgp::Message),
    /// OpenSSL RSA encrypted message
    RSA(i32,String), 
    /// Plain unencrypted message
    Plain(String)
}


impl TryFrom<String> for EnigmaMsg {
    type Error = Box<(dyn std::error::Error + 'static)>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.starts_with(PLAIN_BEGIN)
        && value.ends_with(PLAIN_END) {
            debug2!{"Plain value: {value}"}
            return Ok(from_plain_envelope(value));
        }

        if value.starts_with(KEY_TAG) {
            let (key_hdr, encrypted) = value
                                    .split_once(SEPARATOR)
                                    .ok_or("Malformed Enigma envelope")?;
            let key_id = try_key_id_from(key_hdr)?;

            if encrypted.starts_with(PGP_BEGIN) 
            && encrypted.ends_with(PGP_END) {
                return try_from_pgp_armor(key_id, encrypted);
            }

            if encrypted.starts_with(RSA_BEGIN)
            && encrypted.ends_with(RSA_END) {
                return Ok(from_rsa_envelope(key_id, encrypted));
            }
        }

        debug2!("Unmatched: {value}");
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
                format!("{}{}{}{}", KEY_TAG, key, SEPARATOR, msg)
            },
            EnigmaMsg::RSA(key,msg) => {
                format!("{}{}{}{}{}{}",
                    KEY_TAG, key, SEPARATOR, RSA_BEGIN, msg, RSA_END)
            },
            EnigmaMsg::Plain(s) => {
                format!("{}{}{}", PLAIN_BEGIN, s, PLAIN_END)
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
        Self::PGP(id, value)
    }

    pub fn rsa(id: i32, value: String) -> Self {
        Self::RSA(id, value)
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
            Self::RSA(k,_) => Some(*k),
            Self::PGP(k,_) => Some(*k),
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

/*********************
 * PRIVATE FUNCTIONS *
 * *******************/

fn try_key_id_from(key_hdr: &str)
-> Result<i32, Box<(dyn std::error::Error + 'static)>> {
    //key_hdr.trim_start_matches(KEY_TAG).parse::<i32>()
    Ok(key_hdr.trim_start_matches(KEY_TAG).parse()?)
}

fn try_from_pgp_armor(key_id: i32, value: &str) 
-> Result<EnigmaMsg, Box<(dyn std::error::Error + 'static)>> {
    let buf = Cursor::new(value);
    let (msg, _) = Message::from_armor_single(buf)?;
    Ok(EnigmaMsg::PGP(key_id, msg))
}

fn from_rsa_envelope(key_id: i32, value: &str) -> EnigmaMsg {
    EnigmaMsg::RSA(key_id, value
        .trim_start_matches(RSA_BEGIN)
        .trim_end_matches(RSA_END)
        .to_string() )
}

fn from_plain_envelope(value: String) -> EnigmaMsg {
    EnigmaMsg::Plain(value
        .trim_start_matches(PLAIN_BEGIN)
        .trim_end_matches(PLAIN_END)
        .to_string() )
}


