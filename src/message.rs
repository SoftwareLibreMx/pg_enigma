use crate::Enigma;
use pgp::Deserializable;
use pgp::Esk::PublicKeyEncryptedSessionKey;
use pgp::Message;
use pgp::types::KeyId;
use pgrx::debug1;
use std::fmt::{Display, Formatter};
use std::io::Cursor;

const PGP_BEGIN: &str = "-----BEGIN PGP MESSAGE-----\n";
const PGP_END: &str = "-----END PGP MESSAGE-----\n";
const RSA_BEGIN: &str = "-----BEGIN RSA ENCRYPTED-----\n";
const RSA_END: &str = "-----END RSA ENCRYPTED-----\n";
const RSA_KEY: &str = "-----RSA KEY ID ";
const PLAIN_BEGIN: &str = "BEGIN PLAIN=====>";
const PLAIN_END: &str = "<=====END PLAIN";

pub enum EnigmaMsg {
    /// PGP message
    PGP(pgp::Message),
    /// OpenSSL RSA encrypted message
    RSA(String,u64), // TODO: refactor
    /// Plain unencrypted message
    Plain(String)
}


/*
impl From<String> for EnigmaMsg {
    fn from(value: String) -> Self {
        let value = enigma.value.clone();
        
        if value.starts_with(PLAIN_BEGIN)
        && value.ends_with(PLAIN_END) {
            return from_plain_envelope(value);
        }

        if value.starts_with(PGP_BEGIN)
        && value.ends_with(PGP_END) {
            if let Ok(pgp_msg) = try_from_pgp_armor(value) {
                 return pgp_msg;
            }
        }

        // TODO: RSA envelope

        EnigmaMsg::Plain(value)
    }
}

impl From<Enigma> for EnigmaMsg {
    fn from(enigma: Enigma) -> Self {
        Self::from(enigma.value)
    }
}
*/

impl TryFrom<String> for EnigmaMsg {
    type Error = Box<(dyn std::error::Error + 'static)>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.starts_with(PLAIN_BEGIN)
        && value.ends_with(PLAIN_END) {
            return Ok(from_plain_envelope(value));
        }

        if value.starts_with(PGP_BEGIN)
        && value.ends_with(PGP_END) {
            return try_from_pgp_armor(value); // Result
        }

        // TODO: RSA envelope

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
    fn from(msg: EnigmaMsg) -> Enigma {
        let value: String;
        match msg {
            EnigmaMsg::PGP(m) => {
                value = m.to_armored_string(None.into())
                    .expect("PGP error")
                    .trim_start_matches(PGP_BEGIN)
                    .trim_end_matches(PGP_END)
                    .to_string();
            },
            EnigmaMsg::RSA(msg,k) => {
                value = format!("{}{}{}\n{}{}", 
                    RSA_BEGIN, RSA_KEY, k, msg, RSA_END);
            },
            EnigmaMsg::Plain(s) => {
                value = format!("{}{}{}",PLAIN_BEGIN, s ,PLAIN_END);
            }
        }
        Enigma{ value: value }
    }
}

impl Display for EnigmaMsg {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PGP(m) => {
                let armored = m.to_armored_string(None.into())
                    .expect("PGP error");

                let out = armored.trim_start_matches(PGP_BEGIN)
                    .trim_end_matches(PGP_END);
                write!(f, "{}", out)
            },
            Self::RSA(m,_) => {
                write!(f, "{}", m)
            },
            Self::Plain(s) => {
                write!(f, "{}", s)
            }
        }
    }
}

impl EnigmaMsg {
    pub fn plain(value: String) -> Self {
        Self::Plain(value)
    }

    pub fn is_encrypted(&self) -> bool {
        !self.is_plain()
    }

    pub fn is_pgp(&self) -> bool {
        matches!(*self, Self::PGP(_))
    }

    pub fn is_rsa(&self) -> bool {
        matches!(*self, Self::RSA(_,_))
    }

    pub fn is_plain(&self) -> bool {
        matches!(*self, Self::Plain(_))
    }

    pub fn encrypting_keys(&self)
    -> Result<Vec<KeyId>, Box<(dyn std::error::Error + 'static)>> {
        let mut keys = Vec::new();
        if let Self::PGP(pgp::Message::Encrypted{ esk, .. }) = self {
            for each_esk in esk {
                if let PublicKeyEncryptedSessionKey(skey) = each_esk {
                    let skey_id = skey.id()?;
                    debug1!("Encrypting key: {:?}", skey_id);
                    keys.push(skey_id.clone());
                }
            }
        }
        Ok(keys)
    }

    pub fn encrypting_key(&self)
    -> Result<KeyId, Box<(dyn std::error::Error + 'static)>> {
        let mut keys = self.encrypting_keys()?;
        if keys.len() > 1 {
            return Err("More than one encrypting key".into());
        }
        keys.pop().ok_or("No encrypting key found".into())
    }
}

/*********************
 * PRIVATE FUNCTIONS *
 * *******************/

fn try_from_pgp_armor(value: String) 
-> Result<EnigmaMsg, Box<(dyn std::error::Error + 'static)>> {
    let buf = Cursor::new(value);
    let (msg, _) = Message::from_armor_single(buf)?;
    Ok(EnigmaMsg::PGP(msg))
}

fn from_plain_envelope(value: String) -> EnigmaMsg {
    EnigmaMsg::Plain(value
        .trim_start_matches(PLAIN_BEGIN)
        .trim_end_matches(PLAIN_END)
        .to_string() )
}
