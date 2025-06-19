use crate::Enigma;
use pgp::Deserializable;
use pgp::Esk::PublicKeyEncryptedSessionKey;
use pgp::Message;
use pgp::types::KeyId;
use pgrx::debug1;
use std::io::Cursor;

const PGP_BEGIN: &str = "-----BEGIN PGP MESSAGE-----\n";
const PGP_END: &str = "-----END PGP MESSAGE-----\n";
const PLAIN_BEGIN: &str = "BEGIN PLAIN=====>";
const PLAIN_END: &str = "<=====END PLAIN";
// TODO: Enigma RSA envelope

pub enum EnigmaMsg {
    /// PGP message
    PGP(pgp::Message),
    /// OpenSSL RSA encrypted message
    RSA(Vec<u8>,u64), // TODO: refactor
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
