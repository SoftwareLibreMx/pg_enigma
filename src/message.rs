use crate::Enigma;
use pgp::Deserializable;
use pgp::Message;
use std::io::Cursor;

const PGP_BEGIN: &str = "-----BEGIN PGP MESSAGE-----";
const PGP_END: &str = "-----END PGP MESSAGE-----";
const PLAIN_BEGIN: &str = "BEGIN PLAIN=====>";
const PLAIN_END: &str = "<=====END PLAIN";
// TODO: Enigma RSA envelope

pub enum EnigmaMessage {
    /// PGP message
    PGP(pgp::Message),
    /// OpenSSL RSA encrypted
    RSA(Vec<u8>), // TODO: refactor
    /// Plain unencrypted message
    PLAIN(String)
}

impl TryFrom<String> for EnigmaMessage {
    type Error = Box<(dyn std::error::Error + 'static)>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value.starts_with(PLAIN_BEGIN)
        && value.ends_with(PLAIN_END) {
            return Ok(from_plain_envelope(value));
        }

        if value.starts_with(PGP_BEGIN)
        && value.ends_with(PGP_END) {
            return try_from_pgp_armor(value);
        }

        // TODO: RSA envelope

        Err("Not an Enigma message".into())
    }
}

impl TryFrom<Enigma> for EnigmaMessage {
    type Error = Box<(dyn std::error::Error + 'static)>;

    fn try_from(enigma: Enigma) -> Result<Self, Self::Error> {
        Self::try_from(enigma.value)
    }
}


/*********************
 * PRIVATE FUNCTIONS *
 * *******************/

fn try_from_pgp_armor(value: String) 
-> Result<EnigmaMessage, Box<(dyn std::error::Error + 'static)>> {
    let buf = Cursor::new(value);
    let (msg, _) = Message::from_armor_single(buf)?;
    Ok(EnigmaMessage::PGP(msg))
}

fn from_plain_envelope(value: String) -> EnigmaMessage {
    EnigmaMessage::PLAIN(value
        .trim_start_matches(PLAIN_BEGIN)
        .trim_end_matches(PLAIN_END)
        .to_string() )
}
