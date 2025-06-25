use crate::EnigmaMsg;
use crate::traits::Decrypt;
use lazy_static::lazy_static;
use openssl::base64::decode_block;
use openssl::encrypt::Decrypter;
use openssl::pkey::{PKey,Private};
use openssl::rsa::Padding;
use pgp::{Deserializable,Message,SignedSecretKey};
use pgp::types::PublicKeyTrait;
use regex::bytes::Regex;
use std::io::Cursor;

pub enum PrivKey {
    /// PGP secret key
    PGP(SignedSecretKey, String),
    /// OpenSSL RSA
    RSA(PKey<Private>)
}

impl PrivKey {
    /// Creates a `PrivKey` struct with the key obtained
    /// from the `armored key` and the provided plain text password
    pub fn new(armored_key: &str, pw: &str) 
    -> Result<Self, Box<(dyn std::error::Error + 'static)>> {
        // TODO: From<String>
        lazy_static! {
            static ref RE_PGP: Regex = 
                Regex::new(r"BEGIN PGP PRIVATE KEY BLOCK")
                .expect("failed to compile PGP key regex");
            static ref RE_RSA: Regex = 
                Regex::new(r"BEGIN ENCRYPTED PRIVATE KEY")
                .expect("failed to compile OpenSSL RSA key regex");
        }
        if RE_PGP.captures(armored_key.as_bytes()).is_some() {
            // https://docs.rs/pgp/latest/pgp/composed/trait.Deserializable.html#method.from_string
            let (sec_key, _) = SignedSecretKey::from_string(armored_key)?;
            sec_key.verify()?;
            Ok(PrivKey::PGP(sec_key, pw.to_string()))
        } else if RE_RSA.captures(armored_key.as_bytes()).is_some() {
            let priv_key = 
                PKey::<Private>::private_key_from_pem_passphrase(
                    armored_key.as_bytes(), pw.as_bytes())?;
           Ok(PrivKey::RSA(priv_key))
        } else {
            Err("key type not supported".into())
        }
    }

    pub fn key_id(&self) -> String {
        match self {
            PrivKey::PGP(k,_) => format!("{:?}", k.key_id()),
            PrivKey::RSA(k) => format!("{:?}", k.id())
        }
    }
}

impl Decrypt<EnigmaMsg> for PrivKey {
    fn decrypt(&self, msg: EnigmaMsg) 
    -> Result<EnigmaMsg, Box<(dyn std::error::Error + 'static)>> {
        match self {
            PrivKey::PGP(key,pass) => {
                decrypt_pgp(key, pass.clone(), msg)
            },
            PrivKey::RSA(pkey) => {
                decrypt_rsa(pkey, msg)
            }
        }
    }
}

impl Decrypt<String> for PrivKey {
    fn decrypt(&self, message: String) 
    -> Result<String, Box<(dyn std::error::Error + 'static)>> {
        match self {
            PrivKey::PGP(key,pass) => {
                decrypt_pgp_string(key, pass.clone(), message)
            },
            PrivKey::RSA(pkey) => {
                decrypt_rsa_string(pkey, message)
            }
        }
    }
}

/*********************
 * PRIVATE FUNCTIONS *
 * *******************/

fn decrypt_pgp(key: &SignedSecretKey, pass: String, message: EnigmaMsg)
-> Result<EnigmaMsg, Box<(dyn std::error::Error + 'static)>> {
    if let EnigmaMsg::PGP(msg) = message {
        let (decrypted, _) = msg.decrypt(|| pass.to_string(), &[&key])?;
        // TODO: Should `expect()` instead of `unwrap()`
        let bytes = decrypted.get_content()?.ok_or("No content")?;
        let clear_text = String::from_utf8(bytes)?;
        return Ok(EnigmaMsg::plain(clear_text));
    }
    Err("Wrong key. Message is not PGP.".into())
}

fn decrypt_pgp_string(key: &SignedSecretKey, pass: String, message: String)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    let buf = Cursor::new(message);
    let (msg, _) = Message::from_armor_single(buf)?;
    Ok(decrypt_pgp(key, pass, EnigmaMsg::pgp(msg))?.to_string())
}

fn decrypt_rsa(key: &PKey<Private>, message: EnigmaMsg)
-> Result<EnigmaMsg, Box<(dyn std::error::Error + 'static)>> {
    if ! message.is_rsa() { 
        return Err("Wrong key. Message is not RSA encrypted.".into());
    }
    Ok(EnigmaMsg::plain(decrypt_rsa_string(key, message.to_string())?))
}

fn decrypt_rsa_string(pkey: &PKey<Private>, message: String)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    let input = decode_block(message.as_str())?;
    let mut decrypter = Decrypter::new(&pkey)?;
    decrypter.set_rsa_padding(Padding::PKCS1)?;
    // Get the length of the output buffer
    let buffer_len = decrypter.decrypt_len(&input)?;
    let mut decoded = vec![0u8; buffer_len];
    // Decrypt the data and get its length
    let decoded_len = decrypter.decrypt(&input, &mut decoded)?;
    // Use only the part of the buffer with the decrypted data
    let decoded = &decoded[..decoded_len];
    let clear_text = String::from_utf8(decoded.to_vec())?;
    Ok(clear_text)
}


