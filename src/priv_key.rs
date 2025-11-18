use crate::common::Plain;
use crate::enigma::Enigma;
use hex::ToHex;
use openssl::base64::decode_block;
use openssl::encrypt::Decrypter;
use openssl::pkey::{PKey,Private};
use openssl::rsa::Padding;
use pgp::composed::{Deserializable,Message,SignedSecretKey};
use pgp::types::{KeyDetails,Password};
use pgrx::debug2;
use std::io::Cursor;

const PGP_BEGIN: &str = "-----BEGIN PGP MESSAGE-----\n";
const PGP_END: &str = "-----END PGP MESSAGE-----\n";
const PGPKEY_BEGIN: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
const PGPKEY_END: &str = "-----END PGP PRIVATE KEY BLOCK-----";
// TODO:  Other OpenSSL supported key types (elyptic curves, etc.)
const SSL_BEGIN: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
const SSL_END: &str = "-----END ENCRYPTED PRIVATE KEY-----";

pub enum PrivKey {
    /// PGP secret key
    PGP(SignedSecretKey, String),
    /// OpenSSL RSA
    RSA(PKey<Private>)
}

impl PrivKey {
    /// Creates a `PrivKey` struct with the key obtained
    /// from the `armored key` and the provided plain text password
    pub fn new(armored: &str, pw: &str) 
    -> Result<Self, Box<dyn std::error::Error + 'static>> {
        if armored.contains(PGPKEY_BEGIN) && armored.contains(PGPKEY_END) {
            // https://docs.rs/pgp/latest/pgp/composed/trait.Deserializable.html#method.from_string
            let (sec_key, _) = SignedSecretKey::from_string(armored)?;
            sec_key.verify()?;
            return Ok(PrivKey::PGP(sec_key, pw.to_string()));
        }

        if armored.contains(SSL_BEGIN) && armored.contains(SSL_END) {
            let priv_key = 
                PKey::<Private>::private_key_from_pem_passphrase(
                    armored.as_bytes(), pw.as_bytes())?;
           return Ok(PrivKey::RSA(priv_key));
        } 

        Err("key not recognized".into())
    }

    pub fn priv_key_id(&self) -> String {
        match self {
            PrivKey::PGP(k,_) => k.key_id().encode_hex(),
            PrivKey::RSA(k) => format!("{:?}", k.id())
        }
    }

    pub fn decrypt(&self, msg: Enigma) 
    -> Result<Enigma, Box<dyn std::error::Error + 'static>> {
        match self {
            PrivKey::PGP(key,pass) => {
                debug2!("Decrypt: PGP key");
                decrypt_pgp(key, pass.clone(), msg)
            },
            PrivKey::RSA(pkey) => {
                debug2!("Decrypt: RSA key");
                decrypt_rsa(pkey, msg)
            }
        }
    }
}


/*********************
 * PRIVATE FUNCTIONS *
 * *******************/

fn decrypt_pgp(key: &SignedSecretKey, pass: String, enigma: Enigma)
-> Result<Enigma, Box<dyn std::error::Error + 'static>> {
    if let Enigma::PGP(_,message) = enigma {
        debug2!("Decrypt: PGP Enigma: {message}");
        let buf = Cursor::new(format!("{}{}{}",PGP_BEGIN,message,PGP_END));
        let (msg, _) = Message::from_armor(buf)?;
        let pw = Password::from(pass);
        let mut decrypted = msg.decrypt(&pw, key)?;
        let clear_text = decrypted.as_data_string()?;
        return Ok(Enigma::plain(clear_text));
    }
    Err("Wrong key. Message is not PGP.".into())
}


fn decrypt_rsa(key: &PKey<Private>, enigma: Enigma)
-> Result<Enigma, Box<dyn std::error::Error + 'static>> {
    if let Enigma::RSA(_,message) = enigma {
        debug2!("Decrypt: RSA Enigma: {message}");
        let input = decode_block(message.as_str())?;
        let mut decrypter = Decrypter::new(key)?;
        decrypter.set_rsa_padding(Padding::PKCS1)?;
        // Get the length of the output buffer
        let buffer_len = decrypter.decrypt_len(&input)?;
        let mut decoded = vec![0u8; buffer_len];
        // Decrypt the data and get its length
        let decoded_len = decrypter.decrypt(&input, &mut decoded)?;
        // Use only the part of the buffer with the decrypted data
        let decoded = &decoded[..decoded_len];
        let clear_text = String::from_utf8(decoded.to_vec())?;
        Ok(Enigma::plain(clear_text))
    } else {
        Err("Wrong key. Message is not RSA encrypted.".into())
    }
}

