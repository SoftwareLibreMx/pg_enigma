use crate::common::{Decrypt,Plain};
use crate::enigma::Enigma;
use crate::enigma_pgp::Epgp;
use crate::pgp::{pgp_decrypt,pgp_sec_key_from,pgp_sec_key_id};
use openssl::base64::decode_block;
use openssl::encrypt::Decrypter;
use openssl::pkey::{PKey,Private};
use openssl::rsa::Padding;
use pgp::composed::SignedSecretKey;
use pgrx::debug2;

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
        if let Ok(sec_key) = pgp_sec_key_from(armored) {
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
            PrivKey::PGP(k,_) => pgp_sec_key_id(k),
            PrivKey::RSA(k) => format!("{:?}", k.id())
        }
    }
}

impl Decrypt<Enigma> for PrivKey {
    fn decrypt(&self, enigma: Enigma) 
    -> Result<Enigma, Box<dyn std::error::Error + 'static>> {
        if enigma.is_plain() { 
             return Err("Already decrypted message".into());
        }

        match self {
            PrivKey::PGP(key,pass) => {
                debug2!("Decrypt: PGP key");
                if let Enigma::PGP(_,msg) = enigma {
                    Ok(Enigma::plain(pgp_decrypt(key, pass.clone(), msg)?))
                } else {
                    Err("Wrong key. Message is not PGP.".into())
                }
            },
            PrivKey::RSA(pkey) => {
                debug2!("Decrypt: RSA key");
                decrypt_rsa(pkey, enigma)
            }
        }
    }
}

impl Decrypt<Epgp> for PrivKey {
    fn decrypt(&self, enigma: Epgp) 
    -> Result<Epgp, Box<dyn std::error::Error + 'static>> {
        if enigma.is_plain() { 
             return Err("Already decrypted message".into());
        }

        match self {
            PrivKey::PGP(key,pass) => {
                debug2!("Decrypt: PGP key");
                if let Epgp::PGP(_,msg) = enigma {
                    Ok(Epgp::plain(pgp_decrypt(key, pass.clone(), msg)?))
                } else {
                    Err("Wrong key. Message is not PGP.".into())
                }
            },
            _ => Err("Key is not PGP".into())
        }
    }
}

/*********************
 * PRIVATE FUNCTIONS *
 * *******************/


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

