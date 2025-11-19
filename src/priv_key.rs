use crate::common::{Decrypt,Plain};
use crate::types::enigma::Enigma;
use crate::types::enigma_pgp::Epgp;
use crate::types::enigma_rsa::Ersa;
use crate::crypt::pgp::{pgp_decrypt,pgp_sec_key_from,pgp_sec_key_id};
use crate::crypt::rsa::{rsa_decrypt/*,rsa_sec_key_from,rsa_sec_key_id*/};
use openssl::pkey::{PKey,Private};
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
                    Err("Message is not PGP encrypted.".into())
                }
            },
            PrivKey::RSA(key) => {
                debug2!("Decrypt: RSA key");
                if let Enigma::RSA(_,msg) = enigma {
                    Ok(Enigma::plain(rsa_decrypt(key, msg)?))
                } else {
                    Err("Message is not RSA encrypted.".into())
                }
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
                    Err("Message is not PGP encrypted.".into())
                }
            },
            _ => Err("Key is not PGP".into())
        }
    }
}

impl Decrypt<Ersa> for PrivKey {
    fn decrypt(&self, enigma: Ersa) 
    -> Result<Ersa, Box<dyn std::error::Error + 'static>> {
        if enigma.is_plain() { 
             return Err("Already decrypted message".into());
        }

        match self {
            PrivKey::RSA(key) => {
                debug2!("Decrypt: RSA key");
                if let Ersa::RSA(_,msg) = enigma {
                    Ok(Ersa::plain(rsa_decrypt(key, msg)?))
                } else {
                    Err("Message is not RSA encrypted.".into())
                }
            },
            _ => Err("Key is not RSA".into())
        }
    }
}


