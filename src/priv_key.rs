use crate::common::{Decrypt,Plain};
use crate::crypt::pgp;
use crate::types::enigma::Enigma;
use crate::types::enigma_rsa::Ersa;
use crate::crypt::openssl::{rsa_decrypt,rsa_priv_key_from,rsa_key_id};
use openssl::pkey::{PKey,Private};
use pgrx::debug2;

pub enum PrivKey {
    /// PGP secret key
    PGP(pgp::PrivateKey),
    /// OpenSSL RSA
    RSA(PKey<Private>)
}

impl PrivKey {
    /// Creates a `PrivKey` struct with the key obtained
    /// from the `armored key` and the provided plain text password
    pub fn new(armored: &str, pw: &str) 
    -> Result<Self, Box<dyn std::error::Error + 'static>> {
        if let Ok(priv_key) = pgp::PrivateKey::new(armored, pw) {
            return Ok(PrivKey::PGP(priv_key));
        }

        if let Ok(priv_key) = rsa_priv_key_from(armored, pw) {
            return Ok(PrivKey::RSA(priv_key));
        }

        Err("key not recognized".into())
    }

    pub fn priv_key_id(&self) -> String {
        match self {
            PrivKey::PGP(k) => k.key_id(),
            PrivKey::RSA(k) => rsa_key_id(k)
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
            PrivKey::PGP(_) => {
                debug2!("Decrypt: PGP key");
                if enigma.is_pgp() {
                    enigma.decrypt()
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


