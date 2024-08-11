use lazy_static::lazy_static;
use openssl::pkey::{PKey,Private};
use pgp::{Deserializable,SignedSecretKey};
use pgp::types::{KeyId,KeyTrait};
use regex::bytes::Regex;

pub struct PrivKey {
    /// Enigma private key
    key: EnigmaPrivKey,
    /// Secret key password, used for decryption
    pass: String
}

pub enum EnigmaPrivKey {
    /// PGP secret key
    PGP(SignedSecretKey),
    /// OpenSSL RSA
    RSA(PKey<Private>)
}

impl PrivKey {
    /// Creates a `PrivKey` struct with the `SignedSecretKey` obtained
    /// from the `armored key` and the provided plain text password
    pub fn new(armored_key: &str, pw: &str) 
    -> Result<Self, Box<(dyn std::error::Error + 'static)>> {
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
            Ok(PrivKey {
                key: EnigmaPrivKey::PGP(sec_key),
                pass: pw.to_string()
            })
        } else if RE_RSA.captures(armored_key.as_bytes()).is_some() {
            let priv_key = 
                PKey::<Private>::private_key_from_pem_passphrase(
                    armored_key.as_bytes(), pw.as_bytes())?;
           Ok(PrivKey {
                key: EnigmaPrivKey::RSA(priv_key),
                pass: pw.to_string()
            })
        } else {
            Err("key type not supported".into())
        }
    }

    pub fn key_id(&self) -> String {
        match &self.key {
            EnigmaPrivKey::PGP(p) => {
                String::from(format!("{:X}", p.key_id()))
            },
            EnigmaPrivKey::RSA(r) => {
                 String::from(format!("{:X}", r.id().as_raw()))
            }
        }
    }

    pub fn pass(&self)  -> String {
        self.pass.clone()
    }

    pub fn get_key(&self) -> &EnigmaPrivKey {
        &self.key
    }
}

impl EnigmaPrivKey {
    pub fn key_id(&self) -> KeyId {
        match self {
            EnigmaPrivKey::PGP(k) => k.key_id(),
            _ => todo!()
        }
    }

}


