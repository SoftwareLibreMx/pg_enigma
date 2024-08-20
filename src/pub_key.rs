use lazy_static::lazy_static;
use openssl::base64::encode_block;
use openssl::encrypt::Encrypter;
use openssl::pkey::{PKey,Public};
use openssl::rsa::Padding;
use pgp::{Deserializable,Message,SignedPublicKey};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{KeyTrait};
use rand::rngs::StdRng;
use rand::SeedableRng;
use regex::bytes::Regex;

pub enum PubKey {
    /// PGP public key
    PGP(SignedPublicKey),
    /// OpenSSL RSA
    RSA(PKey<Public>)
}

impl PubKey {
    /// Creates a `PubKey` struct with the key obtained
    /// from the `armored key`
    pub fn new(armored_key: &str) 
    -> Result<Self, Box<(dyn std::error::Error + 'static)>> {
        lazy_static! {
            static ref RE_PGP: Regex = 
                Regex::new(r"BEGIN PGP PUBLIC KEY BLOCK")
                .expect("failed to compile PGP key regex");
            static ref RE_RSA: Regex = 
                Regex::new(r"BEGIN PUBLIC KEY")
                .expect("failed to compile OpenSSL RSA key regex");
        }
        if RE_PGP.captures(armored_key.as_bytes()).is_some() {
            // https://docs.rs/pgp/latest/pgp/composed/trait.Deserializable.html#method.from_string
            let (pub_key, _) = SignedPublicKey::from_string(armored_key)?;
            pub_key.verify()?;
            Ok(PubKey::PGP(pub_key))
        } else if RE_RSA.captures(armored_key.as_bytes()).is_some() {
            let pub_key = PKey::<Public>::public_key_from_pem(
                armored_key.as_bytes())?;
           Ok(PubKey::RSA(pub_key))
        } else {
            Err("key type not supported".into())
        }
    }

    pub fn key_id(&self) -> String {
        match self {
            PubKey::PGP(k) => format!("{:?}", k.key_id()),
            PubKey::RSA(k) => format!("{:?}", k.id())
        }
    }

    pub fn encrypt(&self, message: &String) 
    -> Result<String, Box<(dyn std::error::Error + 'static)>> {
        match self {
            PubKey::PGP(pub_key) => {
                let msg = Message::new_literal("none", message.as_str());
                let mut rng = StdRng::from_entropy();
                let new_msg = msg.encrypt_to_keys(
                    &mut rng, SymmetricKeyAlgorithm::AES128, &[&pub_key])?;
                Ok(new_msg.to_armored_string(None)?)
            },
            PubKey::RSA(pub_key) => {
                let mut encrypter = Encrypter::new(&pub_key)?;
                encrypter.set_rsa_padding(Padding::PKCS1)?;
                // Get the length of the output buffer
                let buffer_len = encrypter.encrypt_len(&message.as_bytes())?;
                let mut encoded = vec![0u8; buffer_len];
                // Encode the data and get its length
                let encoded_len = encrypter.encrypt(&message.as_bytes(), 
                    &mut encoded)?;
                // Use only the part of the buffer with the encoded data
                let encoded = &encoded[..encoded_len];
                Ok(encode_block(encoded))
            }
        }
    }
}


