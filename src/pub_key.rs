use crate::EnigmaMsg;
use crate::traits::Encrypt;
use once_cell::sync::Lazy;
use openssl::base64::encode_block;
use openssl::encrypt::Encrypter;
use openssl::pkey::{PKey,Public};
use openssl::rsa::Padding;
use pgp::{Deserializable,Message,SignedPublicKey};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::PublicKeyTrait;
use pgrx::datum::DatumWithOid;
use pgrx::{debug1,PgBuiltInOids,Spi};
use rand_chacha::ChaCha12Rng;
use rand_chacha::rand_core::SeedableRng;
use std::time::{SystemTime,UNIX_EPOCH};

const PGP_BEGIN: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
const PGP_END: &str = "-----END PGP PUBLIC KEY BLOCK-----";
// TODO:  Other OpenSSK supported key types (elyptic curves, etc.)
const SSL_BEGIN: &str = "-----BEGIN PUBLIC KEY-----";
const SSL_END: &str = "-----END PUBLIC KEY-----";

static SEED: Lazy<u64> = Lazy::new(|| init_seed());

pub enum PubKey {
    /// PGP public key
    PGP(SignedPublicKey),
    /// OpenSSL RSA
    RSA(PKey<Public>)
}

impl PubKey {
    /// Creates a `PubKey` struct with the key obtained
    /// from the `armored key`
    pub fn new(armored: &str) 
    -> Result<Self, Box<(dyn std::error::Error + 'static)>> {
        if armored.contains(PGP_BEGIN) && armored.contains(PGP_END) {
            // https://docs.rs/pgp/latest/pgp/composed/trait.Deserializable.html#method.from_string
            let (pub_key, _) = SignedPublicKey::from_string(armored)?;
            pub_key.verify()?;
            return Ok(PubKey::PGP(pub_key));
        } 

        if armored.contains(SSL_BEGIN) && armored.contains(SSL_END) {
            let pub_key = 
                PKey::<Public>::public_key_from_pem(armored.as_bytes())?;
           return Ok(PubKey::RSA(pub_key));
        }

        Err("Key not recognized".into())
    }

    pub fn pub_key_id(&self) -> String {
        match self {
            PubKey::PGP(k) => format!("{:x}", k.key_id()),
            PubKey::RSA(k) => format!("{:?}", k.id())
        }
    }
}

impl Encrypt<u32,EnigmaMsg> for PubKey {
    fn encrypt(&self, id: u32, msg: EnigmaMsg) 
    -> Result<EnigmaMsg, Box<(dyn std::error::Error + 'static)>> {
        if msg.is_encrypted() { 
             return Err("Nested encryption not supported".into());
        }

        match self {
            PubKey::PGP(pub_key) => {
                let new_msg = encrypt_pgp(pub_key, msg.to_string())?;
                Ok(EnigmaMsg::pgp(id, new_msg))
            },
            PubKey::RSA(pub_key) => {
                let new_msg = encrypt_rsa(pub_key, msg.to_string())?;
                Ok(EnigmaMsg::rsa(id, new_msg))
            }
        }
    }
}

impl Encrypt<i32,EnigmaMsg> for PubKey {
    fn encrypt(&self, id: i32, msg: EnigmaMsg) 
    -> Result<EnigmaMsg, Box<(dyn std::error::Error + 'static)>> {
        if id < 1 { // TODO: Support Key ID 0
            return Err("Key id must be a positive integer".into());
        }
        self.encrypt(id as u32, msg)
    }
}


impl Encrypt<u32,String> for PubKey {
    fn encrypt(&self, id: u32, message: String) 
    -> Result<String, Box<(dyn std::error::Error + 'static)>> {
        let msg = EnigmaMsg::try_from(message)?;
        Ok(self.encrypt(id,msg)?.to_string())
    }
}

impl Encrypt<i32,String> for PubKey {
    fn encrypt(&self, id: i32, message: String) 
    -> Result<String, Box<(dyn std::error::Error + 'static)>> {
        if id < 1 { // TODO: Support Key ID 0
            return Err("Key id must be a positive integer".into());
        }
        self.encrypt(id as u32, message)
    }
}

/// Get the public key from the keys table
/// id is `i32` because Postgres `integer` is signed integer
pub fn get_public_key(id: i32) -> Result<Option<String>, pgrx::spi::Error> {
    let query = "SELECT public_key FROM _enigma_public_keys WHERE id = $1";
    let args = unsafe { 
        [ DatumWithOid::new(id, PgBuiltInOids::INT4OID.value()) ]
    };
    Spi::connect(|client| {
        let tuple_table = client.select(query, Some(1), &args)?;
        if tuple_table.len() == 0 {
            Ok(None)
        } else {
            tuple_table.first().get_one::<String>()
        }
    })

}

/// Inserts the armored public key as text in table _enigma_public_keys
/// id is `i32` because Postgres `integer` is signed integer
pub fn insert_public_key(id: i32, key: &str)
-> Result<Option<String>, pgrx::spi::Error> {
    // create_key_table()?;
    let args = unsafe {
        [
            DatumWithOid::new(id,  PgBuiltInOids::INT4OID.value()),
            DatumWithOid::new(key, PgBuiltInOids::TEXTOID.value()),
        ]
    };
    Spi::get_one_with_args(
        r#"INSERT INTO _enigma_public_keys(id, public_key)
           VALUES ($1, $2)
           ON CONFLICT(id)
           DO UPDATE SET public_key=$2
           RETURNING 'Public key set'"#,
         &args
    )
}

/*********************
 * PRIVATE FUNCTIONS *
 * *******************/

fn encrypt_pgp(pub_key: &SignedPublicKey, message: String) 
-> Result<Message, Box<(dyn std::error::Error + 'static)>> {
    let msg = Message::new_literal("none", message.as_str());
    // TODO: use some random seed (nanoseconds or something)
    let mut rng =  ChaCha12Rng::seed_from_u64(*SEED);
    let new_msg = msg.encrypt_to_keys_seipdv1(
        &mut rng , SymmetricKeyAlgorithm::AES128, &[&pub_key])?;
    Ok(new_msg)
}

fn encrypt_rsa(pub_key: &PKey<Public>, message: String) 
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    let mut encrypter = Encrypter::new(&pub_key)?;
    encrypter.set_rsa_padding(Padding::PKCS1)?;
    let as_bytes = message.as_bytes();
    // Get the length of the output buffer
    let buffer_len = encrypter.encrypt_len(&as_bytes)?;
    let mut encoded = vec![0u8; buffer_len];
    // Encode the data and get its length
    let encoded_len = encrypter.encrypt(&as_bytes, &mut encoded)?;
    // Use only the part of the buffer with the encoded data
    let encoded = &encoded[..encoded_len];
    Ok(encode_block(encoded))
}

fn init_seed() -> u64 {
        let dur = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap(); // always greater than UNIX_EPOCH
        let secs = dur.as_secs(); 
        let nano = dur.subsec_nanos() as u64;
        let seed = secs ^ nano + nano << 32;
        debug1!("RNG seed: {:x} ones: {} zeros: {}", 
            seed, seed.count_ones(), seed.count_zeros());
        seed
}


