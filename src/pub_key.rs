use crate::common::IsEncrypted;
use crate::enigma::Enigma;
use crate::pgp::{pgp_encrypt,pgp_pub_key_from,pgp_pub_key_id};
use openssl::base64::encode_block;
use openssl::encrypt::Encrypter;
use openssl::pkey::{PKey,Public};
use openssl::rsa::Padding;
use pgp::composed::SignedPublicKey;
use pgrx::datum::DatumWithOid;
use pgrx::{PgBuiltInOids,Spi};

// TODO:  Other OpenSSL supported key types (elyptic curves, etc.)
const SSL_BEGIN: &str = "-----BEGIN PUBLIC KEY-----";
const SSL_END: &str = "-----END PUBLIC KEY-----";

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
    -> Result<Self, Box<dyn std::error::Error + 'static>> {
        if let Ok(pub_key) = pgp_pub_key_from(armored) {
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
            PubKey::PGP(k) => pgp_pub_key_id(k),
            PubKey::RSA(k) => format!("{:?}", k.id())
        }
    }

    pub fn encrypt(&self, id: u32, msg: Enigma) 
    -> Result<Enigma, Box<dyn std::error::Error + 'static>> {
        if msg.is_encrypted() { 
             return Err("Nested encryption not supported".into());
        }

        match self {
            PubKey::PGP(pub_key) => {
                let encrypted = pgp_encrypt(pub_key, msg.to_string())?;
                Ok(Enigma::pgp(id, encrypted))
            },
            PubKey::RSA(pub_key) => {
                let encrypted = encrypt_rsa(pub_key, msg.to_string())?;
                Ok(Enigma::rsa(id, encrypted))
            }
        }
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

fn encrypt_rsa(pub_key: &PKey<Public>, message: String) 
-> Result<String, Box<dyn std::error::Error + 'static>> {
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


