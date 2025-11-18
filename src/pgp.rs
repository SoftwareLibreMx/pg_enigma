use hex::ToHex;
use once_cell::sync::Lazy;
use pgp::composed::{
    ArmorOptions, Deserializable,Message,MessageBuilder, 
    SignedPublicKey, SignedSecretKey
};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{KeyDetails,Password};
use pgrx::{debug1,debug2};
use rand_chacha::ChaCha12Rng;
use rand_chacha::rand_core::SeedableRng;
use std::fmt::Display;
use std::io::Cursor;
use std::time::{SystemTime,UNIX_EPOCH};

const PGP_BEGIN: &str = "-----BEGIN PGP MESSAGE-----\n";
const PGP_END: &str = "-----END PGP MESSAGE-----\n";
const PGP_PUB_KEY_BEGIN: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
const PGP_PUB_KEY_END: &str = "-----END PGP PUBLIC KEY BLOCK-----";
const PGP_SEC_KEY_BEGIN: &str = "-----BEGIN PGP PRIVATE KEY BLOCK-----";
const PGP_SEC_KEY_END: &str = "-----END PGP PRIVATE KEY BLOCK-----";

static SEED: Lazy<u64> = Lazy::new(|| init_seed());

pub fn pgp_trim_envelope(msg: String) -> String {
    msg.trim_start_matches(PGP_BEGIN).trim_end_matches(PGP_END).to_string()
}

pub fn pgp_add_envelope<T: Display>(msg: T) -> String {
    format!("{}{}{}", PGP_BEGIN, msg, PGP_END)
}

pub fn pgp_match_msg(msg: &str) -> bool {
    msg.starts_with(PGP_BEGIN) && msg.ends_with(PGP_END)
}

pub fn pgp_pub_key_from(armored: &str)
-> Result<SignedPublicKey, Box<dyn std::error::Error + 'static>> {
    // https://docs.rs/pgp/latest/pgp/composed/trait.Deserializable.html#method.from_string
    if armored.contains(PGP_PUB_KEY_BEGIN) 
    && armored.contains(PGP_PUB_KEY_END) {
        let (pub_key, _) = SignedPublicKey::from_string(armored)?;
        pub_key.verify()?;
        Ok(pub_key)
    } else {
        Err("Public key is not PGP armor".into())
    }
}

pub fn pgp_sec_key_from(armored: &str) 
-> Result<SignedSecretKey, Box<dyn std::error::Error + 'static>> {
    // https://docs.rs/pgp/latest/pgp/composed/trait.Deserializable.html#method.from_string
    if armored.contains(PGP_SEC_KEY_BEGIN) 
    && armored.contains(PGP_SEC_KEY_END) {
        let (sec_key, _) = SignedSecretKey::from_string(armored)?;
        sec_key.verify()?;
        Ok(sec_key)
    } else {
        Err("Secret key is not PGP armor".into())
    }
}

pub fn pgp_pub_key_id(key: &SignedPublicKey) -> String {
    key.key_id().encode_hex()
}

pub fn pgp_sec_key_id(key: &SignedSecretKey) -> String {
    key.key_id().encode_hex()
}

pub fn pgp_encrypt(pub_key: &SignedPublicKey, message: String) 
-> Result<String, Box<dyn std::error::Error + 'static>> {
    let mut rng =  ChaCha12Rng::seed_from_u64(*SEED);
    let mut builder = MessageBuilder::from_bytes("", message)
        .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
    builder.encrypt_to_key(&mut rng, &pub_key)?;
    let encrypted = builder
        .to_armored_string(rng,ArmorOptions::default())?;
    Ok(pgp_trim_envelope(encrypted))
}

pub fn pgp_decrypt(key: &SignedSecretKey, pass: String, msg: String)
-> Result<String, Box<dyn std::error::Error + 'static>> {
    debug2!("Decrypt: PGP message: {msg}");
    let buf = Cursor::new(pgp_add_envelope(msg));
    let (pgp_msg, _) = Message::from_armor(buf)?;
    let pw = Password::from(pass);
    let mut decrypted = pgp_msg.decrypt(&pw, key)?;
    let clear_text = decrypted.as_data_string()?;
    return Ok(clear_text);
}

/* Functions commented-out for future use
pub fn pgp_encrypting_keys(&self)
-> Result<Vec<KeyId>, Box<dyn std::error::Error + 'static>> {
    let mut keys = Vec::new();
    if let Self::PGP(_,pgp::Message::Encrypted{ esk, .. }) = self {
        for each_esk in esk {
            if let PublicKeyEncryptedSessionKey(skey) = each_esk {
                let pgp_id = skey.id()?;
                debug1!("Encrypting key: {:?}", pgp_id);
                keys.push(pgp_id.clone());
            }
        }
    }
    Ok(keys)
}

pub fn pgp_encrypting_key(&self)
-> Result<KeyId, Box<dyn std::error::Error + 'static>> {
    let mut keys = self.pgp_encrypting_keys()?;
    if keys.len() > 1 {
        return Err("More than one encrypting key".into());
    }
    keys.pop().ok_or("No encrypting key found".into())
}

pub fn pgp_encrypting_key_as_string(&self)
-> Result<String, Box<dyn std::error::Error + 'static>> {
    let pgp_id = self.pgp_encrypting_key()?;
    Ok(format!("{:x}", pgp_id))
} 

/// Iterates over each of the message's encrypting keys looking
/// for a matching key_id in it's own private keys map
pub fn find_encrypting_key(self: &'static PrivKeysMap, msg: &Enigma)
-> Result<Option<&'static PrivKey>, 
Box<dyn std::error::Error + 'static>> {
    if let Some(id) = msg.key_id() {
        return self.get(id);
    }
    if msg.is_pgp() {
        let binding = self.keys.read()?;
        for skey_id in msg.pgp_encrypting_keys()? {
            let mkey_id = format!("{:x}", skey_id);
            // TODO: key_id map
            for (_,pkey) in binding.iter() {
                if mkey_id == pkey.priv_key_id() {
                    info!("KEY_ID: {mkey_id}");
                    return Ok(Some(pkey));
                }
            }
        }
        return Ok(None);
    }
    Ok(None)
} */

/*********************
 * PRIVATE FUNCTIONS *
 * *******************/

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


