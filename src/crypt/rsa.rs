use hex::ToHex;
use pgrx::{debug1,debug2};
use std::fmt::Display;
use std::io::Cursor;
use std::time::{SystemTime,UNIX_EPOCH};

const RSA_BEGIN: &str = "-----BEGIN RSA ENCRYPTED-----\n";
const RSA_END: &str = "\n-----END RSA ENCRYPTED-----";


pub fn rsa_trim_envelope(msg: String) -> String {
    msg.trim_start_matches(RSA_BEGIN).trim_end_matches(RSA_END).to_string()
}

pub fn rsa_add_envelope<T: Display>(msg: T) -> String {
    format!("{}{}{}", RSA_BEGIN, msg, RSA_END)
}

pub fn rsa_match_msg(msg: &str) -> bool {
    msg.starts_with(RSA_BEGIN) && msg.ends_with(RSA_END)
}

/*
pub fn rsa_pub_key_from(armored: &str)
-> Result<SignedPublicKey, Box<dyn std::error::Error + 'static>> {
    // https://docs.rs/rsa/latest/rsa/composed/trait.Deserializable.html#method.from_string
    if armored.contains(RSA_PUB_KEY_BEGIN) 
    && armored.contains(RSA_PUB_KEY_END) {
        let (pub_key, _) = SignedPublicKey::from_string(armored)?;
        pub_key.verify()?;
        Ok(pub_key)
    } else {
        Err("Public key is not RSA PEM".into())
    }
}

pub fn rsa_sec_key_from(armored: &str) 
-> Result<SignedSecretKey, Box<dyn std::error::Error + 'static>> {
    // https://docs.rs/rsa/latest/rsa/composed/trait.Deserializable.html#method.from_string
    if armored.contains(RSA_SEC_KEY_BEGIN) 
    && armored.contains(RSA_SEC_KEY_END) {
        let (sec_key, _) = SignedSecretKey::from_string(armored)?;
        sec_key.verify()?;
        Ok(sec_key)
    } else {
        Err("Secret key is not RES PEM".into())
    }
}

pub fn rsa_pub_key_id(key: &SignedPublicKey) -> String {
    key.key_id().encode_hex()
}

pub fn rsa_sec_key_id(key: &SignedSecretKey) -> String {
    key.key_id().encode_hex()
}

pub fn rsa_encrypt(pub_key: &SignedPublicKey, message: String) 
-> Result<String, Box<dyn std::error::Error + 'static>> {
    let mut rng =  ChaCha12Rng::seed_from_u64(*SEED);
    let mut builder = MessageBuilder::from_bytes("", message)
        .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
    builder.encrypt_to_key(&mut rng, &pub_key)?;
    let encrypted = builder
        .to_armored_string(rng,ArmorOptions::default())?;
    Ok(rsa_trim_envelope(encrypted))
}

pub fn rsa_decrypt(key: &SignedSecretKey, pass: String, msg: String)
-> Result<String, Box<dyn std::error::Error + 'static>> {
    debug2!("Decrypt: RSA message: {msg}");
    let buf = Cursor::new(rsa_add_envelope(msg));
    let (rsa_msg, _) = Message::from_armor(buf)?;
    let pw = Password::from(pass);
    let mut decrypted = rsa_msg.decrypt(&pw, key)?;
    let clear_text = decrypted.as_data_string()?;
    return Ok(clear_text);
}
*/

/*********************
 * PRIVATE FUNCTIONS *
 * *******************/

/*
fn from_rsa_envelope(key_id: u32, value: &str) -> Legacy {
    Legacy::RSA(key_id, value
        .trim_start_matches(RSA_BEGIN)
        .trim_end_matches(RSA_END)
        .to_string() )
}
*/

