use openssl::base64::{decode_block,encode_block};
use openssl::encrypt::{Decrypter,Encrypter};
use openssl::pkey::{PKey,Private,Public};
use openssl::rsa::Padding;
use pgrx::{debug2};
use std::fmt::Display;

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
*/

pub fn rsa_encrypt(pub_key: &PKey<Public>, message: String) 
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

pub fn rsa_decrypt(key: &PKey<Private>, msg: String)
-> Result<String, Box<dyn std::error::Error + 'static>> {
    debug2!("Decrypt: RSA Enigma: {msg}");
    let input = decode_block(msg.as_str())?;
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
    Ok(clear_text)
}


