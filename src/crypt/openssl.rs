use openssl::base64::{decode_block,encode_block};
use openssl::encrypt::{Decrypter,Encrypter};
use openssl::pkey::{PKey,Private,Public};
use openssl::rsa::Padding;
use pgrx::{debug2};
//use std::fmt::Display;

const RSA_BEGIN: &str = "-----BEGIN RSA ENCRYPTED-----\n";
const RSA_END: &str = "\n-----END RSA ENCRYPTED-----";
// TODO:  Other OpenSSL supported key types (elyptic curves, etc.)
const RSA_PUB_KEY_BEGIN: &str = "-----BEGIN PUBLIC KEY-----";
const RSA_PUB_KEY_END: &str = "-----END PUBLIC KEY-----";
const RSA_PRV_KEY_BEGIN: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
const RSA_PRV_KEY_END: &str = "-----END ENCRYPTED PRIVATE KEY-----";

pub fn rsa_trim_envelope(msg: String) -> String {
    msg.trim_start_matches(RSA_BEGIN).trim_end_matches(RSA_END).to_string()
}

/* pub fn rsa_add_envelope<T: Display>(msg: T) -> String { // unneeded
    format!("{}{}{}", RSA_BEGIN, msg, RSA_END)
} */

pub fn rsa_match_msg(msg: &str) -> bool {
    msg.starts_with(RSA_BEGIN) && msg.ends_with(RSA_END)
}

pub fn rsa_pub_key_from(pem: &str)
-> Result<PKey<Public>, Box<dyn std::error::Error + 'static>> {
    if pem.contains(RSA_PUB_KEY_BEGIN) 
    && pem.contains(RSA_PUB_KEY_END) {
        let pub_key = PKey::<Public>::public_key_from_pem(pem.as_bytes())?;
        Ok(pub_key)
    } else {
        Err("Public key is not RSA PEM".into())
    }
}

pub fn rsa_priv_key_from(pem: &str, pw: &str) 
-> Result<PKey<Private>, Box<dyn std::error::Error + 'static>> {
    if pem.contains(RSA_PRV_KEY_BEGIN) 
    && pem.contains(RSA_PRV_KEY_END) {
       let priv_key = PKey::<Private>::private_key_from_pem_passphrase(
            pem.as_bytes(), pw.as_bytes())?;
        Ok(priv_key)
    } else {
        Err("Secret key is not RSA PEM".into())
    }
}

pub fn rsa_key_id<T>(key: &PKey<T>) -> String {
    format!("{:?}", key.id())
}

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


