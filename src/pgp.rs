use std::fmt::Display;

const PGP_BEGIN: &str = "-----BEGIN PGP MESSAGE-----\n";
const PGP_END: &str = "-----END PGP MESSAGE-----\n";

pub fn pgp_trim_envelope(msg: String) -> String {
    msg
        .trim_start_matches(PGP_BEGIN)
        .trim_end_matches(PGP_END)
        .to_string()
}

pub fn pgp_add_envelope<T: Display>(msg: T) -> String {
    format!("{}{}{}", PGP_BEGIN, msg, PGP_END)
}

pub fn pgp_match(msg: &str) -> bool {
    msg.starts_with(PGP_BEGIN) 
    && msg.ends_with(PGP_END)
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
} */


