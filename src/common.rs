#[allow(unused)]
pub const PLAIN_TAG: &str  = "PLAINMSG"; // 0x504C41494E4D5347
pub const PLAIN_INT: u64   = 0x504C41494E4D5347; // "PLAINMSG"
pub const SEPARATOR: char = '\n';

/// Enigma types must implement `Plain` trait for plain unencrypted payload
pub trait Plain {
    /// plain unencrypted payload 
    fn plain(value: String) -> Self;
    /// true if plain unencrypted payload
    fn is_plain(&self) -> bool;
}

pub trait IsEncrypted {
    /// true if payload is encrypted
    fn is_encrypted(&self) -> bool;
}

impl<T> IsEncrypted for T where T: Plain {
    fn is_encrypted(&self) -> bool {
        !self.is_plain()
    }
}

pub trait Value {
    /// get the value as a String
    fn value(&self) -> String;
}

impl <T> Value for T where T: ToString {
    fn value(&self) -> String {
        self.to_string()
    }
}

pub trait Encrypt<T> where T: IsEncrypted {
    fn encrypt(&self, id: u32, msg: T)
        -> Result<T, Box<dyn std::error::Error + 'static>>;
}

pub trait Decrypt<T> where T: Plain {
    fn decrypt(&self, msg: T)
        -> Result<T, Box<dyn std::error::Error + 'static>>;
}

/** Enigma header is exactly 16 octets. 

First 8 octets are Enigma tag `0x454E49474D417631`. It's value can be verified as 32-bit integer or as string `ENIGMAv1`. 

Next 8 octets are hex-encoded 32-bit integer corresponding to enigma key_id in *typmod*. Since typmod is signed integer, maximum key_id value can not be greater than `2,147,483,647`.

This fixed size header is for parsing efficiency.  **/
pub struct Header {
    pub tag: u64,
    pub key: u32
    // TODO: More Keys vector
}

/// Try to read Enigma header from given string.
impl TryFrom<&str> for Header {
    type Error = Box<dyn std::error::Error + 'static>;

    fn try_from(full_header: &str) -> Result<Self, Self::Error> {
        if full_header.len() < 16 {
            return Err("Wrong header".into());
        }
        let (hdr,_) = full_header.split_at(16);
        let (stag, skey) = hdr.split_at(8);
        let ret = Header {
            tag: u64::from_be_bytes(stag.as_bytes().try_into()?),
            key: u32::from_str_radix(skey, 16)?
        };
        Ok(ret)
    }
}


