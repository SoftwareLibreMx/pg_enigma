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

