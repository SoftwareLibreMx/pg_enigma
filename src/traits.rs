//use crate::EnigmaMsg;

/// Function `encrypt(&self, id: i32, message: T)` encrypts message 
/// of type T, returning an encrypted message with the same type. 
/// Argument `id` is used for storing key ID in message envelope.
pub trait Encrypt<T> {
    fn encrypt(&self, id: i32, message: T) 
    -> Result<T, Box<(dyn std::error::Error + 'static)>>;
}

/// Function `decrypt(&self, message: T)` decrypts message 
/// of type T, returning a decrypted message with the same type. 
pub trait Decrypt<T> {
    fn decrypt(&self, message: T) 
    -> Result<T, Box<(dyn std::error::Error + 'static)>>;

}

