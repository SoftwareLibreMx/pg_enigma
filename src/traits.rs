
/// Function `decrypt(&self, message: T)` decrypts message 
/// of type T, returning a decrypted message with the same type. 
pub trait Decrypt<T> {
    fn decrypt(&self, message: T) 
    -> Result<T, Box<(dyn std::error::Error + 'static)>>;

}

