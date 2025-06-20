use crate::EnigmaMsg;

pub trait Encrypt<T> {
    fn encrypt(&self, id: i32, _: T) 
    -> Result<EnigmaMsg, Box<(dyn std::error::Error + 'static)>>;
}

pub trait Decrypt {
    fn decrypt(&self, id: Option<i32>) 
    -> Result<EnigmaMsg, Box<(dyn std::error::Error + 'static)>>;

}

