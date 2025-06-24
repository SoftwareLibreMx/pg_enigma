use crate::functions::get_public_key;
use crate::message::*;
use crate::priv_key::PrivKey;
use crate::pub_key::PubKey;
use crate::traits::{Encrypt,Decrypt};
use pgrx::info;
use std::collections::BTreeMap;
use std::sync::RwLock;

/********************
 * Private keys map *
 * ******************/
pub struct PrivKeysMap {
    /// each `BTreeMap` entry is a reference to a `PrivKey` structure
    keys: RwLock<BTreeMap<i32,&'static PrivKey>>,
}

/// Functions for private keys map
/// Lifetimes are handled here, so these functions can be called safely
/// from elsewhere.
impl PrivKeysMap {
    /// Creates new (empty) PrivKeys struct
    pub fn new() -> Self {
        let keys = RwLock::new(BTreeMap::new());
        PrivKeysMap {
            keys: keys // new empty BTreeMap
        }
    }

    /// Sets the `PrivKeysMap` `id` to the `PrivKey` obtained from the
    /// provides armored key and plain text password
    pub fn set(&self, id: i32, armored_key: &str, pw: &str)
    -> Result<String, Box<(dyn std::error::Error + 'static)>> {
        let key = PrivKey::new(armored_key, pw)?; // key with '1 lifetime
        let key_id = key.key_id();
        // put the key into the box to allow change it's lifetime
        let boxed_key = Box::new(key);
        // leaked key is the same address, but now with 'static lifetime
        let static_key: &'static PrivKey = Box::leak(boxed_key);
        // need write lock to insert the key on the BTreeMap
        let old = match self.keys.write() {
            // RwLock::insert() returns Some(old_value) if replaced
            Ok(mut m) => m.insert(id, &static_key),
            Err(e) => return Err(
                format!("PrivKeysMap: set: could not get write lock: {}", e)
                .into()),
        };
        
        let msg = match old {
            Some(o) => { // the old key was replaced
                let old_id = o.key_id(); 
                // TODO: drop(o); // free old key (explicitly)
                format!("key {}: private key {} replaced with {}", 
                    id, old_id, key_id)
            },
            None => { // No previous key was replaced
                format!("key {}: private key {} imported", id, key_id)
            }
        };
        Ok(msg)
    }

    pub fn del(&'static self, id: i32) 
    -> Result<String, Box<(dyn std::error::Error + 'static)>> {
        let old = match self.keys.write() {
            Ok(mut m) => {
                m.remove(&id)
            },
            Err(e) => return Err(
                format!("PrivKeysMap: del: could not get write lock: {}", e)
                .into()),
        };

        let msg = match old {
            Some(o) => {
                let key_id = o.key_id();
                // TODO: drop(o); // free old key (explicitly)
                format!("key {}: private key {} forgotten", id, key_id)
            },
            None => format!("key {}: not set", id)
        };
        Ok(msg)
    }

    /// Gets reference to `PrivKey` from `PrivKeysMap` entry with `id` 
    pub fn get(self: &'static PrivKeysMap, id: i32) 
    -> Result<Option<&'static PrivKey>, 
    Box<(dyn std::error::Error + 'static)>> {
        let binding = self.keys.read()?;
        let key = match binding.get(&id) {
            Some(k) => k,
            None => return Ok(None)
        };
        Ok(Some(key))
    }

    /// Custom decrypt function for `PrivKeysMap`.
    /// This function is not an implementation of trait `Decrypt`
    /// Will look for the decryption key in it's key map and call
    /// the key's decrypt function to decrypt the message.
    /// If no decrypting key is found, returns the same encrypted message.
    pub fn decrypt(self: &'static PrivKeysMap, message: EnigmaMsg)
    -> Result<EnigmaMsg, Box<(dyn std::error::Error + 'static)>> {
        // TODO: key_id map
        match self.find_encrypting_key(&message)? {
            Some(sec_key) => {
                sec_key.decrypt(message)
            },
            None => Ok(message)
        }
    }

    /// Iterates over each of the message's encrypting keys looking
    /// for a matching key_id in it's own private keys map
    pub fn find_encrypting_key(self: &'static PrivKeysMap, msg: &EnigmaMsg)
    -> Result<Option<&'static PrivKey>, 
    Box<(dyn std::error::Error + 'static)>> {
        if msg.is_pgp() {
            // TODO: enigma_key_id from envelope
            let binding = self.keys.read()?;
            for skey_id in msg.encrypting_keys()? {
                let mkey_id = format!("{:?}", skey_id);
                // TODO: key_id map
                for (_,pkey) in binding.iter() {
                    if mkey_id == pkey.key_id() {
                        info!("KEY_ID: {mkey_id}");
                        return Ok(Some(pkey));
                    }
                }
            }
            return Ok(None);
        }
        if let Ok(id) = msg.enigma_key() {
            return self.get(id);
        }
        Ok(None)
    }
}

/*******************
 * Public keys map *
 * *****************/
pub struct PubKeysMap {
    /// each `BTreeMap` entry is a reference to a `PubKey` structure
    keys: RwLock<BTreeMap<i32,&'static PubKey>>,
}

/// Functions for private keys map
/// Lifetimes are handled here, so these functions can be called safely
/// from elsewhere.
impl PubKeysMap {
    /// Creates new (empty) PubKeys struct
    pub fn new() -> Self {
        let keys = RwLock::new(BTreeMap::new());
        PubKeysMap {
            keys: keys // new empty BTreeMap
        }
    }

    /// Sets the `PubKeysMap` `id` to the `PubKey` obtained from the
    /// provides armored key and plain text password
    pub fn set(&self, id: i32, armored_key: &str)
    -> Result<String, Box<(dyn std::error::Error + 'static)>> {
        let key = PubKey::new(armored_key)?; // key with '1 lifetime
        let key_id = key.key_id();
        // put the key into the box to allow change it's lifetime
        let boxed_key = Box::new(key);
        // leaked key is the same address, but now with 'static lifetime
        let static_key: &'static PubKey = Box::leak(boxed_key);
        // need write lock to insert the key on the BTreeMap
        let old = match self.keys.write() {
            // RwLock::insert() returns Some(old_value) if replaced
            Ok(mut m) => m.insert(id, &static_key),
            Err(e) => return Err(
                format!("PubKeysMap: set: could not get write lock: {}", e)
                .into()),
        };
        
        let msg = match old {
            Some(o) => { // the old key was replaced
                let old_id = o.key_id(); 
                // TODO: drop(o); // free old key (explicitly)
                format!("key {}: public key {} replaced with {}", 
                    id, old_id, key_id)
            },
            None => { // No previous key was replaced
                format!("key {}: public key {} imported", id, key_id)
            }
        };
        Ok(msg)
    }

    pub fn del(&'static self, id: i32) 
    -> Result<String, Box<(dyn std::error::Error + 'static)>> {
        let old = match self.keys.write() {
            Ok(mut m) => {
                m.remove(&id)
            },
            Err(e) => return Err(
                format!("PubKeysMap: del: could not get write lock: {}", e)
                .into()),
        };

        let msg = match old {
            Some(o) => {
                let key_id = o.key_id();
                // TODO: drop(o); // free old key (explicitly)
                format!("key {}: public key {} forgotten", id, key_id)
            },
            None => format!("key {}: not set", id)
        };
        Ok(msg)
    }

    /// Gets reference to `PubKey` from `PubKeysMap` entry with `id` 
    pub fn get(self: &'static PubKeysMap, id: i32) 
    -> Result<Option<&'static PubKey>, 
    Box<(dyn std::error::Error + 'static)>> {
        let binding = self.keys.read()?;
        let key = match binding.get(&id) {
            Some(k) => k,
            None => {
                // TODO: rename to public_ket_from_sql()
                let armored_key = get_public_key(id)?; // Key from SQL
                match armored_key {
                    Some(k) => {
                        let set_msg = self.set(id, &k)?;
                        info!("{set_msg}");
                        // retry get key just being set
                        match binding.get(&id) {
                            Some(k) => k,
                            None => return Ok(None)
                        }
                    }
                    None => return Ok(None)
                }
            }
        };
        Ok(Some(key))
    }

    pub fn encrypt(self: &'static PubKeysMap, id: i32, msg: EnigmaMsg) 
    -> Result<EnigmaMsg, Box<(dyn std::error::Error + 'static)>> {
        if let Some(pub_key) = self.get(id)? {
            return pub_key.encrypt(id, msg);
        }
        Err(format!("No public key with id: {}", id).into())
    }

}

