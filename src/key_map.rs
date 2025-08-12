use crate::enigma::*;
use crate::priv_key::PrivKey;
use crate::pub_key::{PubKey,get_public_key};
use crate::traits::{Encrypt,Decrypt};
use pgrx::{debug1,debug2,info};
use std::collections::BTreeMap;
use std::mem::drop;
use std::sync::RwLock;

/********************
 * Private keys map *
 * ******************/
pub struct PrivKeysMap {
    /// each `BTreeMap` entry is a reference to a `PrivKey` structure
    keys: RwLock<BTreeMap<u32,&'static PrivKey>>,
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
    pub fn set(&self, id: u32, armored_key: &str, pw: &str)
    -> Result<String, Box<(dyn std::error::Error + 'static)>> {
        let key = PrivKey::new(armored_key, pw)?; // key with '1 lifetime
        let priv_id = key.priv_key_id();
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
                let old_id = o.priv_key_id(); 
                // TODO: drop(o); // free old key (explicitly)
                format!("key {}: private key {} replaced with {}", 
                    id, old_id, priv_id)
            },
            None => { // No previous key was replaced
                format!("key {}: private key {} imported", id, priv_id)
            }
        };
        Ok(msg)
    }
    
    /// Removes key from the `PrivKeysMap`. 
    /// Once the key gets out of scope, it's supposed to be dropped.
    pub fn del(&'static self, id: u32) 
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
                let priv_id = o.priv_key_id();
                // TODO: drop(o); // free old key (explicitly)
                format!("key {}: private key {} forgotten", id, priv_id)
            },
            None => format!("key {}: not set", id)
        };
        Ok(msg)
    }

    /// Gets reference to `PrivKey` from `PrivKeysMap` entry with `id` 
    pub fn get(self: &'static PrivKeysMap, id: u32) 
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
    /// the key's `decrypt()` function to decrypt the message.
    /// If no decrypting key is found, returns the same encrypted message.
    pub fn decrypt(self: &'static PrivKeysMap, message: Enigma)
    -> Result<Enigma, Box<(dyn std::error::Error + 'static)>> {
        let key_id = match message.key_id() {
            Some(k) => k,
            None => return Ok(message) // Not encrypted
        };
        debug2!("Decrypt: Message key_id: {key_id}");
        match self.get(key_id)? {
            Some(sec_key) => {
                debug2!("Decrypt: got secret key");
                sec_key.decrypt(message)
            },
            None => Ok(message)
        }
    }

    /* PGP specific functions commented-out for future use
    /// Iterates over each of the message's encrypting keys looking
    /// for a matching key_id in it's own private keys map
    pub fn find_encrypting_key(self: &'static PrivKeysMap, msg: &Enigma)
    -> Result<Option<&'static PrivKey>, 
    Box<(dyn std::error::Error + 'static)>> {
        if let Some(id) = msg.key_id() {
            return self.get(id);
        }
        if msg.is_pgp() {
            let binding = self.keys.read()?;
            for skey_id in msg.pgp_encrypting_keys()? {
                let mkey_id = format!("{:x}", skey_id);
                // TODO: key_id map
                for (_,pkey) in binding.iter() {
                    if mkey_id == pkey.priv_key_id() {
                        info!("KEY_ID: {mkey_id}");
                        return Ok(Some(pkey));
                    }
                }
            }
            return Ok(None);
        }
        Ok(None)
    } */
}

/*******************
 * Public keys map *
 * *****************/
pub struct PubKeysMap {
    /// each `BTreeMap` entry is a reference to a `PubKey` structure
    keys: RwLock<BTreeMap<u32,&'static PubKey>>,
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
    pub fn set(&self, id: u32, armored_key: &str)
    -> Result<String, Box<(dyn std::error::Error + 'static)>> {
        let key = PubKey::new(armored_key)?; // key with '1 lifetime
        let pub_id = key.pub_key_id();
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
                let old_id = o.pub_key_id(); 
                // TODO: drop(o); // free old key (explicitly)
                format!("key {}: public key {} replaced with {}", 
                    id, old_id, pub_id)
            },
            None => { // No previous key was replaced
                format!("key {}: public key {} imported", id, pub_id)
            }
        };
        Ok(msg)
    }

    /// Removes key from the `PubKeysMap`. 
    /// Once the key gets out of scope, it's supposed to be dropped.
    pub fn del(&'static self, id: u32) 
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
                let pub_id = o.pub_key_id();
                // TODO: drop(o); // free old key (explicitly)
                format!("key {}: public key {} forgotten", id, pub_id)
            },
            None => format!("key {}: not set", id)
        };
        Ok(msg)
    }

    /// Gets reference to `PubKey` from `PubKeysMap` entry with `id` 
    pub fn get(self: &'static PubKeysMap, id: u32) 
    -> Result<Option<&'static PubKey>, 
    Box<(dyn std::error::Error + 'static)>> {
        let binding = self.keys.read()?;
        let key = match binding.get(&id) {
            Some(k) => k,
            None => {
                drop(binding);
                // get_public_key() reads Key from SQL
                if let Some(armored_key) = get_public_key(id as i32)? { 
                    debug1!("Key with ID {id}:\n{armored_key}");
                    let set_msg = self.set(id, &armored_key)?;
                    info!("{set_msg}");
                    // return the key just been set
                    self.get(id)?.ok_or("missing just set key")?
                } else {
                    return Ok(None);
                }
            }
        };
        Ok(Some(key))
    }

    /// Custom encrypt function for `PubKeysMap`.
    /// This function is not an implementation of trait `Decrypt`
    /// Will look for the encryption key in it's key map and call
    /// the key's `encrypt()` function to encrypt the message.
    /// If no encrypting key is found, returns an error message.
    pub fn encrypt(self: &'static PubKeysMap, id: i32, msg: Enigma) 
    -> Result<Enigma, Box<(dyn std::error::Error + 'static)>> {
        if id < 1 { // TODO: Support Key ID 0
            return Err("Key id must be a positive integer".into());
        }
        let key_id: u32 = id as u32;
        if let Some(msgid) = msg.key_id() { // message is encrypted
            if msgid == key_id {
                info!("Already encrypted with key ID {msgid}"); 
                return  Ok(msg);
            };
            // TODO: try to decrypt
            return Err("Nested encryption not supported".into());
        }
        if let Some(pub_key) = self.get(key_id)? {
            return pub_key.encrypt(key_id, msg);
        }
        // retry from SQL is expected to be needed only once 
        /* if let Some(pub_key) = self.from_sql(key_id)? {
            return pub_key.encrypt(key_id, msg);
        } */
        Err(format!("No public key with key_id: {}", key_id).into())
    }

/*********************
 * PRIVATE FUNCTIONS *
 * *******************/


}

