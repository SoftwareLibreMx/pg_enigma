use std::collections::BTreeMap;
use crate::priv_key::PrivKey;
use std::sync::RwLock;

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
    pub fn get(self: &'static PrivKeysMap, id: &i32) 
    -> Result<Option<&'static PrivKey>, 
    Box<(dyn std::error::Error + 'static)>> {
        let binding = self.keys.read()?;
        let key = match binding.get(id) {
            Some(k) => k,
            None => return Ok(None)
        };
        Ok(Some(key))
    }
}


