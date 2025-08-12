mod enigma;
mod key_map;
mod priv_key;
mod pub_key;
mod traits;

use core::ffi::CStr;
use crate::enigma::Enigma;
use crate::key_map::{PrivKeysMap,PubKeysMap};
use crate::pub_key::insert_public_key;
use once_cell::sync::Lazy;
use pgrx::prelude::*;
use pgrx::StringInfo;
use pgrx::datum::Internal;
use pgrx::pg_sys::Oid;
use std::fs;


pgrx::pg_module_magic!();

static PRIV_KEYS: Lazy<PrivKeysMap> = Lazy::new(|| PrivKeysMap::new());
static PUB_KEYS: Lazy<PubKeysMap> = Lazy::new(|| PubKeysMap::new());


/// Functions for extracting and inserting data
#[pg_extern(stable, parallel_safe, requires = [ "shell_type" ])]
fn enigma_input(input: &CStr, oid: pg_sys::Oid, typmod: i32) 
-> Result<Enigma, Box<(dyn std::error::Error + 'static)>> {
	//debug2!("INPUT: OID: {:?},  Typmod: {}", oid, typmod);
	debug5!("INPUT: ARGUMENTS: \
            Input: {:?}, OID: {:?},  Typmod: {}", input, oid, typmod);
	//let value = input.to_str()?;
    let enigma =  Enigma::try_from(input)?;
    if typmod == -1 { // unknown typmod 
        debug1!("Unknown typmod: {typmod}");
        return Ok(enigma);
    }
    enigma.encrypt(typmod)
}

/// Cast enigma to enigma is called after enigma_input_with_typmod(). 
/// This function is passed the correct known typmod argument.
#[pg_extern(stable, parallel_safe)]
fn enigma_as_enigma(original: Enigma, typmod: i32, explicit: bool) 
-> Result<Enigma, Box<(dyn std::error::Error + 'static)>> {
    debug2!("CAST(Enigma AS Enigma): \
        ARGUMENTS: explicit: {},  Typmod: {}", explicit, typmod);
    if typmod == -1 {
        return Err(
            format!("Unknown typmod: {}\noriginal: {:?}\nexplicit: {}", 
                typmod, original, explicit).into());
    }
    debug5!("Original: {:?}", original);
    if original.is_encrypted() {
        // TODO: if original.key_id != key_id {try_reencrypt()} 
        return Ok(original);
    } 
    let key_id = typmod;
    debug2!("Encrypting plain message with key ID: {key_id}");
    original.encrypt(key_id)
}

/// Enigma RECEIVE function
#[pg_extern(stable, parallel_safe, requires = [ "shell_type" ])]
fn enigma_receive(mut internal: Internal, oid: Oid, typmod: i32) 
-> Result<Enigma, Box<(dyn std::error::Error + 'static)>> {
    debug2!("RECEIVE: OID: {:?},  Typmod: {}", oid, typmod);
    let buf = unsafe { 
        internal.get_mut::<::pgrx::pg_sys::StringInfoData>().unwrap() 
    };
    let mut serialized = ::pgrx::StringInfo::new();
    // reserve space for the header
    serialized.push_bytes(&[0u8; ::pgrx::pg_sys::VARHDRSZ]); 
    serialized.push_bytes(unsafe {
        core::slice::from_raw_parts(
            buf.data as *const u8,
            buf.len as usize )
    });
    //let value = serialized.as_str()?;
	debug5!("RECEIVE value: {}", serialized);
    Enigma::try_from(&serialized)?.encrypt(typmod)
} 

/// Enigma OUTPUT function
/// Sends Enigma to Postgres converted to `&Cstr`
#[pg_extern(stable, parallel_safe, requires = [ "shell_type" ])]
fn enigma_output(enigma: Enigma) 
-> Result<&'static CStr, Box<(dyn std::error::Error + 'static)>> {
	//debug2!("OUTPUT");
	debug5!("OUTPUT: {}", enigma);
    let decrypted = PRIV_KEYS.decrypt(enigma)?;
	let mut buffer = StringInfo::new();
    buffer.push_str(decrypted.to_string().as_str());
	//TODO try to avoid this unsafe
	let ret = unsafe { buffer.leak_cstr() };
    Ok(ret)
}

/// Enigma SEND function
#[pg_extern(stable, parallel_safe, requires = [ "shell_type" ])]
fn enigma_send(enigma: Enigma) 
-> Result<Vec<u8>, Box<(dyn std::error::Error + 'static)>> {
	//debug2!("SEND");
	debug5!("SEND: {}", enigma);
    let decrypted = PRIV_KEYS.decrypt(enigma)?;
    Ok(decrypted.to_string().into_bytes())
}


/// Enigma TYPMOD_IN function.
/// converts typmod from cstring to i32
#[pg_extern(immutable, parallel_safe, requires = [ "shell_type" ])]
fn enigma_typmod_in(input: Array<&CStr>) 
-> Result<i32, Box<(dyn std::error::Error + 'static)>> {
	debug2!("TYPMOD_IN");
    if input.len() != 1 {
        return Err(
            "Enigma type modifier must be a single integer value".into());
    }
    let typmod = input.iter() // iterator
    .next() // Option<Item>
    .ok_or("No Item")? // Item
    .ok_or("Null item")? // &Cstr
    .to_str()? //&str
    .parse::<i32>()?; // i32
    debug1!("typmod_in({typmod})");
    if typmod < 0 {
        return Err(
            "Enigma type modifier must be a positive integer".into());
    }
    Ok(typmod)
}



/// SQL function for setting private key in memory (PrivKeysMap)
/// All in-memory private keys will be lost when session is closed
/// and postgres sessionprocess ends.
#[pg_extern(stable)]
fn set_private_key(id: i32, key: &str, pass: &str)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    if id < 1 {
        return Err("Key id must be a positive integer".into());
    }
    PRIV_KEYS.set(id as u32, key, pass)
}

// TODO: polymorphic set_private_key() without pass
// TODO: polymorphic set_private_key() without typmod (key_id 0)


/// SQL function for setting public key in memory (PubKeysMap)
/// Also inserts provided public key into enigma public keys table, 
/// making it available for other sessions.
#[pg_extern(volatile, requires = [ "shell_type" ])]
fn set_public_key(id: i32, key: &str)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    if id < 1 {
        return Err("Key id must be a positive integer".into());
    }
    match insert_public_key(id, key)? {
        Some(_) => PUB_KEYS.set(id as u32, key),
        None => Err(format!("No key ({}) inserted", id).into())
    }
}

// TODO: polymorphic set_public_key() without typmod (key_id 0)
// TODO: insert_public_key() Postgres function

/// Delete the private key from memory (PrivKeysMap)
#[pg_extern(stable)]
fn forget_private_key(id: i32)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    if id < 1 {
        return Err("Key id must be a positive integer".into());
    }
    PRIV_KEYS.del(id as u32)
}

/// Delete the public key from memory (PubKeysMap)
#[pg_extern(stable)]
fn forget_public_key(id: i32)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    if id < 1 {
        return Err("Key id must be a positive integer".into());
    }
    PUB_KEYS.del(id as u32)
}

// TODO: delete_public_key() Postgres function

/// Sets the private key reading it from a file
#[pg_extern(stable)]
fn set_private_key_from_file(id: i32, file_path: &str, pass: &str)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    let contents = fs::read_to_string(file_path)
    .expect("Error reading private key file");
    set_private_key(id, &contents, pass)
}

/// Sets the public key reading it from a file
#[pg_extern(stable)]
fn set_public_key_from_file(id: i32, file_path: &str)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    let contents = fs::read_to_string(file_path)
        .expect("Error reading public file");
    set_public_key(id, &contents)
}


/**************************************************************************
*                                                                         *
*                                                                         *
*           S Q L   F O R   C R E A T E   E X T E N S I O N               *
*                                                                         *
*                                                                         *
**************************************************************************/


// Enigma shell_type
extension_sql_file!("../sql/shell_type.sql", bootstrap);


// Create the real type
extension_sql_file!("../sql/concrete_type.sql", creates = [Type(Enigma)],
    requires = ["shell_type", enigma_input, enigma_output, 
    enigma_receive, enigma_send, enigma_typmod_in],
);

// Creates the casting function so we can get the key id in the
// typmod value, this is needed because postgres does not send 
// the typmod to the input function.
// https://stackoverflow.com/questions/40406662/postgres-doc-regaring-input-function-for-create-type-does-not-seem-to-be-correct/74426960#74426960
// https://www.postgresql.org/message-id/67091D2B.5080002%40acm.org
extension_sql_file!("../sql/enigma_casts.sql",
    requires = ["concrete_type", enigma_as_enigma]
);


/**************************************************************************
*                                                                         *
*                                                                         *
*                       T E S T  F U N C T I O N S                        *
*                                                                         *
*                                                                         *
**************************************************************************/

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    //use crate::Enigma;
    use crate::enigma::Enigma;
    use pgrx::prelude::*;
    use std::error::Error;
 
    /// Just create a table with type Enigma with typmod
    #[pg_test]
    fn e01_create_table_with_enigma()  -> Result<(), Box<dyn Error>> {
        Spi::run(
        "
CREATE TABLE testab ( a SERIAL, b Enigma(2));
        ")?;
        if let Some(res) = Spi::get_one::<i64>("
SELECT count(a) FROM testab;
        ")? {
            if res == 0 { return Ok(()); }
        } 
        Err("Should return count: 0".into())
    }

    /// Create the table, then try to insert a row in the table without 
    /// setting the public key.
    /// `INSERT` should fail with error "No public key with id"
    #[pg_test]
    #[should_panic]
    fn e02_insert_without_pub_key()  -> Result<(), Box<dyn Error>> {
        Ok(Spi::run(
        "
CREATE TABLE testab ( a SERIAL, b Enigma(2));
INSERT INTO testab (b) VALUES ('my first record');
        ")?) // Err( No public key )
    }

    /// Ser wrong public key should fail
    #[pg_test]
    #[should_panic]
    fn e03_set_wrong_pub_key()  -> Result<(), Box<dyn Error>> {
        Ok(Spi::run(
        "
SELECT set_public_key(2, '--- INVALID KEY ---'); 
        ")?) // Err( key type not supported )
    }

    /// Ser wrong private key should fail
    #[pg_test]
    #[should_panic]
    fn e04_set_wrong_priv_key()  -> Result<(), Box<dyn Error>> {
        Ok(Spi::run(
        "
SELECT set_private_key(2, '--- INVALID KEY ---', 'bad pass'); 
        ")?) // Err( key type not supported )
    }

    /// Just set the public key. 
    /// Should not fail unless public key file is not there.
    #[pg_test]
    fn e05_set_public_key()  -> Result<(), Box<dyn Error>> {
        use std::env;
        let path = env::current_dir()?;
        debug1!("The current directory is {}", path.display());
        // pwd seems to be pg_enigma/target/test-pgdata/13
        Spi::run(
        "
SELECT set_public_key_from_file(2, '../../../test/public-key.asc'); 
        ")?;
        if let Some(res) = Spi::get_one::<String>("
SELECT public_key FROM _enigma_public_keys WHERE id = 2;
        ")? {
            if res.contains("BEGIN PGP PUBLIC KEY") { return Ok(()); }
        } 
        Err("Should return String with PGP public key".into())
    }

    /// Insert a row in the table and then query the encrypted value
    #[pg_test]
    fn e06_insert_with_pub_key()  -> Result<(), Box<dyn Error>> {
        Spi::run(
        "
CREATE TABLE testab ( a SERIAL, b Enigma(2));
SELECT set_public_key_from_file(2, '../../../test/public-key.asc'); 
INSERT INTO testab (b) VALUES ('my PGP test record');
        ")? ; 
        if let Some(res) = Spi::get_one::<Enigma>("
SELECT b FROM testab LIMIT 1;
        ")? {
            if res.is_pgp() { return Ok(()); }
        } 
        Err("Should return String with PGP message".into()) 
    }

    /// Insert a row in the table, then set private key and then 
    /// query the decrypted value
    #[pg_test]
    fn e07_select_with_priv_key()  -> Result<(), Box<dyn Error>> {
        Spi::run(
        "
CREATE TABLE testab ( a SERIAL, b Enigma(2));
SELECT set_public_key_from_file(2, '../../../test/public-key.asc'); 
INSERT INTO testab (b) VALUES ('my PGP test record');
SELECT set_private_key_from_file(2, 
    '../../../test/private-key.asc', 'Prueba123!'); 
        ")? ; 
        if let Some(res) = Spi::get_one::<Enigma>("
SELECT b FROM testab LIMIT 1;
        ")? {
            info!("Decrypted value: {}", res);
            if res.value() == String::from("my PGP test record") {
                return Ok(());
            }
        } 
        Err("Should return decrypted string".into()) 
    } 

    /// Insert a row in the table and then query the encrypted value
    #[pg_test]
    fn e08_insert_with_rsa_pub_key()  -> Result<(), Box<dyn Error>> {
        Spi::run(
        "
CREATE TABLE testab ( a SERIAL, b Enigma(3));
SELECT set_public_key_from_file(3, '../../../test/alice_public.pem'); 
INSERT INTO testab (b) VALUES ('my RSA test record');
        ")? ; 
        if let Some(res) = Spi::get_one::<Enigma>("
SELECT b FROM testab LIMIT 1;
        ")? {
            if res.is_rsa() { return Ok(()); }
        } 
        Err("Should return String with RSA encrypted message".into()) 
    }

    /// Insert a row in the table, then set private key and then 
    /// query the decrypted value
    #[pg_test]
    fn e09_select_with_rsa_priv_key()  -> Result<(), Box<dyn Error>> {
        Spi::run(
        "
CREATE TABLE testab ( a SERIAL, b Enigma(3));
SELECT set_public_key_from_file(3, '../../../test/alice_public.pem'); 
INSERT INTO testab (b) VALUES ('my RSA test record');
SELECT set_private_key_from_file(3, 
    '../../../test/alice_private.pem', 'Prueba123!'); 
        ")? ; 
        if let Some(res) = Spi::get_one::<Enigma>("
SELECT b FROM testab LIMIT 1;
        ")? {
            info!("Decrypted value: {}", res);
            if res.value() == String::from("my RSA test record") {
                return Ok(());
            }
        } 
        Err("Should return decrypted string".into()) 
    } 

    /// This test is just a cast from String to Enigma
    /// String get through INPUT and then typmod CAST
    #[pg_test]
    fn e10_select_string_as_enigma()  -> Result<(), Box<dyn Error>> {
        Spi::run(
        "
SELECT set_public_key_from_file(2, '../../../test/public-key.asc'); 
        ")? ;  
        if let Some(res) = Spi::get_one::<Enigma>("
SELECT 'my CAST test record'::Enigma(2);
        ")? {
            info!("Encrypted value: {}", res);
            if res.value().as_str() != "my CAST test record" { return Ok(()); }
        } 
        Err("Should return encrypted string".into()) 
    } 

    /// This test is just a cast from String to Enigma
    /// String get through INPUT and then typmod CAST
    /// Unlike e10, key 2 is delete from PubKeysMap, so it has to be 
    /// retrieved from public keys table first 
    #[pg_test]
    fn e11_pub_keys_from_sql()  -> Result<(), Box<dyn Error>> {
        Spi::run(
        "
SELECT set_public_key_from_file(2, '../../../test/public-key.asc'); 
-- deletes the key from PubKeysMap to need from_sql
SELECT forget_public_key(2);
        ")? ;  
        if let Some(res) = Spi::get_one::<Enigma>("
SELECT 'my CAST test record'::Enigma(2);
        ")? {
            info!("Encrypted value: {}", res);
            if res.value().as_str() != "my CAST test record" { return Ok(()); }
        } 
        Err("Should return encrypted string".into()) 
    } 

    /// Insert a row in the table, then set private key and then 
    /// query the decrypted value.
    /// Using `CAST(Enigma AS Text)` will force casting througn the 
    /// OUTPUT function.
    #[pg_test]
    fn e12_decrypt_pgp_casting_as_text()  -> Result<(), Box<dyn Error>> {
        Spi::run(
        "
CREATE TABLE testab ( a SERIAL, b Enigma(2));
SELECT set_public_key_from_file(2, '../../../test/public-key.asc'); 
INSERT INTO testab (b) VALUES ('my PGP test record');
SELECT set_private_key_from_file(2, 
    '../../../test/private-key.asc', 'Prueba123!'); 
        ")? ; 
        if let Some(res) = Spi::get_one::<String>("
SELECT CAST(b AS Text) FROM testab LIMIT 1;
        ")? {
            info!("Decrypted value: {}", res);
            if res.as_str() == "my PGP test record" { return Ok(()); }
        } 
        Err("Should return decrypted string".into()) 
    } 

    /// Insert a row in the table, then set private key and then 
    /// query the decrypted value
    /// Using `CAST(Enigma AS Text)` will force casting througn the 
    /// OUTPUT function.
    #[pg_test]
    fn e13_decrypt_rsa_casting_as_text()  -> Result<(), Box<dyn Error>> {
        Spi::run(
        "
CREATE TABLE testab ( a SERIAL, b Enigma(3));
SELECT set_public_key_from_file(3, '../../../test/alice_public.pem'); 
INSERT INTO testab (b) VALUES ('my RSA test record');
SELECT set_private_key_from_file(3, 
    '../../../test/alice_private.pem', 'Prueba123!'); 
        ")? ; 
        if let Some(res) = Spi::get_one::<String>("
SELECT CAST(b AS Text) FROM testab LIMIT 1;
        ")? {
            info!("Decrypted value: {}", res);
            if res.as_str() == "my RSA test record" { return Ok(()); }
        } 
        Err("Should return decrypted string".into()) 
    } 

}

/// This module is required by `cargo pgrx test` invocations.
/// It must be visible at the root of your extension crate.
#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {
        // perform one-off initialization when the pg_test framework starts
    }

    pub fn postgresql_conf_options() -> Vec<&'static str> {
        // return any postgresql.conf settings that are required for your tests
        vec![]
    }
}




