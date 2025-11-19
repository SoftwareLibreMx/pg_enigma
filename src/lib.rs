mod common;
mod enigma;
mod enigma_pgp;
mod key_map;
mod pgp;
mod priv_key;
mod pub_key;

use crate::key_map::{PrivKeysMap,PubKeysMap};
use crate::pub_key::insert_public_key;
use once_cell::sync::Lazy;
use pgrx::prelude::*;
use std::fs;


pgrx::pg_module_magic!();

static PRIV_KEYS: Lazy<PrivKeysMap> = Lazy::new(|| PrivKeysMap::new());
static PUB_KEYS: Lazy<PubKeysMap> = Lazy::new(|| PubKeysMap::new());




/// SQL function for setting private key in memory (PrivKeysMap)
/// All in-memory private keys will be lost when session is closed
/// and postgres sessionprocess ends.
#[pg_extern(stable)]
fn set_private_key(id: i32, key: &str, pass: &str)
-> Result<String, Box<dyn std::error::Error + 'static>> {
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
-> Result<String, Box<dyn std::error::Error + 'static>> {
    if id < 0 { // TODO: Polymorphic default (without ID)
        return Err("Key id must be zero or greater".into());
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
-> Result<String, Box<dyn std::error::Error + 'static>> {
    if id < 1 {
        return Err("Key id must be a positive integer".into());
    }
    PRIV_KEYS.del(id as u32)
}

/// Delete the public key from memory (PubKeysMap)
#[pg_extern(stable)]
fn forget_public_key(id: i32)
-> Result<String, Box<dyn std::error::Error + 'static>> {
    if id < 1 {
        return Err("Key id must be a positive integer".into());
    }
    PUB_KEYS.del(id as u32)
}

// TODO: delete_public_key() Postgres function

/// Sets the private key reading it from a file
#[pg_extern(stable)]
fn set_private_key_from_file(id: i32, file_path: &str, pass: &str)
-> Result<String, Box<dyn std::error::Error + 'static>> {
    let contents = fs::read_to_string(file_path)
    .expect("Error reading private key file");
    set_private_key(id, &contents, pass)
}

/// Sets the public key reading it from a file
#[pg_extern(stable)]
fn set_public_key_from_file(id: i32, file_path: &str)
-> Result<String, Box<dyn std::error::Error + 'static>> {
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
    requires = ["concrete_type", enigma_as_enigma, string_as_enigma]
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
    /// Since INPUT typmod is ambiguous INSERT will cast as ::Text 
    #[pg_test]
    fn e06_insert_with_pub_key()  -> Result<(), Box<dyn Error>> {
        Spi::run(
        "
CREATE TABLE testab ( a SERIAL, b Enigma(2));
SELECT set_public_key_from_file(2, '../../../test/public-key.asc'); 
INSERT INTO testab (b) VALUES ('my PGP test record'::Text);
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
    /// Since INPUT typmod is ambiguous INSERT will cast as ::Text 
    #[pg_test]
    fn e07_select_with_priv_key()  -> Result<(), Box<dyn Error>> {
        Spi::run(
        "
CREATE TABLE testab ( a SERIAL, b Enigma(2));
SELECT set_public_key_from_file(2, '../../../test/public-key.asc'); 
INSERT INTO testab (b) VALUES ('my PGP test record'::Text);
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
    /// Since INPUT typmod is ambiguous INSERT will cast as ::Text 
    #[pg_test]
    fn e08_insert_with_rsa_pub_key()  -> Result<(), Box<dyn Error>> {
        Spi::run(
        "
CREATE TABLE testab ( a SERIAL, b Enigma(3));
SELECT set_public_key_from_file(3, '../../../test/alice_public.pem'); 
INSERT INTO testab (b) VALUES ('my RSA test record'::Text);
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
    /// Since INPUT typmod is ambiguous INSERT will cast as ::Text 
    #[pg_test]
    fn e09_select_with_rsa_priv_key()  -> Result<(), Box<dyn Error>> {
        Spi::run(
        "
CREATE TABLE testab ( a SERIAL, b Enigma(3));
SELECT set_public_key_from_file(3, '../../../test/alice_public.pem'); 
INSERT INTO testab (b) VALUES ('my RSA test record'::Text);
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
    /// Since INPUT typmod is ambiguous ASSIGNMENT cast is needed 
    #[pg_test]
    fn e10_select_string_as_enigma()  -> Result<(), Box<dyn Error>> {
        Spi::run(
        "
SELECT set_public_key_from_file(2, '../../../test/public-key.asc'); 
        ")? ;  
        if let Some(res) = Spi::get_one::<Enigma>("
SELECT 'my CAST test record'::Text::Enigma(2);
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
    /// Since INPUT typmod is ambiguous ASSIGNMENT cast is needed 
    #[pg_test]
    fn e11_pub_keys_from_sql()  -> Result<(), Box<dyn Error>> {
        Spi::run(
        "
SELECT set_public_key_from_file(2, '../../../test/public-key.asc'); 
-- deletes the key from PubKeysMap to need from_sql
SELECT forget_public_key(2);
        ")? ;  
        if let Some(res) = Spi::get_one::<Enigma>("
SELECT 'my CAST test record'::Text::Enigma(2);
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
    /// Since INPUT typmod is ambiguous INSERT will cast as ::Text 
    #[pg_test]
    fn e12_decrypt_pgp_casting_as_text()  -> Result<(), Box<dyn Error>> {
        Spi::run(
        "
CREATE TABLE testab ( a SERIAL, b Enigma(2));
SELECT set_public_key_from_file(2, '../../../test/public-key.asc'); 
INSERT INTO testab (b) VALUES ('my PGP test record'::Text);
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
    /// Since INPUT typmod is ambiguous INSERT will cast as ::Text 
    #[pg_test]
    fn e13_decrypt_rsa_casting_as_text()  -> Result<(), Box<dyn Error>> {
        Spi::run(
        "
CREATE TABLE testab ( a SERIAL, b Enigma(3));
SELECT set_public_key_from_file(3, '../../../test/alice_public.pem'); 
INSERT INTO testab (b) VALUES ('my RSA test record'::Text);
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




