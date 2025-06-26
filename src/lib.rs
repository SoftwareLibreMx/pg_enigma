mod functions;
mod key_map;
mod message;
mod priv_key;
mod pub_key;
mod traits;

use core::ffi::CStr;
use crate::message::EnigmaMsg;
use crate::functions::*;
use crate::key_map::{PrivKeysMap,PubKeysMap};
use once_cell::sync::Lazy;
use pgrx::prelude::*;
use pgrx::{rust_regtypein, StringInfo};
use pgrx::pgrx_sql_entity_graph::metadata::{
    ArgumentError, Returns, ReturnsError, SqlMapping, SqlTranslatable,
};
use pgrx::callconv::{ArgAbi, BoxRet};
use pgrx::datum::Datum;
use pgrx::pg_sys::Oid;
use std::fmt::{Display, Formatter};
use std::fs;


pgrx::pg_module_magic!();

static PRIV_KEYS: Lazy<PrivKeysMap> = Lazy::new(|| PrivKeysMap::new());
static PUB_KEYS: Lazy<PubKeysMap> = Lazy::new(|| PubKeysMap::new());

/// Value stores entcrypted information
#[repr(transparent)]
#[derive( Clone, Debug)]
struct Enigma {
    value: String,
}


/// Functions for extracting and inserting data
#[pg_extern(immutable, parallel_safe, requires = [ "shell_type" ])]
fn enigma_input_with_typmod(input: &CStr, oid: pg_sys::Oid, typmod: i32) 
-> Enigma {
	debug2!("enigma_input_with_typmod: \
            ARGUMENTS: Input: *****, OID: {:?},  Typmod: {}", oid, typmod);
	let value: String = input
			.to_str()
			.expect("Enigma::input can't convert to str")
			.to_string();
    let plain = EnigmaMsg::plain(value);
    if typmod == -1 { // unknown typmod 
        debug1!("Unknown typmod: {}\noid: {:?}", typmod, oid);
        return Enigma::try_from(plain).unwrap(); // Plain is always Ok()
    }
    let key_id = typmod;
    let encrypted = PUB_KEYS.encrypt(key_id, plain) // Result
                            .expect("Encrypt (input)"); // EnigmaMsg
    Enigma::from(encrypted)
}

/// Cast enigma to enigma is called after enigma_input_with_typmod(). 
/// This function is passed the correct known typmod argument.
#[pg_extern]
fn enigma_cast(original: Enigma, typmod: i32, explicit: bool) -> Enigma {
    debug2!("enigma_cast: \
        ARGUMENTS: explicit: {},  Typmod: {}", explicit, typmod);
    if typmod == -1 {
        panic!("Unknown typmod: {}\noriginal: {:?}\nexplicit: {}", 
            typmod, original, explicit);
    }
    //debug5!("Original: {:?}", original);
    let msg = EnigmaMsg::try_from(original).expect("Corrupted Enigma");
    if msg.is_plain() {
        let key_id = typmod;
        debug2!("Encrypting plain message with key ID: {key_id}");
        let encrypted = PUB_KEYS.encrypt(key_id, msg) // Result
                        .expect("Encrypt (typmod cast)"); // EnigmaMsg
        return Enigma::from(encrypted);
    } 
    
    // TODO: if msg.key_id != key_id {try_reencrypt()} 
    Enigma::from(msg)
}

/* TODO: Receive function for Enigma
    The optional receive_function converts the type's external binary 
    representation to the internal representation.
    The receive function can be declared as taking one argument of type 
    internal, or as taking three arguments of types internal, oid, integer.
    The first argument is a pointer to a StringInfo buffer holding the 
    received byte string; the optional arguments are the same as for the 
    text input function. 
    The receive function must return a value of the data type itself.

#[pg_extern]
fn enigma_receive(input: PgBox<StringInfo>) -> Enigma {

    /*let cstr_input = unsafe { CStr::from_ptr(input.as_ptr()) };
        
    let oid = rust_regtypein::<Enigma>();
    enigma_input_with_typmod(cstr_input, oid, -1) */
    Enigma { value: ".oOo.".into() }
} */


// Send to postgres
// TODO check if we can return just StringInfo
#[pg_extern(immutable, parallel_safe, requires = [ "shell_type" ])]
fn enigma_output(e: Enigma) -> &'static CStr {
	debug2!("enigma_output: Entering enigma_output");
	let mut buffer = StringInfo::new();
	let message  = EnigmaMsg::try_from(e).expect("Corrupted Enigma");

	// debug3!("enigma_output value: {}", message);

    // TODO: workaround double decrypt()
     // if decrypting key is not set, returns the same message
     match PRIV_KEYS.decrypt(message) {
		Ok(m) => buffer.push_str(m.to_string().as_str()),
		Err(e) =>  panic!("Decrypt error: {}", e)
	}

	//TODO try to avoid this unsafe
	unsafe { buffer.leak_cstr() }
}

#[pg_extern(immutable, parallel_safe, requires = [ "shell_type" ])]
fn enigma_send(e: Enigma) -> &'static [u8] {
	enigma_output(e).to_bytes()
}


/// Needed for managing keys for each column
/// We mark this function as `immutable` because its output depends ONLY on its inputs.
/// This is required for functions used as a `TYPMOD_IN`, as the planner needs
/// to rely on its output being consistent.
#[pg_extern(immutable, name = "enigma_type_modifier_input", requires = [ "shell_type" ])]
pub fn enigma_type_modifier_input(cstrings: pgrx::Array<'_, &CStr>) -> i32 {

    // TODO: enigma_typmod_in() from KBrown/TypmodInOutFuncs is simpler
    let rust_strings: Vec<&str> = cstrings
        .iter()
        .flatten()
        .map(|cstr| cstr.to_str().unwrap_or_default())
        .collect();

    debug2!("enigma_type_modifier_input:: value {}", 
        rust_strings[0].parse::<i32>().unwrap());

    rust_strings[0]
        .parse::<i32>()
        .expect("Canto convert typmod to integer")
}



/// SQL function for setting private key in memory (PrivKeysMap)
/// All in-memory private keys will be lost when session is closed
/// and postgres sessionprocess ends.
#[pg_extern]
fn set_private_key(id: i32, key: &str, pass: &str)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    PRIV_KEYS.set(id, key, pass)
}   


/// SQL function for setting public key in memory (PubKeysMap)
/// Also inserts provided public key into enigma public keys table, 
/// making it available for other sessions.
#[pg_extern]
fn set_public_key(id: i32, key: &str)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    match insert_public_key(id, key)? {
        Some(_) => PUB_KEYS.set(id, key),
        None => Err(format!("No key ({}) inserted", id).into())
    }
}

/// Delete the private key from memory (PrivKeysMap)
#[pg_extern]
fn forget_private_key(id: i32)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    PRIV_KEYS.del(id)
}

/// Delete the public key from memory (PubKeysMap)
#[pg_extern]
fn forget_public_key(id: i32)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    PUB_KEYS.del(id)
}

/// Sets the private key reading it from a file
#[pg_extern]
fn set_private_key_from_file(id: i32, file_path: &str, pass: &str)
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    let contents = fs::read_to_string(file_path)
    .expect("Error reading private key file");
    set_private_key(id, &contents, pass)
}

/// Sets the public key reading it from a file
#[pg_extern]
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


// Create the type manually
extension_sql!(
    r#"
        CREATE TYPE enigma;
    "#,
    name = "shell_type",
    // declare this extension_sql block as the "bootstrap" block 
    // so it happens first in sql generation
    bootstrap 
);


// Create the real type
extension_sql!(
    r#"
        CREATE TYPE enigma (
            INPUT  = enigma_input_with_typmod,
            OUTPUT = enigma_output,
            TYPMOD_IN = enigma_type_modifier_input
        );
    "#,
    name = "concrete_type",
    creates = [Type(Enigma)],
    requires = ["shell_type", enigma_input_with_typmod, enigma_output, enigma_type_modifier_input],
);

// Creates the casting function so we can get the key id in the
// typmod value, this is needed because postgres does not send 
// the typmod to the input function.
// https://stackoverflow.com/questions/40406662/postgres-doc-regaring-input-function-for-create-type-does-not-seem-to-be-correct/74426960#74426960
// https://www.postgresql.org/message-id/67091D2B.5080002%40acm.org
extension_sql!(
    r#"
    CREATE CAST (enigma AS enigma) WITH FUNCTION enigma_cast AS IMPLICIT;
    "#,
    name = "enigma_casts",
    requires = ["concrete_type", enigma_cast]
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
    use crate::Enigma;
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
SELECT public_key FROM enigma_public_keys WHERE id = 2;
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
            if res.value.contains("BEGIN PGP MESSAGE") { return Ok(()); }
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
            if res.value.as_str() == "my PGP test record" { return Ok(()); }
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
            if res.value.contains("BEGIN RSA ENCRYPTED") { return Ok(()); }
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
            if res.value.as_str() == "my RSA test record" { return Ok(()); }
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
            if res.value.as_str() != "my CAST test record" { return Ok(()); }
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
            if res.value.as_str() != "my CAST test record" { return Ok(()); }
        } 
        Err("Should return encrypted string".into()) 
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



/**************************************************************************
*                                                                         *
*                                                                         *
*                B O I L E R P L A T E  F U N C T I O N S                 *
*                                                                         *
*                                                                         *
**************************************************************************/

// Boilerplate traits for converting type to postgres internals
// Needed for the FunctionMetadata trait
unsafe impl SqlTranslatable for Enigma {
    fn argument_sql() -> Result<SqlMapping, ArgumentError> {
        // this is what the SQL type is called when used in a function argument position
        Ok(SqlMapping::As("enigma".into()))
    }

    fn return_sql() -> Result<Returns, ReturnsError> {
        // this is what the SQL type is called when used in a function return type position
        Ok(Returns::One(SqlMapping::As("enigma".into())))
    }
}


unsafe impl<'fcx> ArgAbi<'fcx> for Enigma
where
    Self: 'fcx,
{
    unsafe fn unbox_arg_unchecked(arg: ::pgrx::callconv::Arg<'_, 'fcx>) -> Self {
        unsafe { arg.unbox_arg_using_from_datum().unwrap() }
    }
}


unsafe impl BoxRet for Enigma {
    unsafe fn box_into<'fcx>(self, 
    fcinfo: &mut pgrx::callconv::FcInfo<'fcx>) 
    -> Datum<'fcx> {
        fcinfo.return_raw_datum(
           self.value.into_datum()
                .expect("Can't convert enigma value into Datum")
        )
    }
}

impl FromDatum for Enigma {
    unsafe fn from_polymorphic_datum(datum: pg_sys::Datum, 
    is_null: bool, _: Oid) 
    -> Option<Self>
    where
        Self: Sized,
    {
        if is_null {
            return None;
        }  
        let value = match String::from_datum(datum, is_null) {
            None => return None,
            Some(v) => v
        };
        // debug5!("FromDatum value:\n{value}");
        let message = EnigmaMsg::try_from(value).expect("Corrupted Enigma");
        //debug5!("FromDatum: Encrypted message: {:?}", message);
        let decrypted = PRIV_KEYS.decrypt(message)
                                .expect("FromDatum: Decrypt error");
        //debug5!("FromDatum: Decrypted message: {:?}", decrypted);
        match decrypted {
            EnigmaMsg::Plain(m) => Some(Enigma{value: m}),
            _ => Some(Enigma::from(decrypted))
        }
    }
}

impl IntoDatum for Enigma {
    fn into_datum(self) -> Option<pg_sys::Datum> {
        Some(
			self.value
				.into_datum()
				.expect("Can't convert enigma value to Datum!")
		)
    }

    fn type_oid() -> Oid {
        rust_regtypein::<Self>()
    }
}

impl Display for Enigma {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}
