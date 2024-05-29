use pgrx::prelude::*;
use serde::{Serialize, Deserialize};
use std::fmt::{Display, Formatter};
use pgrx::{StringInfo};
use core::ffi::CStr;

::pgrx::pg_module_magic!();

//TODO: temporal key for testing

static KEY: Option<&str> = Some("SUPER SECRET KEY");

/// Value stores entcrypted information
#[derive(Serialize, Deserialize, PostgresType)]
#[inoutfuncs]
struct Enigma {
    value: String,
}

/// Functions for extracting and inserting data
impl InOutFuncs for Enigma {
    // Get from postgres
    fn input(input: &CStr) -> Self {
        let mut value: String = input
                .to_str()
                .expect("Enigma::input can't convert to str")
                .to_string();

        // TODO: better error handling
        if KEY != None {
            value = encrypt(value);
        } else {
            value = format!("NO KEY DEFINED");
        }

        Enigma {
            value: value.clone(),
        }
    }

    // Send to postgres
    fn output(&self, buffer: &mut StringInfo) {

        let mut value: String = self.value.clone();

        // TODO: better error handling
		value = match get_private_key().expect("Error getting private key") {
            Some(pk) => decrypt(value, pk),
            None     => format!("NO KEY DEFINED THIS VALUE IS ENCRYPTED: {}", value),
        };

        buffer.push_str(&format!("{}", value));
    }
}

/// Encrypts the value
pub fn decrypt(value: String, private_key: String) -> String {
    format!("DECRYPTED {} by {}", value, private_key)
}

/// Decrypts the value
pub fn encrypt(value: String) -> String {
    format!("ENCRYPTED {}", value)
}


/// TODO: add docs
#[pg_extern]
//fn set_private_key(id i32, key: &str) -> Result<Option<String>, spi::Error> {
fn set_private_key(key: &str) -> Result<Option<String>, spi::Error> {
	let id = 1; // TODO: accept as parameter
	create_key_table()?;
    Spi::get_one_with_args(
        r#"INSERT INTO temp_keys(id, private_key) VALUES ($1, $2) ON CONFLICT(id)
		   DO UPDATE SET private_key=$2 RETURNING 'Private key set'"#,
        vec![
			(PgBuiltInOids::INT4OID.oid(), id.into_datum()),
			(PgBuiltInOids::TEXTOID.oid(), key.into_datum())
		],
    )
}


/// TODO: add docs
#[pg_extern]
//fn set_public_key(id i32, key: &str) -> Result<Option<String>, spi::Error> {
fn set_public_key(key: &str) -> Result<Option<String>, spi::Error> {
	let id = 1; // TODO: accept as parameter
	create_key_table()?;
    Spi::get_one_with_args(
        r#"INSERT INTO temp_keys(id, public_key) VALUES ($1, $2) ON CONFLICT(id)
		   DO UPDATE SET public_key=$2 RETURNING 'Public key set'"#,
        vec![
			(PgBuiltInOids::INT4OID.oid(), id.into_datum()),
			(PgBuiltInOids::TEXTOID.oid(), key.into_datum())
		],
    )
}

#[pg_extern(immutable, parallel_safe)]
fn get_private_key() -> Result<Option<String>, pgrx::spi::Error> {
    Spi::get_one("SELECT private_key FROM temp_keys WHERE id = 1")
}

#[pg_extern(immutable, parallel_safe)]
fn get_public_key() -> Result<Option<String>, pgrx::spi::Error> {
    Spi::get_one("SELECT public_key FROM temp_keys WHERE id = 1")
}


#[pg_extern]
fn create_key_table() -> Result<(), spi::Error> {
    Spi::run(
        "CREATE TEMPORARY TABLE IF NOT EXISTS temp_keys (id INT PRIMARY KEY, private_key TEXT, public_key TEXT)"
    )
}

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use pgrx::prelude::*;

    #[pg_test]
    fn test_hello_pg_enigma() {
        assert_eq!("Hello, pg_enigma", crate::hello_pg_enigma());
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
