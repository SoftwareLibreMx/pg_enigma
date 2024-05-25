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
        if KEY != None {
            value = decrypt(value);
        } else {
            value = format!("NO KEY DEFINED THIS VALUE IS ENCRYPTED: {}", value);
        }

        buffer.push_str(&format!("{}", value));
    }
}

/// Encrypts the value
pub fn decrypt(value: String) -> String {
    format!("DECRYPTED {}", value)
}

/// Decrypts the value
pub fn encrypt(value: String) -> String {
    format!("ENCRYPTED {}", value)
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
