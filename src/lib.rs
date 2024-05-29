use pgrx::prelude::*;
use serde::{Serialize, Deserialize};
use std::fmt::{Display, Formatter};
use pgrx::{StringInfo};
use core::ffi::CStr;
use pgp::{SignedSecretKey, Deserializable};
use pgp::SignedPublicKey;
use pgp::composed::message::Message;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use rand::prelude::*;
use pgp::types::Version;
use pgp::armor::Dearmor;
use std::io::Cursor;

::pgrx::pg_module_magic!();

//TODO: temporal key for testing

static PRV_KEY: Option<&str> =Some("-----BEGIN PGP PRIVATE KEY BLOCK-----

lQIGBGZXG+YBBACpVTBmm+44K5G0g5qtc53jdIckb4FS8N0kiDp4iiC4iST0Ck2D
yxNIPhmIfs18wkaktEFnTqe9NN4v3jiW0TSwlZZF+Kv9Ubl3w6GObuUZbEhF3+qf
myerbWCObAOYd+suwPZu3zwil8HEl1jp+/zon0Aci1kUU9t18EXMjvs8wwARAQAB
/gcDAjp9hSW76Ju57+QsI7mCJlXJB3BOdXmZy0KqP7lQLbZD+LDAI0OX+K3SjLS0
+bAd4gZ41Nqy+Qwvx4a4eDlex9ybVKIeCum0PYBf7AFiEuaz9to+hEvwwcEpigvy
lQr8Y8wM1OitDgBpDmq6dIx7a3umyWkpy9uAPJ45XNnUmxH/nYAn44KGKPRK7YX4
uUhMDann4+NUCsz6BpmLyBaiAuLgzwYW5THUF9vziX99oBhc6D4XJIuKOQTho+11
Bn5eLtYCfQeyxrnLiXPxFuhVb7LbBFPcmpfF6wXVzxgTou2BPY9VLlv529jF6LXo
YctO7FKEedTKpkMgflDbRHFaf8nMX/1qQ7D+J1B/U0NEQLmcFlWXH093gToNok3Y
qPzBNjsUOYhPuuG0as+oQoFlB/KeNpWpoTP0CByY+Kd1pNDTSzKbdEnnKJdc5lzl
Bfo8mzKHsE6VDKPneoTJR3Z1kgbyonHGgJNbiYBoOpVg21PiD0utNES0EnBnX2Vu
aWdtYSB0ZXN0IGtleYjUBBMBCAA+FiEEGAGYSm//v0++hluiy31dohr4uGAFAmZX
G+YCGwMFCQAJOoAFCwkIBwMFFQoJCAsFFgIDAQACHgUCF4AACgkQy31dohr4uGAc
lAQAoAeB/WTnIrWLLLq/izcJGmzlyguReIk3pR93HJcB4CzLOljyrNG/QE7UezN7
bfLp9vqX35LxYhVR22ioROz0jEJM6f23Js1Mt9Nq9GiDxq7dBz4SFiRlPKXnXfOV
GgmmIyMaZ8+GHjYIbSNvDrwB19ojYGI9RcjuotKUj6m72+udAgYEZlcb5gEEAOEp
boygSI/89mU8nBtN6KkX73cpYxAUp6BIwtUFlr213Fy2WwMFclBY9a+6myRfE9jH
z1nt7dlwve+ET1TP7hIE1kWugouEP17VHlWGL6g3V8VuK+lENjlynuFD92M+XDHh
XNuieiGgcjjHyQu4sDZtIolIRlcOlhOBXHwGG3A7ABEBAAH+BwMCEusNDruJ36zv
Ae/VgEtRk/RQrYRekmHt0OAg6XmtAHwlbrgtMZ6D7vsZNLTKZNl+2HTnnpc3eSAY
aA874xm7Z7NiTr7nsc5sIhs8WL0Ub4jI1P20YaDjUHbqMnqzJ01B39bg6ujrCnHz
0aLhfcSgLhAKHfSwGmkV7WnWkDxu4sHe6N9B3H7x+b/oKrxUvmrPboppfwU5avvt
CpeIHdD91sZFTIf1BJNto4y6A3SRxEKKAMLXvYotP5Y1KCjS8LUxYCuia/vXe1jX
2t+h7s1Y+X6Q9LofssZLV/B2LywvqbvnHNygis9bZo+jgdnRZm/JUatBHAL1QZc0
VGaqr3QSLsPOPCTLe1micYWmxS3EX/F4wQB6Vadh+scjJzTPfeR6H1sHHW4JFlG0
fVUxKvdVdG4VI+5jwux8/RZKQEX/+Q2yrWt/wQA97PuiE2u0jyRVrWP/S0IDdSKE
AaYbDeM6UuUxi5AUEKYk4H6Gd3m/e6yVEItOv4i8BBgBCAAmFiEEGAGYSm//v0++
hluiy31dohr4uGAFAmZXG+YCGwwFCQAJOoAACgkQy31dohr4uGB/mgP9FF97K6SO
Vn77XUctBRm0FuLM/S/io8IsNlAivX2vrC7QSZoPbbVqhBPELCnPAAG+dk7y+i1w
dt/epY/+oiyprjgbfygBFet02xyKnCdAtStno8aUCu4hVNmdYcUCezr1AgXnYk2R
DdGpjenMdNnT6b0bjWcwT6cwfdmXKjzaUJs=
=DYQs
-----END PGP PRIVATE KEY BLOCK-----"); 

static PUB_KEY: Option<&str> = Some("-----BEGIN PGP PUBLIC KEY BLOCK-----

mI0EZlcb5gEEAKlVMGab7jgrkbSDmq1zneN0hyRvgVLw3SSIOniKILiJJPQKTYPL
E0g+GYh+zXzCRqS0QWdOp7003i/eOJbRNLCVlkX4q/1RuXfDoY5u5RlsSEXf6p+b
J6ttYI5sA5h36y7A9m7fPCKXwcSXWOn7/OifQByLWRRT23XwRcyO+zzDABEBAAG0
EnBnX2VuaWdtYSB0ZXN0IGtleYjUBBMBCAA+FiEEGAGYSm//v0++hluiy31dohr4
uGAFAmZXG+YCGwMFCQAJOoAFCwkIBwMFFQoJCAsFFgIDAQACHgUCF4AACgkQy31d
ohr4uGAclAQAoAeB/WTnIrWLLLq/izcJGmzlyguReIk3pR93HJcB4CzLOljyrNG/
QE7UezN7bfLp9vqX35LxYhVR22ioROz0jEJM6f23Js1Mt9Nq9GiDxq7dBz4SFiRl
PKXnXfOVGgmmIyMaZ8+GHjYIbSNvDrwB19ojYGI9RcjuotKUj6m72+u4jQRmVxvm
AQQA4SlujKBIj/z2ZTycG03oqRfvdyljEBSnoEjC1QWWvbXcXLZbAwVyUFj1r7qb
JF8T2MfPWe3t2XC974RPVM/uEgTWRa6Ci4Q/XtUeVYYvqDdXxW4r6UQ2OXKe4UP3
Yz5cMeFc26J6IaByOMfJC7iwNm0iiUhGVw6WE4FcfAYbcDsAEQEAAYi8BBgBCAAm
FiEEGAGYSm//v0++hluiy31dohr4uGAFAmZXG+YCGwwFCQAJOoAACgkQy31dohr4
uGB/mgP9FF97K6SOVn77XUctBRm0FuLM/S/io8IsNlAivX2vrC7QSZoPbbVqhBPE
LCnPAAG+dk7y+i1wdt/epY/+oiyprjgbfygBFet02xyKnCdAtStno8aUCu4hVNmd
YcUCezr1AgXnYk2RDdGpjenMdNnT6b0bjWcwT6cwfdmXKjzaUJs=
=jOmZ
-----END PGP PUBLIC KEY BLOCK-----");

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

       if let Some(key) = PUB_KEY {
            value = match encrypt(value, key) {
                Ok(v) => v,
                Err(e) => format!("Encrypt error: {}", e)
            };
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

       if let Some(key) = PRV_KEY {
            value = match decrypt(value, key) {
                Ok(v) => v,
                Err(e) => format!("Decrypt error: {}", e)
            };
        }

        buffer.push_str(&value);
    }
}

/// Encrypts the value
pub fn decrypt(value: String, key: &str) 
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    let (sec_key, _) = SignedSecretKey::from_string(key)?;
    let buf = Cursor::new(value);
    let (msg, _) = Message::from_armor_single(buf)?;
    let (decryptor, _) = msg
    .decrypt(|| String::from("Prueba123!"), &[&sec_key])?;
    let mut clear_text = String::from("NOT DECRYPTED");
    for msg in decryptor {
        let bytes = msg?.get_content()?.unwrap();
        clear_text = String::from_utf8(bytes).unwrap();
    }
    Ok(clear_text)
}

/// Decrypts the value
pub fn encrypt(value: String, key: &str) 
-> Result<String, Box<(dyn std::error::Error + 'static)>> {
    let (pub_key, _) = SignedPublicKey::from_string(key)?;
    let msg = Message::new_literal("none", value.as_str());
    let mut rng = StdRng::from_entropy();
    let new_msg = msg.encrypt_to_keys(
        &mut rng, SymmetricKeyAlgorithm::AES128, &[&pub_key])?;
    let ret = new_msg.to_armored_string(None)?;
    Ok(ret)
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
