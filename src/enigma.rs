use crate::EnigmaMsg;
use crate::PRIV_KEYS;
use pgrx::callconv::{ArgAbi, BoxRet};
use pgrx::datum::{Datum/*,Internal*/};
//use pgrx::debug2;
use pgrx::{FromDatum,IntoDatum,pg_sys,rust_regtypein};
use pgrx::pgrx_sql_entity_graph::metadata::{
    ArgumentError, Returns, ReturnsError, SqlMapping, SqlTranslatable,
};
use std::fmt::{Display, Formatter};

/// Value stores entcrypted information
#[repr(transparent)]
#[derive( Clone, Debug)]
pub struct Enigma {
    // TODO: Should be private
    pub value: String,
}

/**************************************************************************
*                                                                         *
*                                                                         *
*                B O I L E R P L A T E  F U N C T I O N S                 *
*                                                                         *
*                                                                         *
**************************************************************************/

impl Display for Enigma {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

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
    is_null: bool, _: pg_sys::Oid) 
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
        Some(Enigma::from(decrypted))
    }
}

impl IntoDatum for Enigma {
    fn into_datum(self) -> Option<pg_sys::Datum> {
        // TODO: if self.value.is_enigma()
        Some(
			self.value
				.into_datum()
				.expect("Can't convert enigma value to Datum!")
		)
    }

    fn type_oid() -> pg_sys::Oid {
        rust_regtypein::<Self>()
    }
}

