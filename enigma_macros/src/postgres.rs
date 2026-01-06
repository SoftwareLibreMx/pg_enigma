use proc_macro2::TokenStream;
use quote::{quote};
use syn::{DeriveInput, Ident};

/**********************************
 * POSTGRES CREATE TYPE FUNCTIONS *
 * ********************************/

pub fn derive_in_out_funcs(ast: &DeriveInput) -> TokenStream {
    // Get the name of the struct
    let name = &ast.ident;
    let funcname_in = 
        Ident::new(&format!("{name}_input").to_lowercase(), name.span());
    let funcname_out = 
        Ident::new(&format!("{name}_output").to_lowercase(), name.span());
    let funcname_typmod = Ident::new(
            &format!("{name}_typmod_in").to_lowercase(), name.span());
    // Error messages
    let e_ambiguous = format!("INPUT: {name} Typmod is ambiguous.\n\
                    You should cast the value as ::Text\n\
                    More details in issue #4 \
        https://git.softwarelibre.mx/SoftwareLibreMx/pg_enigma/issues/4\
                    ");
    let e_single_int = 
        format!("{name} type modifier must be a single integer value");
    let e_possitive_int = 
        format!("{name} type modifier must be a positive integer");

    quote! {
        /// INPUT function for CREATE TYPE
        #[pg_extern(stable, parallel_safe, requires = [ "shell_type" ])]
        fn #funcname_in(input: &CStr, oid: pg_sys::Oid, typmod: i32) 
        -> Result<#name, Box<dyn std::error::Error + 'static>> {
            //debug2!("INPUT: OID: {:?},  Typmod: {}", oid, typmod);
            debug5!("INPUT: ARGUMENTS: \
                Input: {:?}, OID: {:?},  Typmod: {}", input, oid, typmod);
            let value =  #name::try_from(input)?;
            if value.is_encrypted() {
                info!("Already encrypted"); 
                return Ok(value);
            }
            if typmod == -1 { // unknown typmod 
                //debug1!("Unknown typmod: {typmod}");
                return Err(#e_ambiguous.into());
            }
            value.encrypt(typmod)
        }

        /// OUTPUT function for CREATE TYPE
        #[pg_extern(stable, parallel_safe, requires = [ "shell_type" ])]
        fn #funcname_out(value: #name) 
        -> Result<&'static CStr, Box<dyn std::error::Error + 'static>> {
            //debug2!("OUTPUT");
            debug5!("OUTPUT: {}", value);
            let decrypted = value.decrypt()?;
            let mut buffer = StringInfo::new();
            buffer.push_str(decrypted.value().as_str());
            //TODO try to avoid this unsafe
            let ret = unsafe { buffer.leak_cstr() };
            Ok(ret)
        }

        /// TYPMOD_IN function for CREATE TYPE.
        /// converts typmod from cstring to i32
        #[pg_extern(immutable, parallel_safe, requires = [ "shell_type" ])]
        fn #funcname_typmod(input: Array<&CStr>) 
        -> Result<i32, Box<dyn std::error::Error + 'static>> {
            debug2!("TYPMOD_IN");
            if input.len() != 1 {
                return Err(#e_single_int.into());
            }
            let typmod = input.iter() // iterator
            .next() // Option<Item>
            .ok_or("No Item")? // Item
            .ok_or("Null item")? // &Cstr
            .to_str()? //&str
            .parse::<i32>()?; // i32
            debug1!("TYPMOD_IN({typmod})");
            if typmod < 0 {
                return Err(#e_possitive_int.into());
            }
            Ok(typmod)
        }
    }
}

/*********************************************
 * POSTGRES BINARY FUNCTIONS FOR CREATE TYPE *
 * *******************************************/

pub fn derive_binary_funcs(ast: &DeriveInput) -> TokenStream {
    // Get the name of the struct
    let name = &ast.ident;
    let e_ambiguous = format!("RECEIVE: {name} Typmod is ambiguous.\n\
                    You should cast the value as ::Text\n\
                    More details in issue #4\
        https://git.softwarelibre.mx/SoftwareLibreMx/pg_enigma/issues/4\
                    ");
    let funcname_recv = 
        Ident::new(&format!("{name}_receive").to_lowercase(), name.span());
    let funcname_send = 
        Ident::new(&format!("{name}_send").to_lowercase(), name.span());
        
    quote! {
        /// RECEIVE function FOR CREATE TYPE
        #[pg_extern(stable, parallel_safe, requires = [ "shell_type" ])]
        fn #funcname_recv(
        mut internal: Internal, oid: pg_sys::Oid, typmod: i32) 
        -> Result<#name, Box<dyn std::error::Error + 'static>> {
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
            debug5!("RECEIVE value: {}", serialized);
            let value =  #name::try_from(serialized)?;
            // TODO: Repeated: copied from value_input()
            if value.is_encrypted() {
                info!("Already encrypted"); 
                return Ok(value);
            }
            if typmod == -1 { // unknown typmod 
                return Err(#e_ambiguous.into());
            }
            value.encrypt(typmod)
        } 

        /// SEND function FOR CREATE TYPE
        #[pg_extern(stable, parallel_safe, requires = [ "shell_type" ])]
        fn #funcname_send(value: #name) 
        -> Result<Vec<u8>, Box<dyn std::error::Error + 'static>> {
            //debug2!("SEND");
            debug5!("SEND: {}", value);
            let decrypted = value.decrypt()?;
            Ok(decrypted.value().into_bytes())
        }
    }
}

/***************************
 * POSTGRES CAST FUNCTIONS *
 * *************************/

pub fn derive_cast_funcs(ast: &DeriveInput) -> TokenStream {
    // Get the name of the struct
    let name = &ast.ident;
    let funcname_assignment = Ident::new(
            &format!("string_as_{name}").to_lowercase(), name.span());
    let funcname_sizing = Ident::new(
            &format!("{name}_as_{name}").to_lowercase(), name.span());
    let d2_assignment = format!( "CAST(Text as {}): \
            ARGUMENTS: explicit: {{explicit}},  Typmod: {{typmod}}",
            name);
    let d2_sizing = format!( "CAST({} AS {}): \
            ARGUMENTS: explicit: {{explicit}},  Typmod: {{typmod}}",
            name, name);
        
    quote! {
        /// Assignment cast is called before the INPUT function.
        #[pg_extern]
        fn #funcname_assignment(
        original: String, typmod: i32, explicit: bool) 
        -> Result<#name, Box<dyn std::error::Error + 'static>> {
            debug2!(#d2_assignment);
            let key_id = match typmod {
                -1 => { debug1!("Unknown typmod; using default key ID 0");
                    0 },
                _ => typmod
            };
            #name::try_from(original)?.encrypt(key_id)
        }

        /// Sizing cast is called after the INPUT function only when using 
        /// a typmod and the INPUT function is passed -1 as typmod value. 
        /// This function is passed the correct known typmod argument.
        #[pg_extern(stable, parallel_safe)]
        fn #funcname_sizing(original: #name, typmod: i32, explicit: bool) 
        -> Result<#name, Box<dyn std::error::Error + 'static>> {
            debug2!(#d2_sizing);
            debug5!("Original: {:?}", original);
            if original.is_encrypted() {
                // TODO: if original.key_id != key_id {try_reencrypt()} 
                return Ok(original);
            } 
            let key_id = match typmod {
                -1 => match explicit { 
                    // Implicit is not called when no typmod
                    false => return Err( 
                        format!("Unknown typmod: {}", typmod).into()),
                    true => { debug1!(
                        "Unknown typmod; using default key ID 0");
                    0}
                },
                _ => typmod
            };
            debug2!("Encrypting plain message with key ID: {key_id}");
            original.encrypt(key_id)
        }
    }
}

/*******************************************
*   POSTGRES TYPE BOILERPLATE FUNCTIONS    *
********************************************/
/// Boilerplate traits for converting type to postgres internals
/// Needed for the FunctionMetadata trait
pub fn derive_from_into_datum(ast: &DeriveInput) -> TokenStream {
    // Get the name of the struct
    let name = &ast.ident;
    let myname = format!("{name}");
    let e_corrupted = format!("Corrupted {name}");
    let e_not_encrypted = format!("{name} is not encrypted");

    quote! {
        unsafe impl SqlTranslatable for #name {
            fn argument_sql() -> Result<SqlMapping, ArgumentError> {
                /* this is what the SQL type is called when used in a 
                 * function argument position */
                Ok(SqlMapping::As(#myname.into()))
            }

            fn return_sql() -> Result<Returns, ReturnsError> {
                /* this is what the SQL type is called when used in a 
                 * function return type position */
                Ok(Returns::One(SqlMapping::As(#myname.into())))
            }
        }


        unsafe impl<'fcx> ArgAbi<'fcx> for #name
        where
            Self: 'fcx,
        {
            unsafe fn unbox_arg_unchecked(
            arg: ::pgrx::callconv::Arg<'_, 'fcx>) 
            -> Self {
                unsafe { arg.unbox_arg_using_from_datum().unwrap() }
            }
        }


        unsafe impl BoxRet for #name {
            unsafe fn box_into<'fcx>(self, 
            fcinfo: &mut pgrx::callconv::FcInfo<'fcx>) 
            -> Datum<'fcx> {
                fcinfo.return_raw_datum(
                   self.into_datum()
                        .expect("BoxRet IntoDatum error")
                )
            }
        }

        impl FromDatum for #name {
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
                debug2!("FromDatum value:\n{value}");
                let encrypted = #name::try_from(value)
                                .expect(#e_corrupted);
                //debug2!("FromDatum: Encrypted message: {:?}", encrypted);
                let decrypted = encrypted.decrypt()
                                .expect("FromDatum: Decrypt error");
                //debug2!("FromDatum: Decrypted message: {:?}", decrypted);
                Some(decrypted)
            }
        }

        impl IntoDatum for #name {
            fn into_datum(self) -> Option<pg_sys::Datum> {
                let value = match self {
                    Self::Plain(s) => {
                        debug5!("Plain value: {}", s);
                        error!(#e_not_encrypted);
                    },
                    _ => self.value()
                };
                debug2!("IntoDatum value:\n{value}");
                Some( value.into_datum().expect("IntoDatum error") )
            }

            fn type_oid() -> pg_sys::Oid {
                rust_regtypein::<Self>()
            }
        }
    }
}

