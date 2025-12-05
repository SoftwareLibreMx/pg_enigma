use proc_macro::TokenStream;
use proc_macro2;
use quote::{quote};
use syn::{parse_macro_input, DeriveInput, Ident};

/** Genera las implementaciones de traits para un tipo Enigma

```
#![derive (EnigmaType)]
#[enigma_impl(TryFromString)]
pub enum Example {
    Encrypted(u32,String),
    /// Required for trait Plain
    Plain(String)
}
```

*/ 
#[proc_macro_derive(EnigmaType, attributes(enigma_impl))]
pub fn enigma_derive(input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let input = parse_macro_input!(input as DeriveInput);
    let mut tokens = proc_macro2::TokenStream::new();
    let mut try_from_string = proc_macro2::TokenStream::new();
    //let mut plain = proc_macro2::TokenStream::new();
    let plain = derive_plain(&input);
    let mut type_funcs = proc_macro2::TokenStream::new();
    let mut binary_funcs = proc_macro2::TokenStream::new();
    let mut boilerplate = proc_macro2::TokenStream::new();

    for attr in &input.attrs {
        if let Some(segment) = attr.path().segments.first() {
            if segment.ident.to_string().eq("enigma_impl") {
                //plain =  derive_plain(&input);
                if let Ok(list) = attr.meta.require_list() {
                    tokens = list.tokens.clone();
                }
            }
        }
    }
    for token in tokens {
        match token.to_string().as_str() {
            "BinaryFuncs" => {
                binary_funcs = derive_binary_funcs(&input);
            },
            "Boilerplate" => {
                boilerplate = derive_boilerplate(&input);
            },
            "InOutFuncs" => {
                type_funcs = derive_in_out_funcs(&input);
            },
            "TryFromString" => {
                try_from_string = derive_try_from_string(&input);
            },
            _ => {}
        }
    }

    // Generate the implementation
    let expanded = quote! {
        #try_from_string
        #plain
        #type_funcs
        #binary_funcs
        #boilerplate
    };
    // Convert the generated code back to a TokenStream and return it
    TokenStream::from(expanded)
}

fn derive_plain(ast: &DeriveInput) -> proc_macro2::TokenStream {
    let mut has_plain = false;
    // Get the name of the struct
    let name = &ast.ident;

    // Extract the variants of the enum
    let variants = match ast.data {
        syn::Data::Enum(ref data_enum) => &data_enum.variants,
        _ => panic!("Enigma derive supports only enums"),
    };
    
    // Look for Plain variant
    for variant in variants.iter() {
        if variant.ident.to_string().eq("Plain") {
            if variant.fields.len() == 1 {
                if let Some(field) = variant.fields.iter().next() {
                    if let syn::Type::Path(path) = &field.ty  {
                        for segment in path.path.segments.iter() {
                            if segment.ident.to_string().eq("String") {
                                has_plain = true;
                                break;
                            }
                        }
                    }
                }
            }
            break;
        }
    }

    if has_plain == false {
        panic!("Enigma enum {name} must have a Plain(String) variant");
    }

    quote! {
        //use std::string::String;
        impl Plain for #name {
            fn plain(value: String) -> Self {
                Self::Plain(value)
            }

            fn is_plain(&self) -> bool {
                matches!(*self, Self::Plain(_))
            }
        }
    }
}

fn derive_try_from_string(ast: &DeriveInput) -> proc_macro2::TokenStream {
    // Get the name of the struct
    let name = &ast.ident;

    quote! {
        impl TryFrom<String> for #name {
            type Error = Box<dyn std::error::Error + 'static>;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::try_from(value.as_str())
            }
        }

        impl TryFrom<&String> for #name {
            type Error = Box<dyn std::error::Error + 'static>;

            fn try_from(value: &String) -> Result<Self, Self::Error> {
                Self::try_from(value.as_str())
            }
        }

        impl TryFrom<StringInfo> for #name {
            type Error = Box<dyn std::error::Error + 'static>;

            fn try_from(value: StringInfo) -> Result<Self, Self::Error> {
                Self::try_from(value.as_str()?)
            }
        }

        impl TryFrom<&CStr> for #name {
            type Error = Box<dyn std::error::Error + 'static>;

            fn try_from(value: &CStr) -> Result<Self, Self::Error> {
                Self::try_from(value.to_str()?)
            }
        }
    }
}


/**********************************
 * POSTGRES CREATE TYPE FUNCTIONS *
 * ********************************/

fn derive_in_out_funcs(ast: &DeriveInput) -> proc_macro2::TokenStream {
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
            buffer.push_str(decrypted.to_string().as_str());
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

/********************************************
 * POSTGRE BINARY FUNCTIONS FOR CREATE TYPE *
 * ******************************************/

fn derive_binary_funcs(ast: &DeriveInput) -> proc_macro2::TokenStream {
    // Get the name of the struct
    let name = &ast.ident;
    let e_ambiguous = format!("RECEIVE: {name} Typmod is ambiguous.\n\
                    You should cast the value as ::Text\n\
                    More details in issue #4\
        https://git.softwarelibre.mx/SoftwareLibreMx/pg_enigma/issues/4\
                    ");
    let funcname_recv = 
        Ident::new(&format!("{name}_receive").to_lowercase(), name.span());
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
    }
}

/**************************************************************************
*                                                                         *
*                B O I L E R P L A T E  F U N C T I O N S                 *
*                                                                         *
**************************************************************************/
/// Boilerplate traits for converting type to postgres internals
/// Needed for the FunctionMetadata trait
fn derive_boilerplate(ast: &DeriveInput) -> proc_macro2::TokenStream {
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
                    _ => self.to_string()
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

