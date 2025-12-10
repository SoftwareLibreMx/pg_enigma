mod enigma;
mod postgres;

use crate::enigma::{
    derive_plain,
    derive_try_from_string,
};
use crate::postgres::{
    derive_binary_funcs,
    derive_cast_funcs,
    derive_from_into_datum,
    derive_in_out_funcs,
};
use proc_macro::TokenStream;
use proc_macro2;
use quote::{quote};
use syn::{parse_macro_input, DeriveInput};

/** Generates trait impls and Postgres functions for Enigma type

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
    let mut tokens = proc_macro2::TokenStream::new();
    let mut try_from_string = proc_macro2::TokenStream::new();
    let mut in_out_funcs = proc_macro2::TokenStream::new();
    let mut binary_funcs = proc_macro2::TokenStream::new();
    let mut cast_funcs = proc_macro2::TokenStream::new();
    let mut from_into_datum = proc_macro2::TokenStream::new();

    // Parse the input tokens into a syntax tree
    let input = parse_macro_input!(input as DeriveInput);
    match input.data {
        syn::Data::Enum(_) => {},
        _ => panic!("Enigma derive works only on enum"),
    };

    //let mut plain = proc_macro2::TokenStream::new();
    let plain = derive_plain(&input);
    
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
            "CastFuncs" => {
                cast_funcs = derive_cast_funcs(&input);
            },
            "FromIntoDatum" => {
                from_into_datum = derive_from_into_datum(&input);
            },
            "InOutFuncs" => {
                in_out_funcs = derive_in_out_funcs(&input);
            },
            "TryFromString" => {
                try_from_string = derive_try_from_string(&input);
            },
            "FullBoilerplate" => {
                binary_funcs = derive_binary_funcs(&input);
                cast_funcs = derive_cast_funcs(&input);
                from_into_datum = derive_from_into_datum(&input);
                in_out_funcs = derive_in_out_funcs(&input);
                try_from_string = derive_try_from_string(&input);
            },
            "," => {
                // separator is also a token
            },
            _ => {
                panic!("enigma_impl({}) attribute not supported", token);
            }
        }
    }

    // Generate the implementation
    let expanded = quote! {
        #try_from_string
        #plain
        #in_out_funcs
        #binary_funcs
        #cast_funcs
        #from_into_datum
    };
    // Convert the generated code back to a TokenStream and return it
    TokenStream::from(expanded)
}



