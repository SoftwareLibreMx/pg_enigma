use proc_macro::TokenStream;
use proc_macro2;
use quote::{quote};
use syn::{parse_macro_input, DeriveInput };

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

