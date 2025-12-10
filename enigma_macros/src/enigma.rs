use proc_macro2::TokenStream;
use quote::{quote};
use syn::{DeriveInput};

pub fn derive_plain(ast: &DeriveInput) -> TokenStream {
    let mut has_plain = false;
    // Get the name of the struct
    let name = &ast.ident;

    // Extract the variants of the enum
    let variants = match ast.data {
        syn::Data::Enum(ref data_enum) => &data_enum.variants,
        _ => panic!("Expecting enum {name} {{ ... }}"),
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

pub fn derive_try_from_string(ast: &DeriveInput) -> TokenStream {
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


