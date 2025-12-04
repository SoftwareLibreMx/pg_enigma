use proc_macro::TokenStream;
use proc_macro2;
use quote::{quote};
use syn::{parse_macro_input, DeriveInput };

/** Genera las implementaciones de traits para un tipo Enigma

```
#![derive (Enigma)]
pub enum Example {
    Encrypted(u32,String),
    /// Required for trait Plain
    Plain(String)
}
```

*/ 
#[proc_macro_derive(
    EnigmaType, 
    attributes(
        Plain
    )
)]
pub fn enigma_derive(input: TokenStream) -> TokenStream {
    // Parse the input tokens into a syntax tree
    let input = parse_macro_input!(input as DeriveInput);
    //let mut plain = proc_macro2::TokenStream::new();
    let plain = enigma_derive_plain(&input);

    for attr in &input.attrs {
        let path = &attr.path();
        let path = quote! {#path}.to_string();
        match path.as_str() {
            /* "Plain" => { // Plain is always expanded
                plain = enigma_derive_plain(&input);
            }, */
            _ => {}
        }
    }

    // Generate the implementation
    let expanded = quote! {
        #plain
    };
    // Convert the generated code back to a TokenStream and return it
    TokenStream::from(expanded)
}

fn enigma_derive_plain(ast: &DeriveInput) -> proc_macro2::TokenStream {
    let mut has_plain = false;
    // Get the name of the struct
    let name = &ast.ident;

    // Extract the variants of the enum
    let variants = match ast.data {
        syn::Data::Enum(ref data_enum) => &data_enum.variants,
        _ => panic!("Plain can only be used with enums"),
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
        panic!("Enum {name} has no Plain(String) variant");
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
