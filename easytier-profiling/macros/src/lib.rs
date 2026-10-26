use proc_macro::TokenStream;
use quote::quote;
use syn::{ItemFn, LitStr, parse_macro_input};

/// Instruments a function without recording arguments or return values.
/// An optional string literal supplies a stable name shared by both backends.
#[proc_macro_attribute]
pub fn instrument(attr: TokenStream, item: TokenStream) -> TokenStream {
    let mut function = parse_macro_input!(item as ItemFn);
    let ident = &function.sig.ident;
    let name = if attr.is_empty() {
        quote!(concat!(module_path!(), "::", stringify!(#ident)))
    } else {
        let name = parse_macro_input!(attr as LitStr);
        quote!(#name)
    };
    if function.sig.constness.is_some() {
        return syn::Error::new_spanned(&function.sig, "profiling const functions is unsupported")
            .to_compile_error()
            .into();
    }
    if cfg!(feature = "cpu") {
        function
            .attrs
            .retain(|attr| !attr.path().is_ident("inline"));
        function.attrs.push(syn::parse_quote!(#[inline(never)]));
    }
    if !cfg!(feature = "enabled") {
        return quote!(#function).into();
    }
    let cpu_alias = if cfg!(feature = "cpu") {
        quote! {
            // A nested function carries the enclosing impl/function path even
            // when the user supplies a display label or the method is generic.
            fn __easytier_profiled_symbol() {}
            static __EASYTIER_CPU_ALIAS: ::std::sync::Once = ::std::sync::Once::new();
            __EASYTIER_CPU_ALIAS.call_once(|| {
                let symbol = ::std::any::type_name_of_val(&__easytier_profiled_symbol);
                let symbol = symbol.strip_suffix("::__easytier_profiled_symbol").unwrap();
                let symbol = symbol.strip_suffix("::{{closure}}").unwrap_or(symbol);
                ::easytier_profiling::__private::hotpath::functions::register_cpu_label_alias(#name, symbol);
            });
        }
    } else {
        quote!()
    };
    let body = &function.block;
    function.block = if function.sig.asyncness.is_some() {
        syn::parse_quote!({
            #cpu_alias
            ::easytier_profiling::scope_async!(#name, async #body).await
        })
    } else {
        syn::parse_quote!({
            #cpu_alias
            ::easytier_profiling::scope!(#name, #body)
        })
    };
    quote!(#function).into()
}
