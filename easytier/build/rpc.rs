#![allow(non_snake_case)]

use indoc::formatdoc;
use proc_macro2::{Ident, TokenStream};
use quote::{format_ident, quote};
use std::str::FromStr;

fn parse(value: &str) -> TokenStream {
    TokenStream::from_str(value)
        .unwrap_or_else(|err| panic!("Failed to parse tokens: {} ({})", value, err))
}

fn doc(comments: &prost_build::Comments) -> TokenStream {
    let doc = comments
        .leading
        .iter()
        .flat_map(|c| c.lines().filter(|s| !s.is_empty()));
    quote! { #( #[doc = #doc] )* }
}

const NAMESPACE: &str = "crate::proto::rpc_types";

struct Method {
    index: u8,
    doc: TokenStream,
    method: Ident,
    method_inner: Ident,
    method_str: String,
    method_proto: Ident,
    method_proto_str: String,
    Input: TokenStream,
    Input_proto_str: String,
    Output: TokenStream,
    Output_proto_str: String,
}

impl Method {
    fn new(index: u8, method: prost_build::Method) -> Self {
        assert!(
            !method.client_streaming,
            "Client streaming not yet supported for method {}",
            method.proto_name
        );
        assert!(
            !method.server_streaming,
            "Server streaming not yet supported for method {}",
            method.proto_name
        );
        Self {
            index,
            doc: doc(&method.comments),
            method: format_ident!("{}", method.name),
            method_inner: format_ident!("{}_inner", method.name),
            method_str: method.name,
            method_proto: format_ident!("{}", method.proto_name),
            method_proto_str: method.proto_name,
            Input: parse(&method.input_type),
            Input_proto_str: method.input_proto_type,
            Output: parse(&method.output_type),
            Output_proto_str: method.output_proto_type,
        }
    }
}

struct Service {
    namespace: TokenStream,
    doc: TokenStream,
    Service: Ident,
    ServiceDescriptor: Ident,
    ServiceServer: Ident,
    ServiceClient: Ident,
    ServiceClientFactory: Ident,
    ServiceMethodDescriptor: Ident,
    Service_str: String,
    Service_proto_str: String,
    Service_package_str: String,
    methods: Vec<Method>,
}

impl Service {
    fn new(service: prost_build::Service) -> Self {
        let methods = service
            .methods
            .into_iter()
            .enumerate()
            .map(|(i, method)| Method::new((i + 1) as u8, method))
            .collect();

        Self {
            namespace: parse(NAMESPACE),
            doc: doc(&service.comments),
            Service: format_ident!("{}", service.name),
            ServiceDescriptor: format_ident!("{}Descriptor", service.name),
            ServiceServer: format_ident!("{}Server", service.name),
            ServiceClient: format_ident!("{}Client", service.name),
            ServiceClientFactory: format_ident!("{}ClientFactory", service.name),
            ServiceMethodDescriptor: format_ident!("{}MethodDescriptor", service.name),
            Service_str: service.name,
            Service_proto_str: service.proto_name,
            Service_package_str: service.package,
            methods,
        }
    }

    fn trait_Service(&self) -> TokenStream {
        let Self {
            namespace,
            doc,
            Service,
            methods,
            ..
        } = self;

        let match_json_call_method = methods.iter().map(
            |Method {
                 method,
                 method_str,
                 method_proto_str,
                 Input,
                 ..
             }| {
                quote! {
                    #method_str | #method_proto_str => {
                        let req: #Input = ::serde_json::from_value(json)
                            .map_err(|e| #namespace::error::Error::MalformatRpcPacket(format!("json error: {}", e)))?;
                        let resp = self.#method(ctrl, req).await?;
                        Ok(::serde_json::to_value(resp)
                            .map_err(|e| #namespace::error::Error::MalformatRpcPacket(format!("json error: {}", e)))?)
                    }
                }
            },
        );

        let methods = methods.iter().map(
            |Method {
                 doc,
                 method,
                 Input,
                 Output,
                 ..
             }| {
                quote! {
                    #doc
                    async fn #method(&self, ctrl: Self::Controller, input: #Input) -> #namespace::error::Result<#Output>;
                }
            },
        );

        quote! {
            #doc
            #[async_trait::async_trait]
            #[auto_impl::auto_impl(&, Arc, Box)]
            pub trait #Service {
                type Controller: #namespace::controller::Controller;

                #(#methods)*

                async fn json_call_method(
                    &self,
                    ctrl: Self::Controller,
                    method: &str,
                    json: ::serde_json::Value,
                ) -> #namespace::error::Result<::serde_json::Value> {
                    match method {
                        #(#match_json_call_method)*
                        _ => Err(#namespace::error::Error::InvalidMethodIndex(0, method.to_string())),
                    }
                }
            }
        }
    }

    fn impl_Service_for_Weak(&self) -> TokenStream {
        let Self {
            namespace,
            Service,
            methods,
            ..
        } = self;
        let methods = methods.iter().map(
            |Method {
                 method,
                 Input,
                 Output,
                 ..
             }| {
                quote! {
                    async fn #method(&self, ctrl: Self::Controller, input: #Input) -> #namespace::error::Result<#Output> {
                        let Some(service) = self.upgrade() else {
                            return Err(#namespace::error::Error::Shutdown);
                        };
                        service.#method(ctrl, input).await
                    }
                }
            },
        );

        quote! {
            #[async_trait::async_trait]
            impl<T> #Service for ::std::sync::Weak<T>
            where
                T: Send + Sync + 'static,
                ::std::sync::Arc<T>: #Service,
            {
                type Controller = <::std::sync::Arc<T> as #Service>::Controller;

                #(#methods)*
            }
        }
    }

    fn struct_ServiceDescriptor(&self) -> TokenStream {
        let Self {
            namespace,
            ServiceDescriptor,
            ServiceMethodDescriptor,
            Service_str,
            Service_proto_str,
            Service_package_str,
            methods,
            ..
        } = self;

        let doc = format!("A service descriptor for a `{}`.", Service_str);

        let methods = methods.iter().map(|Method { method_proto, .. }| {
            quote! { #ServiceMethodDescriptor::#method_proto, }
        });

        quote! {
            #[doc = #doc]
            #[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Default)]
            pub struct #ServiceDescriptor;

            impl #namespace::descriptor::ServiceDescriptor for #ServiceDescriptor {
                type Method = #ServiceMethodDescriptor;
                fn name(&self) -> &'static str { #Service_str }
                fn proto_name(&self) -> &'static str { #Service_proto_str }
                fn package(&self) -> &'static str { #Service_package_str }
                fn methods(&self) -> &'static [Self::Method] {
                    &[ #(#methods)* ]
                }
            }
        }
    }

    fn enum_ServiceMethodDescriptor(&self) -> TokenStream {
        let Self {
            ServiceMethodDescriptor,
            Service_str,
            methods,
            ..
        } = self;

        let doc = formatdoc! {"
            Methods available on a `{Service_str}`.

            This can be used as a key when routing requests for servers/clients of a `{Service_str}`.
        "};

        let variants = methods.iter().map(
            |Method {
                 method_proto,
                 index,
                 ..
             }| {
                quote! { #method_proto = #index, }
            },
        );

        let impl_MethodDescriptor = self.impl_MethodDescriptor_for_ServiceMethodDescriptor();
        let impl_TryFrom = self.impl_TryFrom_for_ServiceMethodDescriptor();
        quote! {
            #[doc = #doc]
            #[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
            #[repr(u8)]
            pub enum #ServiceMethodDescriptor {
                #(#variants)*
            }

            #impl_MethodDescriptor

            #impl_TryFrom
        }
    }

    fn impl_MethodDescriptor_for_ServiceMethodDescriptor(&self) -> TokenStream {
        let Self {
            namespace,
            ServiceMethodDescriptor,
            methods,
            ..
        } = self;

        let name = {
            let arms = methods.iter().map(
                |Method {
                     method_proto,
                     method_str,
                     ..
                 }| {
                    quote! { #ServiceMethodDescriptor::#method_proto => #method_str, }
                },
            );

            quote! {
                 fn name(&self) -> &'static str {
                    match *self {
                        #(#arms)*
                    }
                }
            }
        };

        let proto_name = {
            let arms = methods.iter().map(
                |Method {
                     method_proto,
                     method_proto_str,
                     ..
                 }| {
                    quote! { #ServiceMethodDescriptor::#method_proto => #method_proto_str, }
                },
            );

            quote! {
                fn proto_name(&self) -> &'static str {
                    match *self {
                        #(#arms)*
                    }
                }
            }
        };

        let input_type = {
            let arms = methods.iter().map(|Method { method_proto, Input, .. }| {
                quote! { #ServiceMethodDescriptor::#method_proto => ::std::any::TypeId::of::<#Input>(), }
            });

            quote! {
                fn input_type(&self) -> ::std::any::TypeId {
                    match *self {
                        #(#arms)*
                    }
                }
            }
        };

        let input_proto_type = {
            let arms = methods.iter().map(
                |Method {
                     method_proto,
                     Input_proto_str,
                     ..
                 }| {
                    quote! { #ServiceMethodDescriptor::#method_proto => #Input_proto_str, }
                },
            );

            quote! {
                fn input_proto_type(&self) -> &'static str {
                    match *self {
                        #(#arms)*
                    }
                }
            }
        };

        let output_type = {
            let arms = methods.iter().map(|Method { method_proto, Output, .. }| {
                quote! { #ServiceMethodDescriptor::#method_proto => ::std::any::TypeId::of::<#Output>(), }
            });

            quote! {
                fn output_type(&self) -> ::std::any::TypeId {
                    match *self {
                        #(#arms)*
                    }
                }
            }
        };

        let output_proto_type = {
            let arms = methods.iter().map(
                |Method {
                     method_proto,
                     Output_proto_str,
                     ..
                 }| {
                    quote! { #ServiceMethodDescriptor::#method_proto => #Output_proto_str, }
                },
            );

            quote! {
                fn output_proto_type(&self) -> &'static str {
                    match *self {
                        #(#arms)*
                    }
                }
            }
        };

        quote! {
            impl #namespace::descriptor::MethodDescriptor for #ServiceMethodDescriptor {
                #name

                #proto_name

                #input_type

                #input_proto_type

                #output_type

                #output_proto_type

                fn index(&self) -> u8 {
                    *self as u8
                }
            }
        }
    }

    fn impl_TryFrom_for_ServiceMethodDescriptor(&self) -> TokenStream {
        let Self {
            namespace,
            ServiceMethodDescriptor,
            Service_str,
            methods,
            ..
        } = self;

        let arms = methods.iter().map(
            |Method {
                 method_proto,
                 index,
                 ..
             }| {
                quote! { #index => Ok(#ServiceMethodDescriptor::#method_proto), }
            },
        );

        quote! {
            impl std::convert::TryFrom<u8> for #ServiceMethodDescriptor {
                type Error = #namespace::error::Error;
                fn try_from(value: u8) -> #namespace::error::Result<Self> {
                    match value {
                        #(#arms)*
                        _ => Err(#namespace::error::Error::InvalidMethodIndex(value, #Service_str.to_string())),
                    }
                }
            }
        }
    }

    fn struct_ServiceClient(&self) -> TokenStream {
        let Self {
            namespace,
            ServiceDescriptor,
            ServiceClient,
            Service_str,
            ..
        } = self;

        let doc = formatdoc! {"
            A client for a `{Service_str}`.

            This implements the `{Service_str}` trait by dispatching all method calls to the supplied `Handler`.
        "};

        let impl_service_client = self.impl_ServiceClient();
        let impl_service_for_client = self.impl_Service_for_ServiceClient();
        quote! {
            #[doc = #doc]
            #[derive(Clone, Debug)]
            pub struct #ServiceClient<H>(H) where H: #namespace::handler::Handler;

            impl<H> #ServiceClient<H> where H: #namespace::handler::Handler<Descriptor = #ServiceDescriptor> {
                /// Creates a new client instance that delegates all method calls to the supplied handler.
                pub fn new(handler: H) -> Self {
                    Self(handler)
                }
            }

            #impl_service_client

            #impl_service_for_client
        }
    }

    fn impl_ServiceClient(&self) -> TokenStream {
        let Self {
            namespace,
            ServiceClient,
            ServiceDescriptor,
            ServiceMethodDescriptor,
            methods,
            ..
        } = self;

        let methods = methods.iter().map(
            |Method {
                 method_inner,
                 method_proto,
                 Input,
                 Output,
                 ..
             }| {
                quote! {
                    async fn #method_inner(handler: H, ctrl: H::Controller, input: #Input) -> #namespace::error::Result<#Output> {
                        #namespace::__rt::call_method(handler, ctrl, #ServiceMethodDescriptor::#method_proto, input).await
                    }
                }
            },
        );

        quote! {
            impl<H> #ServiceClient<H> where H: #namespace::handler::Handler<Descriptor = #ServiceDescriptor> {
                #(#methods)*
            }
        }
    }

    fn impl_Service_for_ServiceClient(&self) -> TokenStream {
        let Self {
            namespace,
            Service,
            ServiceClient,
            ServiceDescriptor,
            methods,
            ..
        } = self;

        let methods = methods.iter().map(
            |Method {
                 method,
                 method_inner,
                 Input,
                 Output,
                 ..
             }| {
                quote! {
                    async fn #method(&self, ctrl: H::Controller, input: #Input) -> #namespace::error::Result<#Output> {
                        #ServiceClient::#method_inner(self.0.clone(), ctrl, input).await
                    }
                }
            },
        );

        quote! {
            #[async_trait::async_trait]
            impl<H> #Service for #ServiceClient<H> where H: #namespace::handler::Handler<Descriptor = #ServiceDescriptor> {
                type Controller = H::Controller;

                #(#methods)*
            }
        }
    }

    fn struct_ServiceClientFactory(&self) -> TokenStream {
        let Self {
            namespace,
            Service,
            ServiceClient,
            ServiceClientFactory,
            ServiceDescriptor,
            ..
        } = self;

        quote! {
            pub struct #ServiceClientFactory<C: #namespace::controller::Controller>(std::marker::PhantomData<C>);

            impl<C: #namespace::controller::Controller> Clone for #ServiceClientFactory<C> {
                fn clone(&self) -> Self {
                    Self(std::marker::PhantomData)
                }
            }

            impl<C> #namespace::__rt::RpcClientFactory for #ServiceClientFactory<C> where C: #namespace::controller::Controller {
                type Descriptor = #ServiceDescriptor;
                type ClientImpl = Box<dyn #Service<Controller = C> + Send + Sync + 'static>;
                type Controller = C;

                fn new(handler: impl #namespace::handler::Handler<Descriptor = Self::Descriptor, Controller = Self::Controller>) -> Self::ClientImpl {
                    Box::new(#ServiceClient::new(handler))
                }
            }
        }
    }

    fn struct_ServiceServer(&self) -> TokenStream {
        let Self {
            namespace,
            Service,
            ServiceDescriptor,
            ServiceServer,
            ServiceMethodDescriptor,
            Service_str,
            methods,
            ..
        } = self;

        let doc = formatdoc! {"
            A server for a `{Service_str}`.

            This implements the `Server` trait by handling requests and dispatch them to methods on the
            supplied `{Service_str}`.
        "};

        let arms = methods.iter().map(
            |Method {
                 method_proto,
                 method,
                 Input,
                 ..
             }| {
                quote! {
                    #ServiceMethodDescriptor::#method_proto => {
                        let decoded: #Input = #namespace::__rt::decode(input)?;
                        let ret = service.#method(ctrl, decoded).await?;
                        #namespace::__rt::encode(ret)
                    }
                }
            },
        );

        quote! {
            #[doc = #doc]
            #[derive(Clone, Debug)]
            pub struct #ServiceServer<A>(A) where A: #Service + Clone + Send + 'static;

            impl<T> #ServiceServer<::std::sync::Weak<T>>
            where
                T: Send + Sync + 'static,
                ::std::sync::Arc<T>: #Service,
            {
                pub fn new_arc(service: ::std::sync::Arc<T>) -> #ServiceServer<::std::sync::Weak<T>> {
                    #ServiceServer(::std::sync::Arc::downgrade(&service))
                }
            }

            impl<A> #ServiceServer<A> where A: #Service + Clone + Send + 'static {
                /// Creates a new server instance that dispatches all calls to the supplied service.
                pub fn new(service: A) -> #ServiceServer<A> {
                    #ServiceServer(service)
                }

                async fn call_inner(
                    service: A,
                    method: #ServiceMethodDescriptor,
                    ctrl: A::Controller,
                    input: ::bytes::Bytes)
                    -> #namespace::error::Result<::bytes::Bytes> {
                    match method {
                        #(#arms)*
                    }
                }
            }

            #[async_trait::async_trait]
            impl<A> #namespace::handler::Handler for #ServiceServer<A>
            where
                A: #Service + Clone + Send + Sync + 'static {
                type Descriptor = #ServiceDescriptor;
                type Controller = A::Controller;

                async fn call(
                    &self,
                    ctrl: A::Controller,
                    method: #ServiceMethodDescriptor,
                    input: ::bytes::Bytes)
                    -> #namespace::error::Result<::bytes::Bytes> {
                    #ServiceServer::call_inner(self.0.clone(), method, ctrl, input).await
                }
            }
        }
    }
}

/// The service generator to be used with `prost-build` to generate RPC implementations for
/// `prost-simple-rpc`.
///
/// See the crate-level documentation for more info.
#[non_exhaustive]
#[derive(Debug, Default)]
pub struct ServiceGenerator;

impl prost_build::ServiceGenerator for ServiceGenerator {
    fn generate(&mut self, service: prost_build::Service, buf: &mut String) {
        let info = Service::new(service);

        let trait_Service = info.trait_Service();
        let impl_Service_for_Weak = info.impl_Service_for_Weak();
        let struct_ServiceDescriptor = info.struct_ServiceDescriptor();
        let enum_ServiceMethodDescriptor = info.enum_ServiceMethodDescriptor();
        let struct_ServiceClient = info.struct_ServiceClient();
        let struct_ServiceClientFactory = info.struct_ServiceClientFactory();
        let struct_ServiceServer = info.struct_ServiceServer();

        let tokens = quote! {
            #trait_Service

            #impl_Service_for_Weak

            #struct_ServiceDescriptor

            #enum_ServiceMethodDescriptor

            #struct_ServiceClient

            #struct_ServiceClientFactory

            #struct_ServiceServer
        };

        buf.push('\n');
        buf.push_str(&tokens.to_string());
        buf.push('\n');
    }
}
