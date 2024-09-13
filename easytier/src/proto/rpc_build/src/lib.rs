extern crate heck;
extern crate prost_build;

use std::fmt;

const NAMESPACE: &str = "crate::proto::rpc_types";

/// The service generator to be used with `prost-build` to generate RPC implementations for
/// `prost-simple-rpc`.
///
/// See the crate-level documentation for more info.
#[allow(missing_copy_implementations)]
#[derive(Clone, Debug)]
pub struct ServiceGenerator {
    _private: (),
}

impl ServiceGenerator {
    /// Create a new `ServiceGenerator` instance with the default options set.
    pub fn new() -> ServiceGenerator {
        ServiceGenerator { _private: () }
    }
}

impl prost_build::ServiceGenerator for ServiceGenerator {
    fn generate(&mut self, service: prost_build::Service, mut buf: &mut String) {
        use std::fmt::Write;

        let descriptor_name = format!("{}Descriptor", service.name);
        let server_name = format!("{}Server", service.name);
        let client_name = format!("{}Client", service.name);
        let method_descriptor_name = format!("{}MethodDescriptor", service.name);

        let mut trait_methods = String::new();
        let mut enum_methods = String::new();
        let mut list_enum_methods = String::new();
        let mut client_methods = String::new();
        let mut client_own_methods = String::new();
        let mut match_name_methods = String::new();
        let mut match_proto_name_methods = String::new();
        let mut match_input_type_methods = String::new();
        let mut match_input_proto_type_methods = String::new();
        let mut match_output_type_methods = String::new();
        let mut match_output_proto_type_methods = String::new();
        let mut match_handle_methods = String::new();

        let mut match_method_try_from = String::new();

        for (idx, method) in service.methods.iter().enumerate() {
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

            ServiceGenerator::write_comments(&mut trait_methods, 4, &method.comments).unwrap();
            writeln!(
                trait_methods,
                r#"    async fn {name}(&self, ctrl: Self::Controller, input: {input_type}) -> {namespace}::error::Result<{output_type}>;"#,
                name = method.name,
                input_type = method.input_type,
                output_type = method.output_type,
                namespace = NAMESPACE,
            )
            .unwrap();

            ServiceGenerator::write_comments(&mut enum_methods, 4, &method.comments).unwrap();
            writeln!(
                enum_methods,
                "    {name} = {index},",
                name = method.proto_name,
                index = format!("{}", idx + 1)
            )
            .unwrap();

            writeln!(
                match_method_try_from,
                "            {index} => Ok({service_name}MethodDescriptor::{name}),",
                service_name = service.name,
                name = method.proto_name,
                index = format!("{}", idx + 1),
            )
            .unwrap();

            writeln!(
                list_enum_methods,
                "            {service_name}MethodDescriptor::{name},",
                service_name = service.name,
                name = method.proto_name
            )
            .unwrap();

            writeln!(
                client_methods,
                r#"    async fn {name}(&self, ctrl: H::Controller, input: {input_type}) -> {namespace}::error::Result<{output_type}> {{
        {client_name}::{name}_inner(self.0.clone(), ctrl, input).await
    }}"#,
                name = method.name,
                input_type = method.input_type,
                output_type = method.output_type,
                client_name = format!("{}Client", service.name),
                namespace = NAMESPACE,
            )
            .unwrap();

            writeln!(
                client_own_methods,
                r#"    async fn {name}_inner(handler: H, ctrl: H::Controller, input: {input_type}) -> {namespace}::error::Result<{output_type}> {{
            {namespace}::__rt::call_method(handler, ctrl, {method_descriptor_name}::{proto_name}, input).await
    }}"#,
                name = method.name,
                method_descriptor_name = method_descriptor_name,
                proto_name = method.proto_name,
                input_type = method.input_type,
                output_type = method.output_type,
                namespace = NAMESPACE,
            ).unwrap();

            let case = format!(
                "            {service_name}MethodDescriptor::{proto_name} => ",
                service_name = service.name,
                proto_name = method.proto_name
            );

            writeln!(match_name_methods, "{}{:?},", case, method.name).unwrap();
            writeln!(match_proto_name_methods, "{}{:?},", case, method.proto_name).unwrap();
            writeln!(
                match_input_type_methods,
                "{}::std::any::TypeId::of::<{}>(),",
                case, method.input_type
            )
            .unwrap();
            writeln!(
                match_input_proto_type_methods,
                "{}{:?},",
                case, method.input_proto_type
            )
            .unwrap();
            writeln!(
                match_output_type_methods,
                "{}::std::any::TypeId::of::<{}>(),",
                case, method.output_type
            )
            .unwrap();
            writeln!(
                match_output_proto_type_methods,
                "{}{:?},",
                case, method.output_proto_type
            )
            .unwrap();
            write!(
                match_handle_methods,
                r#"{} {{
                    let decoded: {input_type} = {namespace}::__rt::decode(input)?;
                    let ret = service.{name}(ctrl, decoded).await?;
                    {namespace}::__rt::encode(ret)
                }}
"#,
                case,
                input_type = method.input_type,
                name = method.name,
                namespace = NAMESPACE,
            )
            .unwrap();
        }

        ServiceGenerator::write_comments(&mut buf, 0, &service.comments).unwrap();
        write!(
            buf,
            r#"
#[async_trait::async_trait]
#[auto_impl::auto_impl(&, Arc, Box)]
pub trait {name} {{
    type Controller: {namespace}::controller::Controller;

    {trait_methods}
}}

/// A service descriptor for a `{name}`.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Default)]
pub struct {descriptor_name};

/// Methods available on a `{name}`.
///
/// This can be used as a key when routing requests for servers/clients of a `{name}`.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum {method_descriptor_name} {{
    {enum_methods}
}}

impl std::convert::TryFrom<u8> for {method_descriptor_name} {{
    type Error = {namespace}::error::Error;
    fn try_from(value: u8) -> {namespace}::error::Result<Self> {{
        match value {{
            {match_method_try_from}
            _ => Err({namespace}::error::Error::InvalidMethodIndex(value, "{name}".to_string())),
        }}
    }}
}}

/// A client for a `{name}`.
///
/// This implements the `{name}` trait by dispatching all method calls to the supplied `Handler`.
#[derive(Clone, Debug)]
pub struct {client_name}<H>(H) where H: {namespace}::handler::Handler;

impl<H> {client_name}<H> where H: {namespace}::handler::Handler<Descriptor = {descriptor_name}> {{
    /// Creates a new client instance that delegates all method calls to the supplied handler.
    pub fn new(handler: H) -> {client_name}<H> {{
        {client_name}(handler)
    }}
}}

impl<H> {client_name}<H> where H: {namespace}::handler::Handler<Descriptor = {descriptor_name}> {{
    {client_own_methods}
}}

#[async_trait::async_trait]
impl<H> {name} for {client_name}<H> where H: {namespace}::handler::Handler<Descriptor = {descriptor_name}> {{
    type Controller = H::Controller;

    {client_methods}
}}

pub struct {client_name}Factory<C: {namespace}::controller::Controller>(std::marker::PhantomData<C>);

impl<C: {namespace}::controller::Controller> Clone for {client_name}Factory<C> {{
    fn clone(&self) -> Self {{
        Self(std::marker::PhantomData)
    }}
}}

impl<C> {namespace}::__rt::RpcClientFactory for {client_name}Factory<C> where C: {namespace}::controller::Controller {{
    type Descriptor = {descriptor_name};
    type ClientImpl = Box<dyn {name}<Controller = C> + Send + 'static>;
    type Controller = C;

    fn new(handler: impl {namespace}::handler::Handler<Descriptor = Self::Descriptor, Controller = Self::Controller>) -> Self::ClientImpl {{
        Box::new({client_name}::new(handler))
    }}
}}

/// A server for a `{name}`.
///
/// This implements the `Server` trait by handling requests and dispatch them to methods on the
/// supplied `{name}`.
#[derive(Clone, Debug)]
pub struct {server_name}<A>(A) where A: {name} + Clone + Send + 'static;

impl<A> {server_name}<A> where A: {name} + Clone + Send + 'static {{
    /// Creates a new server instance that dispatches all calls to the supplied service.
    pub fn new(service: A) -> {server_name}<A> {{
        {server_name}(service)
    }}

    async fn call_inner(
        service: A,
        method: {method_descriptor_name},
        ctrl: A::Controller,
        input: ::bytes::Bytes)
        -> {namespace}::error::Result<::bytes::Bytes> {{
        match method {{
            {match_handle_methods}        
        }}
    }}
}}

impl {namespace}::descriptor::ServiceDescriptor for {descriptor_name} {{
    type Method = {method_descriptor_name};
    fn name(&self) -> &'static str {{ {name:?} }}
    fn proto_name(&self) -> &'static str {{ {proto_name:?} }}
    fn package(&self) -> &'static str {{ {package:?} }}
    fn methods(&self) -> &'static [Self::Method] {{
        &[ {list_enum_methods} ]
    }}
}}

#[async_trait::async_trait]
impl<A> {namespace}::handler::Handler for {server_name}<A>
where
    A: {name} + Clone + Send + Sync + 'static {{
    type Descriptor = {descriptor_name};
    type Controller = A::Controller;

    async fn call(
        &self,
        ctrl: A::Controller,
        method: {method_descriptor_name},
        input: ::bytes::Bytes)
        -> {namespace}::error::Result<::bytes::Bytes> {{
        {server_name}::call_inner(self.0.clone(), method, ctrl, input).await
    }}
}}

impl {namespace}::descriptor::MethodDescriptor for {method_descriptor_name} {{
    fn name(&self) -> &'static str {{
        match *self {{
            {match_name_methods}        
        }}
    }}

    fn proto_name(&self) -> &'static str {{
        match *self {{
            {match_proto_name_methods}
        }}
    }}

    fn input_type(&self) -> ::std::any::TypeId {{
        match *self {{
            {match_input_type_methods}
        }}
    }}

    fn input_proto_type(&self) -> &'static str {{
        match *self {{
            {match_input_proto_type_methods}
        }}
    }}

    fn output_type(&self) -> ::std::any::TypeId {{
        match *self {{
            {match_output_type_methods}
        }}
    }}

    fn output_proto_type(&self) -> &'static str {{
        match *self {{
            {match_output_proto_type_methods}
        }}
    }}

    fn index(&self) -> u8 {{
        *self as u8
    }}
}}
"#,
            name = service.name,
            descriptor_name = descriptor_name,
            server_name = server_name,
            client_name = client_name,
            method_descriptor_name = method_descriptor_name,
            proto_name = service.proto_name,
            package = service.package,
            trait_methods = trait_methods,
            enum_methods = enum_methods,
            list_enum_methods = list_enum_methods,
            client_own_methods = client_own_methods,
            client_methods = client_methods,
            match_name_methods = match_name_methods,
            match_proto_name_methods = match_proto_name_methods,
            match_input_type_methods = match_input_type_methods,
            match_input_proto_type_methods = match_input_proto_type_methods,
            match_output_type_methods = match_output_type_methods,
            match_output_proto_type_methods = match_output_proto_type_methods,
            match_handle_methods = match_handle_methods,
            namespace = NAMESPACE,
        ).unwrap();
    }
}

impl ServiceGenerator {
    fn write_comments<W>(
        mut write: W,
        indent: usize,
        comments: &prost_build::Comments,
    ) -> fmt::Result
    where
        W: fmt::Write,
    {
        for comment in &comments.leading {
            for line in comment.lines().filter(|s| !s.is_empty()) {
                writeln!(write, "{}///{}", " ".repeat(indent), line)?;
            }
        }
        Ok(())
    }
}
