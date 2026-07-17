use super::Socks5Command;
use super::target_addr::{TargetAddr, read_address};
use super::{AuthenticationMethod, ReplyError, Result, SocksError, consts};
use anyhow::Context;
use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use tokio::io::AsyncReadExt;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::{debug, error, info, trace};

#[derive(Clone)]
pub struct Config<A: Authentication = DenyAuthentication> {
    /// Timeout of the command request
    request_timeout: u64,
    /// Avoid useless roundtrips if we don't need the Authentication layer
    skip_auth: bool,
    /// Enable dns-resolving
    dns_resolve: bool,
    /// Enable command execution
    execute_command: bool,
    /// Enable UDP support
    allow_udp: bool,
    /// For some complex scenarios, we may want to either accept Username/Password configuration
    /// or IP Whitelisting, in case the client send only 1-2 auth methods (no auth) rather than 3 (with auth)
    allow_no_auth: bool,
    /// Contains the authentication trait to use the user against with
    auth: Option<Arc<A>>,
}

impl<A: Authentication> Default for Config<A> {
    fn default() -> Self {
        Config {
            request_timeout: 10,
            skip_auth: false,
            dns_resolve: true,
            execute_command: true,
            allow_udp: false,
            allow_no_auth: false,
            auth: None,
        }
    }
}

/// Use this trait to handle a custom authentication on your end.
#[async_trait::async_trait]
pub trait Authentication: Send + Sync {
    type Item;

    async fn authenticate(&self, credentials: Option<(String, String)>) -> Option<Self::Item>;
}

/// This will simply return Option::None, which denies the authentication
#[derive(Copy, Clone, Default)]
pub struct DenyAuthentication {}

#[async_trait::async_trait]
impl Authentication for DenyAuthentication {
    type Item = ();

    async fn authenticate(&self, _credentials: Option<(String, String)>) -> Option<Self::Item> {
        None
    }
}

/// While this one will always allow the user in.
#[derive(Copy, Clone, Default)]
pub struct AcceptAuthentication {}

#[async_trait::async_trait]
impl Authentication for AcceptAuthentication {
    type Item = ();

    async fn authenticate(&self, _credentials: Option<(String, String)>) -> Option<Self::Item> {
        Some(())
    }
}

impl<A: Authentication> Config<A> {
    /// How much time it should wait until the request timeout.
    pub fn set_request_timeout(&mut self, n: u64) -> &mut Self {
        self.request_timeout = n;
        self
    }

    /// Skip the entire auth/handshake part, which means the server will directly wait for
    /// the command request.
    pub fn set_skip_auth(&mut self, value: bool) -> &mut Self {
        self.skip_auth = value;
        self.auth = None;
        self
    }

    /// For some complex scenarios, we may want to either accept Username/Password configuration
    /// or IP Whitelisting, in case the client send only 2 auth methods rather than 3 (with auth)
    pub fn set_allow_no_auth(&mut self, value: bool) -> &mut Self {
        self.allow_no_auth = value;
        self
    }
}

#[async_trait::async_trait]
pub trait AsyncTcpConnector {
    type S: AsyncRead + AsyncWrite + Unpin + Send;

    async fn tcp_connect(&self, addr: SocketAddr, timeout_s: u64) -> Result<Self::S>;
}

#[async_trait::async_trait]
pub trait Socks5UdpAssociation: Send {
    fn local_addr(&self) -> io::Result<SocketAddr>;

    async fn transfer(self: Box<Self>) -> Result<()>;
}

#[async_trait::async_trait]
pub trait Socks5ServerRuntime: Send + Sync {
    async fn resolve_dns(&self, target_addr: TargetAddr) -> Result<TargetAddr>;

    async fn bind_udp_association(&self) -> Result<Box<dyn Socks5UdpAssociation>>;
}

/// Wrap TcpStream and contains Socks5 protocol implementation.
pub struct Socks5Socket<T: AsyncRead + AsyncWrite + Unpin, A: Authentication, C: AsyncTcpConnector>
{
    inner: T,
    config: Arc<Config<A>>,
    target_addr: Option<TargetAddr>,
    cmd: Option<Socks5Command>,
    /// Socket address which will be used in the reply message.
    reply_ip: Option<IpAddr>,
    tcp_connector: C,
    runtime: Arc<dyn Socks5ServerRuntime>,
}

impl<T: AsyncRead + AsyncWrite + Unpin, A: Authentication, C: AsyncTcpConnector>
    Socks5Socket<T, A, C>
{
    pub fn new(
        socket: T,
        config: Arc<Config<A>>,
        tcp_connector: C,
        runtime: Arc<dyn Socks5ServerRuntime>,
    ) -> Self {
        Socks5Socket {
            inner: socket,
            config,
            target_addr: None,
            cmd: None,
            reply_ip: None,
            tcp_connector,
            runtime,
        }
    }

    /// Process clients SOCKS requests
    /// This is the entry point where a whole request is processed.
    pub async fn upgrade_to_socks5(mut self) -> Result<Socks5Socket<T, A, C>> {
        trace!("upgrading to socks5...");

        // Handshake
        if !self.config.skip_auth {
            let methods = self.get_methods().await?;

            let auth_method = self.can_accept_method(methods).await?;

            if self.config.auth.is_some() {
                self.authenticate(auth_method).await?;
            }
        } else {
            debug!("skipping auth");
        }

        match self.request().await {
            Ok(_) => {}
            Err(SocksError::ReplyError(e)) => {
                // If a reply error has been returned, we send it to the client
                self.reply_error(&e).await?;
                return Err(e.into()); // propagate the error to end this connection's task
            }
            // if any other errors has been detected, we simply end connection's task
            Err(d) => return Err(d),
        };

        Ok(self)
    }

    /// Read the authentication method provided by the client.
    /// A client send a list of methods that he supports, he could send
    ///
    ///   - 0: Non auth
    ///   - 2: Auth with username/password
    ///
    /// Altogether, then the server choose to use of of these,
    /// or deny the handshake (thus the connection).
    ///
    /// # Examples
    /// ```text
    ///                    {SOCKS Version, methods-length}
    ///     eg. (non-auth) {5, 2}
    ///     eg. (auth)     {5, 3}
    /// ```
    ///
    async fn get_methods(&mut self) -> Result<Vec<u8>> {
        trace!("Socks5Socket: get_methods()");
        // read the first 2 bytes which contains the SOCKS version and the methods len()
        let mut header = [0u8; 2];
        self.inner
            .read_exact(&mut header)
            .await
            .context("Can't read methods")?;
        let [version, methods_len] = header;
        debug!(
            "Handshake headers: [version: {version}, methods len: {len}]",
            version = version,
            len = methods_len,
        );

        if version != consts::SOCKS5_VERSION {
            return Err(SocksError::UnsupportedSocksVersion(version));
        }

        // {METHODS available from the client}
        // eg. (non-auth) {0, 1}
        // eg. (auth)     {0, 1, 2}
        let mut methods = vec![0u8; methods_len as usize];
        self.inner
            .read_exact(&mut methods)
            .await
            .context("Can't get methods.")?;
        debug!("methods supported sent by the client: {:?}", &methods);

        // Return methods available
        Ok(methods)
    }

    /// Decide to whether or not, accept the authentication method.
    /// Don't forget that the methods list sent by the client, contains one or more methods.
    ///
    /// # Request
    ///
    ///  Client send an array of 3 entries: [0, 1, 2]
    /// ```text
    ///                          {SOCKS Version,  Authentication chosen}
    ///     eg. (non-auth)       {5, 0}
    ///     eg. (GSSAPI)         {5, 1}
    ///     eg. (auth)           {5, 2}
    /// ```
    ///
    /// # Response
    /// ```text
    ///     eg. (accept non-auth) {5, 0x00}
    ///     eg. (non-acceptable)  {5, 0xff}
    /// ```
    ///
    async fn can_accept_method(&mut self, client_methods: Vec<u8>) -> Result<u8> {
        let method_supported;

        if let Some(_auth) = self.config.auth.as_ref() {
            if client_methods.contains(&consts::SOCKS5_AUTH_METHOD_PASSWORD) {
                // can auth with password
                method_supported = consts::SOCKS5_AUTH_METHOD_PASSWORD;
            } else {
                // client hasn't provided a password
                if self.config.allow_no_auth {
                    // but we allow no auth, for ip whitelisting
                    method_supported = consts::SOCKS5_AUTH_METHOD_NONE;
                } else {
                    // we don't allow no auth, so we deny the entry
                    debug!("Don't support this auth method, reply with (0xff)");
                    self.inner
                        .write_all(&[
                            consts::SOCKS5_VERSION,
                            consts::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE,
                        ])
                        .await
                        .context("Can't reply with method not acceptable.")?;

                    return Err(SocksError::AuthMethodUnacceptable(client_methods));
                }
            }
        } else {
            method_supported = consts::SOCKS5_AUTH_METHOD_NONE;
        }

        debug!(
            "Reply with method {} ({})",
            AuthenticationMethod::from_u8(method_supported).context("Method not supported")?,
            method_supported
        );
        self.inner
            .write(&[consts::SOCKS5_VERSION, method_supported])
            .await
            .context("Can't reply with method auth-none")?;
        Ok(method_supported)
    }

    async fn read_username_password(socket: &mut T) -> Result<(String, String)> {
        trace!("Socks5Socket: authenticate()");
        let mut header = [0u8; 2];
        socket
            .read_exact(&mut header)
            .await
            .context("Can't read user len")?;
        let [version, user_len] = header;
        debug!(
            "Auth: [version: {version}, user len: {len}]",
            version = version,
            len = user_len,
        );

        if user_len < 1 {
            return Err(SocksError::AuthenticationFailed(format!(
                "Username malformed ({} chars)",
                user_len
            )));
        }

        let mut username = vec![0u8; user_len as usize];
        socket
            .read_exact(&mut username)
            .await
            .context("Can't get username.")?;
        debug!("username bytes: {:?}", &username);

        let mut pass_len = [0u8; 1];
        socket
            .read_exact(&mut pass_len)
            .await
            .context("Can't read pass len")?;
        let [pass_len] = pass_len;
        debug!("Auth: [pass len: {len}]", len = pass_len,);

        if pass_len < 1 {
            return Err(SocksError::AuthenticationFailed(format!(
                "Password malformed ({} chars)",
                pass_len
            )));
        }

        let mut password = vec![0u8; pass_len as usize];
        socket
            .read_exact(&mut password)
            .await
            .context("Can't get password.")?;
        debug!("password bytes: {:?}", &password);

        let username = String::from_utf8(username).context("Failed to convert username")?;
        let password = String::from_utf8(password).context("Failed to convert password")?;

        Ok((username, password))
    }

    /// Only called if
    ///  - this server has `Authentication` trait implemented.
    ///  - and the client supports authentication via username/password
    ///  - or the client doesn't send authentication, but we let the trait decides if the `allow_no_auth()` set as `true`
    async fn authenticate(&mut self, auth_method: u8) -> Result<A::Item> {
        let credentials = if auth_method == consts::SOCKS5_AUTH_METHOD_PASSWORD {
            let credentials = Self::read_username_password(&mut self.inner).await?;
            Some(credentials)
        } else {
            // the client hasn't provided any credentials, the function auth.authenticate()
            // will then check None, according to other parameters provided by the trait
            // such as IP, etc.
            None
        };

        let auth = self.config.auth.as_ref().context("No auth module")?;

        if let Some(credentials) = auth.authenticate(credentials).await {
            if auth_method == consts::SOCKS5_AUTH_METHOD_PASSWORD {
                // only the password way expect to write a response at this moment
                self.inner
                    .write_all(&[1, consts::SOCKS5_REPLY_SUCCEEDED])
                    .await
                    .context("Can't reply auth success")?;
            }

            info!("User logged successfully.");

            Ok(credentials)
        } else {
            self.inner
                .write_all(&[1, consts::SOCKS5_AUTH_METHOD_NOT_ACCEPTABLE])
                .await
                .context("Can't reply with auth method not acceptable.")?;

            Err(SocksError::AuthenticationRejected(
                "Authentication, rejected.".to_string(),
            ))
        }
    }

    /// Wrapper to principally cover ReplyError types for both functions read & execute request.
    async fn request(&mut self) -> Result<()> {
        self.read_command().await?;

        if self.config.dns_resolve {
            self.resolve_dns().await?;
        } else {
            debug!("Domain won't be resolved because `dns_resolve`'s config has been turned off.")
        }

        if self.config.execute_command {
            self.execute_command().await?;
        }

        Ok(())
    }

    /// Reply error to the client with the reply code according to the RFC.
    async fn reply_error(&mut self, error: &ReplyError) -> Result<()> {
        let reply = new_reply(error, "0.0.0.0:0".parse().unwrap());
        debug!("reply error to be written: {:?}", &reply);

        self.inner
            .write(&reply)
            .await
            .context("Can't write the reply!")?;

        self.inner.flush().await.context("Can't flush the reply!")?;

        Ok(())
    }

    /// Decide to whether or not, accept the authentication method.
    /// Don't forget that the methods list sent by the client, contains one or more methods.
    ///
    /// # Request
    /// ```text
    ///          +----+-----+-------+------+----------+----------+
    ///          |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    ///          +----+-----+-------+------+----------+----------+
    ///          | 1  |  1  |   1   |  1   | Variable |    2     |
    ///          +----+-----+-------+------+----------+----------+
    /// ```
    ///
    /// It the request is correct, it should returns a ['SocketAddr'].
    ///
    async fn read_command(&mut self) -> Result<()> {
        let mut header = [0u8; 4];
        self.inner
            .read_exact(&mut header)
            .await
            .context("Malformed request")?;
        let [version, cmd, rsv, address_type] = header;
        debug!(
            "Request: [version: {version}, command: {cmd}, rev: {rsv}, address_type: {address_type}]",
            version = version,
            cmd = cmd,
            rsv = rsv,
            address_type = address_type,
        );

        if version != consts::SOCKS5_VERSION {
            return Err(SocksError::UnsupportedSocksVersion(version));
        }

        match Socks5Command::from_u8(cmd) {
            None => return Err(ReplyError::CommandNotSupported.into()),
            Some(cmd) => match cmd {
                Socks5Command::TCPConnect => {
                    self.cmd = Some(cmd);
                }
                Socks5Command::UDPAssociate => {
                    if !self.config.allow_udp {
                        return Err(ReplyError::CommandNotSupported.into());
                    }
                    self.cmd = Some(cmd);
                }
                Socks5Command::TCPBind => return Err(ReplyError::CommandNotSupported.into()),
            },
        }

        // Guess address type
        let target_addr = read_address(&mut self.inner, address_type)
            .await
            .map_err(|e| {
                // print explicit error
                error!("{:#}", e);
                // then convert it to a reply
                ReplyError::AddressTypeNotSupported
            })?;

        self.target_addr = Some(target_addr);

        debug!("Request target is {}", self.target_addr.as_ref().unwrap());

        Ok(())
    }

    /// This function is public, it can be call manually on your own-willing
    /// if config flag has been turned off: `Config::dns_resolve == false`.
    pub async fn resolve_dns(&mut self) -> Result<()> {
        trace!("resolving dns");
        if let Some(target_addr) = self.target_addr.take() {
            // decide whether we have to resolve DNS or not
            self.target_addr = match target_addr {
                TargetAddr::Domain(_, _) => Some(self.runtime.resolve_dns(target_addr).await?),
                TargetAddr::Ip(_) => Some(target_addr),
            };
        }

        Ok(())
    }

    /// Execute the socks5 command that the client wants.
    async fn execute_command(&mut self) -> Result<()> {
        match &self.cmd {
            None => Err(ReplyError::CommandNotSupported.into()),
            Some(cmd) => match cmd {
                Socks5Command::TCPBind => Err(ReplyError::CommandNotSupported.into()),
                Socks5Command::TCPConnect => return self.execute_command_connect().await,
                Socks5Command::UDPAssociate => {
                    if self.config.allow_udp {
                        return self.execute_command_udp_assoc().await;
                    } else {
                        Err(ReplyError::CommandNotSupported.into())
                    }
                }
            },
        }
    }

    /// Connect to the target address that the client wants,
    /// then forward the data between them (client <=> target address).
    async fn execute_command_connect(&mut self) -> Result<()> {
        let addr = match self.target_addr.as_ref().context("target_addr empty")? {
            TargetAddr::Ip(addr) => *addr,
            TargetAddr::Domain(_, _) => {
                return Err(io::Error::other(
                    "domain must be resolved when SOCKS DNS resolution is enabled",
                )
                .into());
            }
        };

        // TCP connect with timeout, to avoid memory leak for connection that takes forever
        let outbound = self
            .tcp_connector
            .tcp_connect(addr, self.config.request_timeout)
            .await?;

        debug!("Connected to remote destination");

        self.inner
            .write(&new_reply(
                &ReplyError::Succeeded,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0),
            ))
            .await
            .context("Can't write successful reply")?;

        self.inner.flush().await.context("Can't flush the reply!")?;

        debug!("Wrote success");

        transfer(&mut self.inner, outbound).await
    }

    /// Bind to a random UDP port, wait for the traffic from
    /// the client, and then forward the data to the remote addr.
    async fn execute_command_udp_assoc(&mut self) -> Result<()> {
        // The DST.ADDR and DST.PORT fields contain the address and port that
        // the client expects to use to send UDP datagrams on for the
        // association. The server MAY use this information to limit access
        // to the association.
        // @see Page 6, https://datatracker.ietf.org/doc/html/rfc1928.
        //
        // We do NOT limit the access from the client currently in this implementation.
        let _not_used = self.target_addr.as_ref();

        // Listen with UDP6 socket, so the client can connect to it with either
        // IPv4 or IPv6.
        let association = self.runtime.bind_udp_association().await?;

        // Respect the pre-populated reply IP address.
        self.inner
            .write(&new_reply(
                &ReplyError::Succeeded,
                SocketAddr::new(
                    self.reply_ip.context("invalid reply ip")?,
                    association.local_addr()?.port(),
                ),
            ))
            .await
            .context("Can't write successful reply")?;

        debug!("Wrote success");

        association.transfer().await?;

        Ok(())
    }
}

/// Copy data between two peers
/// Using 2 different generators, because they could be different structs with same traits.
async fn transfer<I, O>(mut inbound: I, mut outbound: O) -> Result<()>
where
    I: AsyncRead + AsyncWrite + Unpin,
    O: AsyncRead + AsyncWrite + Unpin,
{
    match tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await {
        Ok(res) => info!("transfer closed ({}, {})", res.0, res.1),
        Err(err) => error!("transfer error: {:?}", err),
    };

    Ok(())
}

// Fixes the issue "cannot borrow data in dereference of `Pin<&mut >` as mutable"
//
// cf. https://users.rust-lang.org/t/take-in-impl-future-cannot-borrow-data-in-a-dereference-of-pin/52042
impl<T, A: Authentication, S: AsyncTcpConnector> Unpin for Socks5Socket<T, A, S> where
    T: AsyncRead + AsyncWrite + Unpin
{
}

/// Allow us to read directly from the struct
impl<T, A: Authentication, S: AsyncTcpConnector> AsyncRead for Socks5Socket<T, A, S>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buf)
    }
}

/// Allow us to write directly into the struct
impl<T, A: Authentication, S: AsyncTcpConnector> AsyncWrite for Socks5Socket<T, A, S>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

/// Generate reply code according to the RFC.
fn new_reply(error: &ReplyError, sock_addr: SocketAddr) -> Vec<u8> {
    let (addr_type, mut ip_oct, mut port) = match sock_addr {
        SocketAddr::V4(sock) => (
            consts::SOCKS5_ADDR_TYPE_IPV4,
            sock.ip().octets().to_vec(),
            sock.port().to_be_bytes().to_vec(),
        ),
        SocketAddr::V6(sock) => (
            consts::SOCKS5_ADDR_TYPE_IPV6,
            sock.ip().octets().to_vec(),
            sock.port().to_be_bytes().to_vec(),
        ),
    };

    let mut reply = vec![
        consts::SOCKS5_VERSION,
        error.as_u8(), // transform the error into byte code
        0x00,          // reserved
        addr_type,     // address type (ipv4, v6, domain)
    ];
    reply.append(&mut ip_oct);
    reply.append(&mut port);

    reply
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    use super::*;

    struct SimpleUserPassword {
        username: String,
        password: String,
    }

    #[async_trait::async_trait]
    impl Authentication for SimpleUserPassword {
        type Item = ();

        async fn authenticate(&self, credentials: Option<(String, String)>) -> Option<Self::Item> {
            credentials
                .filter(|(username, password)| {
                    username == &self.username && password == &self.password
                })
                .map(|_| ())
        }
    }

    impl<A: Authentication> Config<A> {
        fn with_authentication<T: Authentication + 'static>(self, authentication: T) -> Config<T> {
            Config {
                request_timeout: self.request_timeout,
                skip_auth: self.skip_auth,
                dns_resolve: self.dns_resolve,
                execute_command: self.execute_command,
                allow_udp: self.allow_udp,
                allow_no_auth: self.allow_no_auth,
                auth: Some(Arc::new(authentication)),
            }
        }
    }

    struct TestConnector {
        outbound: Mutex<Option<DuplexStream>>,
    }

    #[async_trait::async_trait]
    impl AsyncTcpConnector for TestConnector {
        type S = DuplexStream;

        async fn tcp_connect(&self, _addr: SocketAddr, _timeout_s: u64) -> Result<Self::S> {
            self.outbound
                .lock()
                .unwrap()
                .take()
                .context("test outbound already taken")
                .map_err(Into::into)
        }
    }

    struct TestRuntime;

    #[async_trait::async_trait]
    impl Socks5ServerRuntime for TestRuntime {
        async fn resolve_dns(&self, target_addr: TargetAddr) -> Result<TargetAddr> {
            Ok(target_addr)
        }

        async fn bind_udp_association(&self) -> Result<Box<dyn Socks5UdpAssociation>> {
            Err(SocksError::Io(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDP is not used by this test runtime",
            )))
        }
    }

    fn connector(outbound: DuplexStream) -> TestConnector {
        TestConnector {
            outbound: Mutex::new(Some(outbound)),
        }
    }

    #[tokio::test]
    async fn no_auth_connect_handshake_transfers_bidirectionally() {
        let (server_stream, mut client_stream) = tokio::io::duplex(1024);
        let (outbound, mut destination_stream) = tokio::io::duplex(1024);
        let mut config = Config::<AcceptAuthentication>::default();
        config.set_allow_no_auth(true);
        let socket = Socks5Socket::new(
            server_stream,
            Arc::new(config),
            connector(outbound),
            Arc::new(TestRuntime),
        );
        let task = tokio::spawn(socket.upgrade_to_socks5());

        client_stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut method_reply = [0u8; 2];
        client_stream.read_exact(&mut method_reply).await.unwrap();
        assert_eq!(method_reply, [5, 0]);

        client_stream
            .write_all(&[5, 1, 0, 1, 10, 42, 0, 7, 0, 80])
            .await
            .unwrap();
        let mut connect_reply = [0u8; 10];
        client_stream.read_exact(&mut connect_reply).await.unwrap();
        assert_eq!(connect_reply[0..2], [5, 0]);

        client_stream.write_all(b"request").await.unwrap();
        let mut request = [0u8; 7];
        destination_stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request, b"request");

        destination_stream.write_all(b"response").await.unwrap();
        let mut response = [0u8; 8];
        client_stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response");

        drop(client_stream);
        drop(destination_stream);
        assert!(task.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn unresolved_domain_keeps_dns_disabled_failure_semantics() {
        let (server_stream, _client_stream) = tokio::io::duplex(128);
        let (outbound, _destination_stream) = tokio::io::duplex(128);
        let mut socket = Socks5Socket::new(
            server_stream,
            Arc::new(Config::<AcceptAuthentication>::default()),
            connector(outbound),
            Arc::new(TestRuntime),
        );
        socket.target_addr = Some(TargetAddr::Domain("peer.example".into(), 443));

        let error = socket.execute_command_connect().await.unwrap_err();

        assert!(matches!(error, SocksError::Io(_)));
    }

    #[tokio::test]
    async fn password_authentication_rejection_preserves_wire_reply() {
        let (server_stream, mut client_stream) = tokio::io::duplex(128);
        let (outbound, _destination_stream) = tokio::io::duplex(128);
        let config =
            Config::<DenyAuthentication>::default().with_authentication(SimpleUserPassword {
                username: "user".to_string(),
                password: "correct".to_string(),
            });
        let socket = Socks5Socket::new(
            server_stream,
            Arc::new(config),
            connector(outbound),
            Arc::new(TestRuntime),
        );
        let task = tokio::spawn(socket.upgrade_to_socks5());

        client_stream.write_all(&[5, 1, 2]).await.unwrap();
        let mut method_reply = [0u8; 2];
        client_stream.read_exact(&mut method_reply).await.unwrap();
        assert_eq!(method_reply, [5, 2]);

        client_stream
            .write_all(&[
                1, 4, b'u', b's', b'e', b'r', 5, b'w', b'r', b'o', b'n', b'g',
            ])
            .await
            .unwrap();
        let mut auth_reply = [0u8; 2];
        client_stream.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(auth_reply, [1, 0xff]);

        let err = task
            .await
            .unwrap()
            .err()
            .expect("wrong password must reject authentication");
        assert!(matches!(err, SocksError::AuthenticationRejected(_)));
    }
}
