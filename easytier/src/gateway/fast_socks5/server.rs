use super::new_udp_header;
use super::parse_udp_request;
use super::read_exact;
use super::util::stream::tcp_connect_with_timeout;
use super::util::target_addr::{read_address, TargetAddr};
use super::Socks5Command;
use super::{consts, AuthenticationMethod, ReplyError, Result, SocksError};
use anyhow::Context;
use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::{SocketAddr, ToSocketAddrs as StdToSocketAddrs};
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use tokio::io::AsyncReadExt;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::net::UdpSocket;
use tokio::try_join;

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

/// Basic user/pass auth method provided.
pub struct SimpleUserPassword {
    pub username: String,
    pub password: String,
}

/// The struct returned when the user has successfully authenticated
pub struct AuthSucceeded {
    pub username: String,
}

/// This is an example to auth via simple credentials.
/// If the auth succeed, we return the username authenticated with, for further uses.
#[async_trait::async_trait]
impl Authentication for SimpleUserPassword {
    type Item = AuthSucceeded;

    async fn authenticate(&self, credentials: Option<(String, String)>) -> Option<Self::Item> {
        if let Some((username, password)) = credentials {
            // Client has supplied credentials
            if username == self.username && password == self.password {
                // Some() will allow the authentication and the credentials
                // will be forwarded to the socket
                Some(AuthSucceeded { username })
            } else {
                // Credentials incorrect, we deny the auth
                None
            }
        } else {
            // The client hasn't supplied any credentials, which only happens
            // when `Config::allow_no_auth()` is set as `true`
            None
        }
    }
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

    /// Enable authentication
    /// 'static lifetime for Authentication avoid us to use `dyn Authentication`
    /// and set the Arc before calling the function.
    pub fn with_authentication<T: Authentication + 'static>(self, authentication: T) -> Config<T> {
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

    /// For some complex scenarios, we may want to either accept Username/Password configuration
    /// or IP Whitelisting, in case the client send only 2 auth methods rather than 3 (with auth)
    pub fn set_allow_no_auth(&mut self, value: bool) -> &mut Self {
        self.allow_no_auth = value;
        self
    }

    /// Set whether or not to execute commands
    pub fn set_execute_command(&mut self, value: bool) -> &mut Self {
        self.execute_command = value;
        self
    }

    /// Will the server perform dns resolve
    pub fn set_dns_resolve(&mut self, value: bool) -> &mut Self {
        self.dns_resolve = value;
        self
    }

    /// Set whether or not to allow udp traffic
    pub fn set_udp_support(&mut self, value: bool) -> &mut Self {
        self.allow_udp = value;
        self
    }
}

#[async_trait::async_trait]
pub trait AsyncTcpConnector {
    type S: AsyncRead + AsyncWrite + Unpin + Send + Sync;

    async fn tcp_connect(&self, addr: SocketAddr, timeout_s: u64) -> Result<Self::S>;
}

pub struct DefaultTcpConnector {}

#[async_trait::async_trait]
impl AsyncTcpConnector for DefaultTcpConnector {
    type S = TcpStream;

    async fn tcp_connect(&self, addr: SocketAddr, timeout_s: u64) -> Result<TcpStream> {
        tcp_connect_with_timeout(addr, timeout_s).await
    }
}

/// Wrap TcpStream and contains Socks5 protocol implementation.
pub struct Socks5Socket<T: AsyncRead + AsyncWrite + Unpin, A: Authentication, C: AsyncTcpConnector>
{
    inner: T,
    config: Arc<Config<A>>,
    auth: AuthenticationMethod,
    target_addr: Option<TargetAddr>,
    cmd: Option<Socks5Command>,
    /// Socket address which will be used in the reply message.
    reply_ip: Option<IpAddr>,
    /// If the client has been authenticated, that's where we store his credentials
    /// to be accessed from the socket
    credentials: Option<A::Item>,
    tcp_connector: C,
}

impl<T: AsyncRead + AsyncWrite + Unpin, A: Authentication, C: AsyncTcpConnector>
    Socks5Socket<T, A, C>
{
    pub fn new(socket: T, config: Arc<Config<A>>, tcp_connector: C) -> Self {
        Socks5Socket {
            inner: socket,
            config,
            auth: AuthenticationMethod::None,
            target_addr: None,
            cmd: None,
            reply_ip: None,
            credentials: None,
            tcp_connector,
        }
    }

    /// Set the bind IP address in Socks5Reply.
    ///
    /// Only the inner socket owner knows the correct reply bind addr, so leave this field to be
    /// populated. For those strict clients, users can use this function to set the correct IP
    /// address.
    ///
    /// Most popular SOCKS5 clients [1] [2] ignore BND.ADDR and BND.PORT the reply of command
    /// CONNECT, but this field could be useful in some other command, such as UDP ASSOCIATE.
    ///
    /// [1]: https://github.com/chromium/chromium/blob/bd2c7a8b65ec42d806277dd30f138a673dec233a/net/socket/socks5_client_socket.cc#L481
    /// [2]: https://github.com/curl/curl/blob/d15692ebbad5e9cfb871b0f7f51a73e43762cee2/lib/socks.c#L978
    pub fn set_reply_ip(&mut self, addr: IpAddr) {
        self.reply_ip = Some(addr);
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
                let credentials = self.authenticate(auth_method).await?;
                self.credentials = Some(credentials);
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

    /// Consumes the `Socks5Socket`, returning the wrapped stream.
    pub fn into_inner(self) -> T {
        self.inner
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
        let [version, methods_len] =
            read_exact!(self.inner, [0u8; 2]).context("Can't read methods")?;
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
        let methods = read_exact!(self.inner, vec![0u8; methods_len as usize])
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
        let [version, user_len] = read_exact!(socket, [0u8; 2]).context("Can't read user len")?;
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

        let username =
            read_exact!(socket, vec![0u8; user_len as usize]).context("Can't get username.")?;
        debug!("username bytes: {:?}", &username);

        let [pass_len] = read_exact!(socket, [0u8; 1]).context("Can't read pass len")?;
        debug!("Auth: [pass len: {len}]", len = pass_len,);

        if pass_len < 1 {
            return Err(SocksError::AuthenticationFailed(format!(
                "Password malformed ({} chars)",
                pass_len
            )));
        }

        let password =
            read_exact!(socket, vec![0u8; pass_len as usize]).context("Can't get password.")?;
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
        let [version, cmd, rsv, address_type] =
            read_exact!(self.inner, [0u8; 4]).context("Malformed request")?;
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
                TargetAddr::Domain(_, _) => Some(target_addr.resolve_dns().await?),
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
        // async-std's ToSocketAddrs doesn't supports external trait implementation
        // @see https://github.com/async-rs/async-std/issues/539
        let addr = self
            .target_addr
            .as_ref()
            .context("target_addr empty")?
            .to_socket_addrs()?
            .next()
            .context("unreachable")?;

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
        let peer_sock = UdpSocket::bind("[::]:0").await?;

        // Respect the pre-populated reply IP address.
        self.inner
            .write(&new_reply(
                &ReplyError::Succeeded,
                SocketAddr::new(
                    self.reply_ip.context("invalid reply ip")?,
                    peer_sock.local_addr()?.port(),
                ),
            ))
            .await
            .context("Can't write successful reply")?;

        debug!("Wrote success");

        transfer_udp(peer_sock).await?;

        Ok(())
    }

    pub fn target_addr(&self) -> Option<&TargetAddr> {
        self.target_addr.as_ref()
    }

    pub fn auth(&self) -> &AuthenticationMethod {
        &self.auth
    }

    pub fn cmd(&self) -> &Option<Socks5Command> {
        &self.cmd
    }

    /// Borrow the credentials of the user has authenticated with
    pub fn get_credentials(&self) -> Option<&<<A as Authentication>::Item as Deref>::Target>
    where
        <A as Authentication>::Item: Deref,
    {
        self.credentials.as_deref()
    }

    /// Get the credentials of the user has authenticated with
    pub fn take_credentials(&mut self) -> Option<A::Item> {
        self.credentials.take()
    }

    pub fn tcp_connector(&self) -> &C {
        &self.tcp_connector
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

async fn handle_udp_request(inbound: &UdpSocket, outbound: &UdpSocket) -> Result<()> {
    let mut buf = vec![0u8; 0x10000];
    loop {
        let (size, client_addr) = inbound.recv_from(&mut buf).await?;
        debug!("Server recieve udp from {}", client_addr);
        inbound.connect(client_addr).await?;

        let (frag, target_addr, data) = parse_udp_request(&buf[..size]).await?;

        if frag != 0 {
            debug!("Discard UDP frag packets sliently.");
            return Ok(());
        }

        debug!("Server forward to packet to {}", target_addr);
        let mut target_addr = target_addr
            .to_socket_addrs()?
            .next()
            .context("unreachable")?;

        target_addr.set_ip(match target_addr.ip() {
            std::net::IpAddr::V4(v4) => std::net::IpAddr::V6(v4.to_ipv6_mapped()),
            v6 @ std::net::IpAddr::V6(_) => v6,
        });
        outbound.send_to(data, target_addr).await?;
    }
}

async fn handle_udp_response(inbound: &UdpSocket, outbound: &UdpSocket) -> Result<()> {
    let mut buf = vec![0u8; 0x10000];
    loop {
        let (size, remote_addr) = outbound.recv_from(&mut buf).await?;
        debug!("Recieve packet from {}", remote_addr);

        let mut data = new_udp_header(remote_addr)?;
        data.extend_from_slice(&buf[..size]);
        inbound.send(&data).await?;
    }
}

async fn transfer_udp(inbound: UdpSocket) -> Result<()> {
    let outbound = UdpSocket::bind("[::]:0").await?;

    let req_fut = handle_udp_request(&inbound, &outbound);
    let res_fut = handle_udp_response(&inbound, &outbound);
    match try_join!(req_fut, res_fut) {
        Ok(_) => {}
        Err(error) => return Err(error),
    }

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
