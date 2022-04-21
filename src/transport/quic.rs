use std::borrow::BorrowMut;
use std::fmt::{Debug, Formatter};
use std::fs::File;
use std::io::{BufReader, Error, IoSlice};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use super::Transport;
use crate::config::{TlsConfig, TransportConfig};
use crate::transport::SocketOpts;
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use futures_util::StreamExt;
use p12::PFX;
use quinn::{Connecting, Connection, Endpoint, EndpointConfig, Incoming, VarInt};
use rustls::server::WantsServerCert;
use rustls::{ConfigBuilder, ServerConfig};
use rustls_pemfile::{read_all, read_one, Item};
use tokio::fs;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio::sync::Mutex;

pub const ALPN_QUIC_TUNNEL: &[&[u8]] = &[b"qt"];
pub const DEFAULT_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);
pub const DEFAULT_MAX_IDLE_TIMEOUT: u32 = 30_000;

pub struct QuicTransport {
    config: TlsConfig,
    client_crypto: Option<rustls::ClientConfig>,
}

impl Debug for QuicTransport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let client_crypto = &self.client_crypto.as_ref().map(|_| "ClientConfig{}");

        f.debug_struct("QuicTransport")
            .field("config", &self.config)
            .field("client_crypto", client_crypto)
            .finish()
    }
}

#[derive(Debug)]
pub struct QuicBiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    conn: Connection,
}

impl QuicBiStream {
    fn new((send, recv): (quinn::SendStream, quinn::RecvStream), conn: Connection) -> Self {
        Self { send, recv, conn }
    }
}

impl AsyncRead for QuicBiStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(self.get_mut().recv.borrow_mut()).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicBiStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, Error>> {
        Pin::new(self.get_mut().send.borrow_mut()).poll_write(cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::result::Result<(), Error>> {
        Pin::new(self.get_mut().send.borrow_mut()).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::result::Result<(), Error>> {
        Pin::new(self.get_mut().send.borrow_mut()).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<std::result::Result<usize, Error>> {
        Pin::new(self.get_mut().send.borrow_mut()).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.send.is_write_vectored()
    }
}

pub struct QuicAcceptor(Endpoint, Mutex<Incoming>);

impl From<QuicAcceptor> for Endpoint {
    fn from(a: QuicAcceptor) -> Self {
        a.0
    }
}

impl Drop for QuicBiStream {
    fn drop(&mut self) {
        self.conn.close(0u8.into(), &[]);
    }
}

async fn read_server_pkcs12(
    config: &TlsConfig,
    server_crypto: ConfigBuilder<ServerConfig, WantsServerCert>,
) -> Result<ServerConfig> {
    let buf = fs::read(
        config
            .pkcs12
            .as_ref()
            .with_context(|| "Config `quic.pkcs12` was not provided")?,
    )
    .await
    .with_context(|| "Failed to read the `quic.pkcs12`")?;

    let pfx = PFX::parse(buf.as_slice()).with_context(|| "Failed to parse `quic.pkcs12`")?;
    let keys = pfx
        .key_bags(
            config
                .pkcs12_password
                .as_ref()
                .with_context(|| "Expected `quic.pkcs12_password` value to be set")?,
        )
        .with_context(|| "Could not decrypt  `quic.pkcs12 with `quic.pkcs12_password`")?;
    let certs = pfx
        .cert_bags(
            config
                .pkcs12_password
                .as_ref()
                .with_context(|| "Config `quic.pkcs12_password` was not provided")?,
        )
        .with_context(|| "Could not decrypt  `quic.pkcs12` using `quic.pkcs12_password`")?;

    let chain: Vec<rustls::Certificate> = certs.into_iter().map(rustls::Certificate).collect();
    let key = rustls::PrivateKey(
        keys.into_iter()
            .next()
            .with_context(|| "No keys found in `quic.pkcs12`")?,
    );
    server_crypto
        .with_single_cert(chain, key)
        .with_context(|| "Server keys invalid")
}

async fn read_server_pem(
    config: &TlsConfig,
    server_crypto: ConfigBuilder<ServerConfig, WantsServerCert>,
) -> Result<ServerConfig> {
    // unwrap, since caller should have checked that pem_server_key exists
    let buf = fs::read(config.pem_server_key.as_ref().unwrap())
        .await
        .with_context(|| "Failed to read the `quic.pem_server_key`")?;
    let mut bufr = std::io::BufReader::new(buf.as_slice());
    let key: Vec<u8> =
        match read_one(&mut bufr).with_context(|| "Could not parse `quic.pem_server_key`")? {
            None => Err(anyhow!("`quic.pem_server_key` contained no keys")),
            Some(item) => match item {
                Item::X509Certificate(_) => Err(anyhow!(
                    "`quic.pem_server_key` should contain keys, not certificates"
                )),
                Item::RSAKey(der_key) => Ok(der_key),
                Item::PKCS8Key(der_key) => Ok(der_key),
            },
        }?;

    let buf = fs::read(config.pem_server_cert.as_ref().with_context(|| {
        "`quic.pem_server_key` was provided, yet `quic.pem_server_cert` is missing"
    })?)
    .await
    .with_context(|| "Failed to read the `quic.pem_server_cert`")?;

    let mut bufr = std::io::BufReader::new(buf.as_slice());
    let certs: Result<Vec<Vec<u8>>> = read_all(&mut bufr)
        .with_context(|| "Could not parse `quic.pem_server_cert`")?
        .into_iter()
        .map(|item| match item {
            Item::X509Certificate(der_cert) => Ok(der_cert),
            Item::RSAKey(_) | Item::PKCS8Key(_) => Err(anyhow!(
                "`quic.pem_server_cert` should contain certificates, not keys"
            )),
        })
        .collect();

    let certs = certs?;
    if certs.is_empty() {
        return Err(anyhow!("`quic.pem_server_cert` contained no certs"));
    }

    let chain: Vec<rustls::Certificate> = certs.into_iter().map(rustls::Certificate).collect();
    let key = rustls::PrivateKey(key);

    server_crypto
        .with_single_cert(chain, key)
        .with_context(|| "Server keys invalid")
}

#[async_trait]
impl Transport for QuicTransport {
    type Acceptor = QuicAcceptor;
    type RawStream = Connecting;
    type Stream = QuicBiStream;

    fn new(config: &TransportConfig) -> Result<Self> {
        let tls_config = match &config.quic {
            Some(v) => v,
            None => {
                return Err(anyhow!("Missing quic config: {:?}", config));
            }
        };

        let client_crypto = match tls_config.trusted_root.as_ref() {
            Some(path) => {
                let certs: Result<Vec<Vec<u8>>> = read_all(&mut BufReader::new(
                    &mut File::open(path)
                        .with_context(|| "Failed to open the `quic.trusted_root`")?,
                ))
                .with_context(|| "Could not parse `quic.trusted_root`")?
                .into_iter()
                .map(|item| match item {
                    Item::X509Certificate(der_cert) => Ok(der_cert),
                    Item::RSAKey(_) | Item::PKCS8Key(_) => Err(anyhow!(
                        "`quic.trusted_root` should contain certificates, not keys"
                    )),
                })
                .collect();

                let mut roots = rustls::RootCertStore::empty();
                for cert in certs?.into_iter() {
                    roots
                        .add(&rustls::Certificate(cert))
                        .with_context(|| "adding trusted root cert to trust store")?;
                }

                let mut client_crypto = rustls::ClientConfig::builder()
                    .with_safe_defaults()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                client_crypto.alpn_protocols = ALPN_QUIC_TUNNEL.iter().map(|&x| x.into()).collect();
                Some(client_crypto)
            }
            None => None,
        };

        Ok(QuicTransport {
            config: tls_config.clone(),
            client_crypto,
        })
    }

    fn hint(_: &Self::Stream, _: SocketOpts) {
        // keepalive must be set when connection is initiated. nothing to do...
    }

    async fn bind<A: ToSocketAddrs + Send + Sync>(&self, addr: A) -> Result<Self::Acceptor> {
        let server_crypto = rustls::ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth();
        let mut server_crypto = match self.config.pem_server_key {
            None => read_server_pkcs12(&self.config, server_crypto).await?,
            Some(_) => read_server_pem(&self.config, server_crypto).await?,
        };
        server_crypto.alpn_protocols = ALPN_QUIC_TUNNEL.iter().map(|&x| x.into()).collect();

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(server_crypto));
        server_config.use_retry(true);

        let mut transport_config = quinn::TransportConfig::default();
        transport_config
            .keep_alive_interval(Some(DEFAULT_KEEP_ALIVE_INTERVAL))
            .max_idle_timeout(Some(VarInt::from_u32(DEFAULT_MAX_IDLE_TIMEOUT).into()));
        server_config.transport = Arc::new(transport_config);

        let socket = UdpSocket::bind(addr).await?.into_std()?;
        quinn::Endpoint::new(EndpointConfig::default(), Some(server_config), socket)
            .with_context(|| "Failed to start server")
            .map(|(e, i)| QuicAcceptor(e, Mutex::new(i)))
    }

    async fn accept(&self, a: &Self::Acceptor) -> Result<(Self::RawStream, SocketAddr)> {
        let mut incoming = a.1.lock().await;
        if let Some(connecting) = incoming.next().await {
            let addr = connecting.remote_address();
            return Ok((connecting, addr));
        }
        Err(anyhow!("endpoint closed"))
    }

    async fn handshake(&self, conn: Self::RawStream) -> Result<Self::Stream> {
        let mut new_connection = conn.await?; // handshake happens here
                                              // Connection is established now. Wait for client to open a bidirectional stream
        if let Some(bi_stream_result) = new_connection.bi_streams.next().await {
            Ok(Self::Stream::new(
                bi_stream_result?,
                new_connection.connection,
            ))
        } else {
            anyhow::bail!("connection closed before bi stream could be established")
        }
    }

    async fn connect(&self, addr: &str) -> Result<Self::Stream> {
        let socket_addr: SocketAddr = addr.parse().with_context(|| "server addrress not valid")?;
        let local_addr = match socket_addr {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => ":::0",
        };

        let mut config =
            quinn::ClientConfig::new(Arc::new(self.client_crypto.as_ref().unwrap().clone()));
        let mut transport_config = quinn::TransportConfig::default();
        transport_config
            .keep_alive_interval(Some(DEFAULT_KEEP_ALIVE_INTERVAL))
            .max_idle_timeout(Some(VarInt::from_u32(DEFAULT_MAX_IDLE_TIMEOUT).into()));
        config.transport = Arc::new(transport_config);
        let mut endpoint = quinn::Endpoint::client(local_addr.parse().unwrap())
            .with_context(|| "could not open client socket")?;
        endpoint.set_default_client_config(config);

        let connecting = endpoint.connect(
            socket_addr,
            self.config
                .hostname
                .as_ref()
                .unwrap_or(&String::from(addr.split(':').next().unwrap())),
        )?;
        let new_conn = connecting.await?;
        Ok(QuicBiStream::new(
            new_conn.connection.open_bi().await?,
            new_conn.connection,
        ))
    }

    async fn close(&self, a: Self::Acceptor) {
        let e: Endpoint = a.into(); // drops Incoming
        e.close(0u8.into(), &[]);
        // wait for all connections to signal close as per spec
        // See https://github.com/quinn-rs/quinn/issues/1102
        // this may take a couple of seconds unfortunately, but without it we are not
        // guaranteed that the socket is released when we exit this method.
        e.wait_idle().await;
        drop(e);
    }
}
