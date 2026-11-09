//! Reusable TCP multiplexer and HTTP/TLS relay for high-latency links.
//!
//! Call [`run_server`] or [`run_client`] from an existing Tokio runtime. Configuration
//! is explicit: the library does not read environment variables, parse process
//! arguments, create a runtime, or exit the process.
//!
//! ```no_run
//! use satmux::{ClientConfig, ServerConfig, run_client, run_server};
//!
//! # async fn example() -> anyhow::Result<()> {
//! let psk = vec![0x42; 32]; // Use a securely generated, shared key in production.
//! let server = ServerConfig::new("0.0.0.0", 8444, psk.clone());
//! let client = ClientConfig::new("127.0.0.1", 8444, psk);
//! tokio::try_join!(run_server(server), run_client(client))?;
//! # Ok(())
//! # }
//! ```

use anyhow::{Context, Result, bail};
use blake2b_simd::Params as Blake2bParams;
use flate2::{Compression, read::ZlibDecoder, write::ZlibEncoder};
use hmac::{Hmac, Mac};
use rand::RngCore;
use reqwest::{Client, redirect::Policy};
use sha2::Sha256;
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU32, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{
        TcpListener, TcpSocket, TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{Mutex, mpsc},
    task::JoinSet,
    time,
};
use tokio_rustls::{
    TlsConnector,
    rustls::{ClientConfig as TlsClientConfig, RootCertStore, pki_types::ServerName},
};

/// Ground relay settings. The pre-shared key contains raw bytes, not hexadecimal text.
#[derive(Clone)]
pub struct ServerConfig {
    /// Address or hostname on which to listen.
    pub host: String,
    /// TCP carrier listening port.
    pub port: u16,
    /// Nonempty authentication and encryption key shared with clients.
    pub psk: Vec<u8>,
}

impl ServerConfig {
    /// Creates a configuration with an explicit listen address and shared key.
    pub fn new(host: impl Into<String>, port: u16, psk: Vec<u8>) -> Self {
        Self {
            host: host.into(),
            port,
            psk,
        }
    }
}

/// Local proxy settings. TCP proxies bind to loopback by default.
#[derive(Clone)]
pub struct ClientConfig {
    /// Ground relay address or hostname.
    pub host: String,
    /// Ground relay TCP carrier port.
    pub port: u16,
    /// Nonempty authentication and encryption key shared with the server.
    pub psk: Vec<u8>,
    /// Number of persistent carrier connections; must be greater than zero.
    pub carriers: usize,
    /// Host interface for the local TCP proxies. Defaults to loopback.
    pub listen_host: String,
    /// Local SOCKS5 listening port.
    pub socks_port: u16,
    /// Local HTTP proxy listening port.
    pub http_port: u16,
    /// Local 1-RTT HTTP fetch gateway listening port.
    pub fast_port: u16,
    /// Optional GitHub CLI TLS Unix socket path. Disabled by default.
    pub gh_socket: Option<String>,
}

impl ClientConfig {
    /// Creates a client with 12 carriers and proxy ports 1080, 8080, and 8081.
    ///
    /// The Unix socket bridge is disabled unless [`Self::gh_socket`] is set.
    pub fn new(host: impl Into<String>, port: u16, psk: Vec<u8>) -> Self {
        Self {
            host: host.into(),
            port,
            psk,
            carriers: 12,
            listen_host: "127.0.0.1".into(),
            socks_port: 1080,
            http_port: 8080,
            fast_port: 8081,
            gh_socket: None,
        }
    }
}

const HEADER_LEN: usize = 7;
const MAX_CHUNK: usize = 16_384;
const FT_OPEN: u8 = 1;
const FT_DATA_RAW: u8 = 4;
const FT_DATA_ZLIB: u8 = 5;
const FT_FIN: u8 = 6;
const FT_RST: u8 = 7;
const FT_PING: u8 = 8;
const FT_PONG: u8 = 9;
const FT_FETCH: u8 = 10;
const FT_DATA_ENC: u8 = 11;
type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
struct Frame {
    kind: u8,
    sid: u32,
    payload: Vec<u8>,
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Frame> {
    let mut hdr = [0; HEADER_LEN];
    reader.read_exact(&mut hdr).await?;
    let kind = hdr[0];
    let sid = u32::from_be_bytes(hdr[1..5].try_into()?);
    let len = u16::from_be_bytes(hdr[5..7].try_into()?) as usize;
    let mut payload = vec![0; len];
    reader.read_exact(&mut payload).await?;
    Ok(Frame { kind, sid, payload })
}

async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    kind: u8,
    sid: u32,
    payload: &[u8],
) -> Result<()> {
    let len = u16::try_from(payload.len()).context("protocol frame exceeds 65535 bytes")?;
    writer.write_all(&[kind]).await?;
    writer.write_all(&sid.to_be_bytes()).await?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    Ok(())
}

fn hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn derive_keys(psk: &[u8], nonce: &[u8], session: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut input = b"ORB-V3-C2S".to_vec();
    input.extend_from_slice(nonce);
    input.extend_from_slice(session);
    let c2s = hmac(psk, &input);
    input[..10].copy_from_slice(b"ORB-V3-S2C");
    let s2c = hmac(psk, &input);
    (c2s, s2c)
}

fn xor_keystream(key: &[u8], seq: u64, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for (block, chunk) in data.chunks(64).enumerate() {
        let mut counter = Vec::with_capacity(16);
        counter.extend_from_slice(&seq.to_be_bytes());
        counter.extend_from_slice(&(block as u64).to_be_bytes());
        let hash = Blake2bParams::new().hash_length(64).key(key).hash(&counter);
        out.extend(chunk.iter().zip(hash.as_bytes()).map(|(a, b)| a ^ b));
    }
    out
}

fn zlib(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(6));
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

fn unzlib(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

fn pack_data(
    key: &[u8],
    seq: &AtomicU64,
    sid: u32,
    data: &[u8],
    encrypt: bool,
    compress: bool,
) -> Result<Frame> {
    if encrypt {
        let seq = seq.fetch_add(1, Ordering::Relaxed) + 1;
        let mut payload = seq.to_be_bytes().to_vec();
        payload.extend(xor_keystream(key, seq, &zlib(data)?));
        return Ok(Frame {
            kind: FT_DATA_ENC,
            sid,
            payload,
        });
    }
    if compress && data.len() >= 128 {
        let compressed = zlib(data)?;
        if compressed.len() + 8 < data.len() {
            return Ok(Frame {
                kind: FT_DATA_ZLIB,
                sid,
                payload: compressed,
            });
        }
    }
    Ok(Frame {
        kind: FT_DATA_RAW,
        sid,
        payload: data.to_vec(),
    })
}

fn unpack_data(key: &[u8], frame: Frame) -> Result<Vec<u8>> {
    match frame.kind {
        FT_DATA_RAW => Ok(frame.payload),
        FT_DATA_ZLIB => unzlib(&frame.payload),
        FT_DATA_ENC => {
            if frame.payload.len() < 8 {
                bail!("encrypted data frame is shorter than its sequence number");
            }
            let seq = u64::from_be_bytes(frame.payload[..8].try_into()?);
            unzlib(&xor_keystream(key, seq, &frame.payload[8..]))
        }
        _ => bail!("not a data frame"),
    }
}

enum StreamEvent {
    Data(Vec<u8>),
    Fin,
    Reset,
}

struct Carrier {
    id: usize,
    writer: Mutex<OwnedWriteHalf>,
    streams: Mutex<HashMap<u32, mpsc::UnboundedSender<StreamEvent>>>,
    next_sid: AtomicU32,
    tx_seq: AtomicU64,
    tx_key: Vec<u8>,
    rx_key: Vec<u8>,
    load: Mutex<(f64, Instant)>,
}

impl Carrier {
    fn new(id: usize, writer: OwnedWriteHalf, tx_key: Vec<u8>, rx_key: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            id,
            writer: Mutex::new(writer),
            streams: Mutex::new(HashMap::new()),
            next_sid: AtomicU32::new(1),
            tx_seq: AtomicU64::new(0),
            tx_key,
            rx_key,
            load: Mutex::new((0.0, Instant::now())),
        })
    }

    async fn send(&self, kind: u8, sid: u32, payload: &[u8]) -> Result<()> {
        let mut w = self.writer.lock().await;
        write_frame(&mut *w, kind, sid, payload).await?;
        let mut load = self.load.lock().await;
        let dt = load.1.elapsed().as_secs_f64();
        load.0 *= 0.35_f64.powf(dt);
        load.0 += HEADER_LEN as f64 + payload.len() as f64;
        load.1 = Instant::now();
        Ok(())
    }

    async fn load_score(&self) -> f64 {
        let load = self.load.lock().await;
        load.0 * 0.35_f64.powf(load.1.elapsed().as_secs_f64())
    }

    async fn register(&self) -> (u32, mpsc::UnboundedReceiver<StreamEvent>) {
        let sid = self.next_sid.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::unbounded_channel();
        self.streams.lock().await.insert(sid, tx);
        (sid, rx)
    }
}

async fn dispatch_frames(mut reader: OwnedReadHalf, carrier: Arc<Carrier>) -> Result<()> {
    loop {
        let frame = read_frame(&mut reader).await?;
        let sid = frame.sid;
        if frame.kind == FT_PING {
            carrier.send(FT_PONG, 0, &frame.payload).await?;
            continue;
        }
        if frame.kind == FT_PONG {
            continue;
        }
        let event = match frame.kind {
            FT_DATA_RAW | FT_DATA_ZLIB | FT_DATA_ENC => {
                StreamEvent::Data(unpack_data(&carrier.rx_key, frame)?)
            }
            FT_FIN => StreamEvent::Fin,
            FT_RST => StreamEvent::Reset,
            _ => continue,
        };
        let terminal = matches!(event, StreamEvent::Fin | StreamEvent::Reset);
        let tx = { carrier.streams.lock().await.get(&sid).cloned() };
        if let Some(tx) = tx {
            let _ = tx.send(event);
        }
        if terminal {
            carrier.streams.lock().await.remove(&sid);
        }
    }
}

async fn accept_server(
    mut stream: TcpStream,
    psk: Arc<Vec<u8>>,
    fetch_client: Client,
) -> Result<()> {
    tune_socket(&stream, 1280);
    let mut nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut nonce);
    stream.write_all(&nonce).await?;
    let mut hello = [0u8; 48];
    time::timeout(Duration::from_secs(12), stream.read_exact(&mut hello)).await??;
    let session = &hello[..16];
    let mut auth = b"ORB-MUX-V3".to_vec();
    auth.extend_from_slice(&nonce);
    auth.extend_from_slice(session);
    if !constant_time_eq(&hmac(&psk, &auth), &hello[16..]) {
        bail!("invalid client HMAC");
    }
    let mut ok = b"ORB-MUX-V3-OK".to_vec();
    ok.extend_from_slice(&nonce);
    ok.extend_from_slice(session);
    stream.write_all(&hmac(&psk, &ok)).await?;
    let (c2s, s2c) = derive_keys(&psk, &nonce, session);
    let (reader, writer) = stream.into_split();
    let carrier = Carrier::new(0, writer, s2c, c2s);
    server_read_loop(reader, carrier, fetch_client).await
}

async fn server_read_loop(
    mut reader: OwnedReadHalf,
    carrier: Arc<Carrier>,
    fetch_client: Client,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        while let Some(result) = tasks.try_join_next() {
            result.context("server stream task failed")?;
        }
        let frame = read_frame(&mut reader).await?;
        let sid = frame.sid;
        match frame.kind {
            FT_PING => carrier.send(FT_PONG, 0, &frame.payload).await?,
            FT_OPEN => {
                let (tx, rx) = mpsc::unbounded_channel();
                carrier.streams.lock().await.insert(frame.sid, tx);
                tasks.spawn(server_stream(carrier.clone(), frame.sid, frame.payload, rx));
            }
            FT_FETCH => {
                let (tx, rx) = mpsc::unbounded_channel();
                carrier.streams.lock().await.insert(frame.sid, tx);
                tasks.spawn(ground_fetch(
                    carrier.clone(),
                    frame.sid,
                    frame.payload,
                    rx,
                    fetch_client.clone(),
                ));
            }
            FT_DATA_RAW | FT_DATA_ZLIB | FT_DATA_ENC | FT_FIN | FT_RST => {
                let event = match frame.kind {
                    FT_FIN => StreamEvent::Fin,
                    FT_RST => StreamEvent::Reset,
                    _ => StreamEvent::Data(unpack_data(&carrier.rx_key, frame)?),
                };
                let terminal = matches!(event, StreamEvent::Reset);
                let tx = { carrier.streams.lock().await.get(&sid).cloned() };
                if let Some(tx) = tx {
                    let _ = tx.send(event);
                }
                if terminal {
                    carrier.streams.lock().await.remove(&sid);
                }
            }
            _ => {}
        }
    }
}

async fn server_stream(
    carrier: Arc<Carrier>,
    sid: u32,
    payload: Vec<u8>,
    mut incoming: mpsc::UnboundedReceiver<StreamEvent>,
) {
    let result = async {
        let nul = payload
            .iter()
            .position(|b| *b == 0)
            .context("invalid OPEN payload")?;
        let host = std::str::from_utf8(&payload[..nul])?;
        let port = u16::from_be_bytes(
            payload
                .get(nul + 1..nul + 3)
                .context("missing port")?
                .try_into()?,
        );
        let mut socket =
            time::timeout(Duration::from_secs(8), connect_tuned(host, port, 1400)).await??;
        tune_socket(&socket, 1400);
        let (mut rd, mut wr) = socket.split();
        let mut down = vec![0u8; MAX_CHUNK];
        loop {
            tokio::select! {
                n = rd.read(&mut down) => {
                    let n = n?;
                    if n == 0 {
                        carrier.send(FT_FIN, sid, &[]).await?;
                        break;
                    }
                    let f = pack_data(
                        &carrier.tx_key,
                        &carrier.tx_seq,
                        sid,
                        &down[..n],
                        false,
                        port != 443,
                    )?;
                    carrier.send(f.kind, sid, &f.payload).await?;
                }
                event = incoming.recv() => match event {
                    Some(StreamEvent::Data(data)) => wr.write_all(&data).await?,
                    Some(StreamEvent::Fin) => { let _ = wr.shutdown().await; }
                    Some(StreamEvent::Reset) | None => break,
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if result.is_err() {
        let _ = carrier.send(FT_RST, sid, &[]).await;
    }
    carrier.streams.lock().await.remove(&sid);
}

async fn ground_fetch(
    carrier: Arc<Carrier>,
    sid: u32,
    payload: Vec<u8>,
    _incoming: mpsc::UnboundedReceiver<StreamEvent>,
    client: Client,
) {
    let result = async {
        if payload.len() < 8 {
            bail!("invalid encrypted fetch request");
        }
        let seq = u64::from_be_bytes(payload[..8].try_into()?);
        let request = unzlib(&xor_keystream(
            &carrier.rx_key,
            seq,
            &payload[8..],
        ))?;
        let text = String::from_utf8_lossy(&request);
        let mut lines = text.lines();
        let method = lines.next().unwrap_or("GET");
        let url = lines.next().context("missing fetch URL")?;
        let mut req = client.request(method.parse()?, url);
        for header in lines.skip(1) {
            if let Some((key, value)) = header.split_once(':') {
                if !matches!(
                    key.trim().to_ascii_lowercase().as_str(),
                    "host" | "connection" | "accept-encoding" | "proxy-connection" | "user-agent" | "accept"
                ) {
                    req = req.header(key.trim(), value.trim());
                }
            }
        }
        let response = req.send().await.context("upstream request failed")?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.bytes().await?;
        let mut output = format!("HTTP/1.1 {} {}\r\n", status.as_u16(), status.canonical_reason().unwrap_or("")).into_bytes();
        for (name, value) in &headers {
            if !matches!(name.as_str(), "connection" | "transfer-encoding" | "content-length") {
                output.extend_from_slice(name.as_str().as_bytes());
                output.extend_from_slice(b": ");
                output.extend_from_slice(value.as_bytes());
                output.extend_from_slice(b"\r\n");
            }
        }
        output.extend_from_slice(format!("Content-Length: {}\r\nConnection: close\r\nX-Orb-Sat-Mux: 1-RTT-Ground-TLS\r\n\r\n", body.len()).as_bytes());
        output.extend_from_slice(&body);
        for chunk in output.chunks(MAX_CHUNK) {
            let frame = pack_data(&carrier.tx_key, &carrier.tx_seq, sid, chunk, true, false)?;
            carrier.send(frame.kind, sid, &frame.payload).await?;
        }
        carrier.send(FT_FIN, sid, &[]).await?;
        Ok::<(), anyhow::Error>(())
    }.await;
    if let Err(error) = result {
        let body = format!("Mux Fetch Error: {error}\n");
        let output = format!(
            "HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        if let Ok(frame) = pack_data(
            &carrier.tx_key,
            &carrier.tx_seq,
            sid,
            output.as_bytes(),
            true,
            false,
        ) {
            let _ = carrier.send(frame.kind, sid, &frame.payload).await;
        }
        let _ = carrier.send(FT_FIN, sid, &[]).await;
    }
    carrier.streams.lock().await.remove(&sid);
}

/// Runs the ground relay on the caller's Tokio runtime until cancelled or an error occurs.
///
/// Returns setup and listener errors to the caller. Dropping this future closes its
/// listener and aborts its carrier and stream tasks.
pub async fn run_server(config: ServerConfig) -> Result<()> {
    let ServerConfig { host, port, psk } = config;
    if psk.is_empty() {
        bail!("server pre-shared key must not be empty");
    }
    let listener = TcpListener::bind((host.as_str(), port)).await?;
    let fetch_client = Client::builder()
        .redirect(Policy::limited(5))
        .user_agent("curl/8.7.1")
        .build()?;
    println!("[mux-v3-server] BBR+0RTT+1RTT Listening on {host}:{port}");
    let psk = Arc::new(psk);
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let psk = psk.clone();
                let client = fetch_client.clone();
                tasks.spawn(async move {
                    if let Err(error) = accept_server(stream, psk, client).await {
                        eprintln!("[mux-v3-server] carrier closed: {error:#}");
                    }
                });
            }
            Some(result) = tasks.join_next() => {
                result.context("server carrier task failed")?;
            }
        }
    }
}

struct ClientState {
    server: SocketAddr,
    psk: Vec<u8>,
    session: [u8; 16],
    carriers: Mutex<HashMap<usize, Arc<Carrier>>>,
}

impl ClientState {
    async fn pick(&self) -> Option<Arc<Carrier>> {
        let carriers = self
            .carriers
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut ranked = Vec::new();
        for c in carriers {
            ranked.push((c.load_score().await, c.id, c));
        }
        ranked.sort_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)));
        ranked.into_iter().next().map(|(_, _, c)| c)
    }

    async fn wait_carrier(&self) -> Result<Arc<Carrier>> {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if let Some(carrier) = self.pick().await {
                return Ok(carrier);
            }
            if Instant::now() >= deadline {
                bail!("no warm carrier available");
            }
            time::sleep(Duration::from_millis(50)).await;
        }
    }
}

async fn maintain_carrier(state: Arc<ClientState>, idx: usize) {
    let mut backoff = 1.0;
    loop {
        let attempt = async {
            let mut stream = time::timeout(
                Duration::from_secs(12),
                connect_tuned_addr(state.server, 1280),
            )
            .await??;
            tune_socket(&stream, 1280);
            let mut nonce = [0u8; 32];
            time::timeout(Duration::from_secs(10), stream.read_exact(&mut nonce)).await??;
            let mut auth = b"ORB-MUX-V3".to_vec();
            auth.extend_from_slice(&nonce);
            auth.extend_from_slice(&state.session);
            stream.write_all(&state.session).await?;
            stream.write_all(&hmac(&state.psk, &auth)).await?;
            let mut response = [0u8; 32];
            time::timeout(Duration::from_secs(10), stream.read_exact(&mut response)).await??;
            let mut expected = b"ORB-MUX-V3-OK".to_vec();
            expected.extend_from_slice(&nonce);
            expected.extend_from_slice(&state.session);
            if !constant_time_eq(&hmac(&state.psk, &expected), &response) {
                bail!("bad server HMAC");
            }
            let (c2s, s2c) = derive_keys(&state.psk, &nonce, &state.session);
            let (reader, writer) = stream.into_split();
            let carrier = Carrier::new(idx, writer, c2s, s2c);
            state.carriers.lock().await.insert(idx, carrier.clone());
            println!("[mux-v3-client] Carrier #{idx} READY");
            let result = dispatch_frames(reader, carrier.clone()).await;
            state.carriers.lock().await.remove(&idx);
            carrier.streams.lock().await.clear();
            result
        }
        .await;
        if let Err(error) = attempt {
            eprintln!("[mux-v3-client] Carrier #{idx} disconnected: {error:#}");
        }
        time::sleep(Duration::from_secs_f64(backoff)).await;
        backoff = (backoff * 1.5).min(5.0);
    }
}

async fn open_tunnel(
    state: Arc<ClientState>,
    mut local: TcpStream,
    host: String,
    port: u16,
) -> Result<()> {
    let carrier = state.wait_carrier().await?;
    let (sid, mut incoming) = carrier.register().await;
    let mut payload = host.into_bytes();
    payload.push(0);
    payload.extend_from_slice(&port.to_be_bytes());
    carrier.send(FT_OPEN, sid, &payload).await?;
    let (mut rd, mut wr) = local.split();
    let upload_carrier = carrier.clone();
    let upload = async move {
        let mut buf = vec![0; MAX_CHUNK];
        loop {
            let n = rd.read(&mut buf).await?;
            if n == 0 {
                upload_carrier.send(FT_FIN, sid, &[]).await?;
                return Ok::<(), anyhow::Error>(());
            }
            let frame = pack_data(
                &upload_carrier.tx_key,
                &upload_carrier.tx_seq,
                sid,
                &buf[..n],
                false,
                port != 443,
            )?;
            upload_carrier.send(frame.kind, sid, &frame.payload).await?;
        }
    };
    let download = async {
        while let Some(event) = incoming.recv().await {
            match event {
                StreamEvent::Data(data) => wr.write_all(&data).await?,
                StreamEvent::Fin => {
                    let _ = wr.shutdown().await;
                    break;
                }
                StreamEvent::Reset => break,
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    tokio::try_join!(upload, download)?;
    carrier.streams.lock().await.remove(&sid);
    Ok(())
}

async fn socks_handler(stream: TcpStream, state: Arc<ClientState>) -> Result<()> {
    let mut stream = stream;
    let mut greeting = [0; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != 5 {
        bail!("unsupported SOCKS version");
    }
    let mut methods = vec![0; greeting[1] as usize];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[5, 0]).await?;
    let mut head = [0; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 5 || head[1] != 1 {
        stream.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        bail!("unsupported SOCKS request");
    }
    let host = match head[3] {
        1 => {
            let mut b = [0; 4];
            stream.read_exact(&mut b).await?;
            Ipv4Addr::from(b).to_string()
        }
        3 => {
            let len = stream.read_u8().await? as usize;
            let mut b = vec![0; len];
            stream.read_exact(&mut b).await?;
            String::from_utf8(b)?
        }
        4 => {
            let mut b = [0; 16];
            stream.read_exact(&mut b).await?;
            Ipv6Addr::from(b).to_string()
        }
        _ => bail!("unsupported SOCKS address type"),
    };
    let port = stream.read_u16().await?;
    stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    match open_tunnel(state, stream, host, port).await {
        Ok(()) => Ok(()),
        Err(error) => Err(error),
    }
}

async fn http_handler(mut stream: TcpStream, state: Arc<ClientState>) -> Result<()> {
    let mut head = Vec::new();
    loop {
        let byte = stream.read_u8().await?;
        head.push(byte);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > 64 * 1024 {
            bail!("HTTP proxy header too large");
        }
    }
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.split("\r\n");
    let request = lines.next().context("empty HTTP request")?;
    let mut p = request.split_whitespace();
    let method = p.next().unwrap_or("");
    let target = p.next().unwrap_or("");
    let proto = p.next().unwrap_or("HTTP/1.1");
    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = parse_host_port(target, 443)?;
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        open_tunnel(state, stream, host, port).await
    } else {
        let (host, port, path) = parse_http_target(target, &text)?;
        let carrier = state.wait_carrier().await?;
        let (sid, incoming) = carrier.register().await;
        carrier
            .send(
                FT_OPEN,
                sid,
                &[host.as_bytes(), &[0], &port.to_be_bytes()].concat(),
            )
            .await?;
        let mut request = format!("{method} {path} {proto}\r\n").into_bytes();
        for line in lines {
            if !line.is_empty() && !line.to_ascii_lowercase().starts_with("proxy-") {
                request.extend_from_slice(line.as_bytes());
                request.extend_from_slice(b"\r\n");
            }
        }
        request.extend_from_slice(b"\r\n");
        let frame = pack_data(&carrier.tx_key, &carrier.tx_seq, sid, &request, false, true)?;
        carrier.send(frame.kind, sid, &frame.payload).await?;
        relay_local_http(stream, carrier, sid, incoming).await
    }
}

async fn relay_local_http(
    mut local: TcpStream,
    carrier: Arc<Carrier>,
    sid: u32,
    mut incoming: mpsc::UnboundedReceiver<StreamEvent>,
) -> Result<()> {
    let mut buf = vec![0; MAX_CHUNK];
    loop {
        tokio::select! {
            n = local.read(&mut buf) => {
                let n = n?;
                if n == 0 { carrier.send(FT_FIN, sid, &[]).await?; break; }
                let frame = pack_data(
                    &carrier.tx_key,
                    &carrier.tx_seq,
                    sid,
                    &buf[..n],
                    false,
                    true,
                )?;
                carrier.send(frame.kind, sid, &frame.payload).await?;
            }
            event = incoming.recv() => match event {
                Some(StreamEvent::Data(data)) => local.write_all(&data).await?,
                Some(StreamEvent::Fin) => { let _ = local.shutdown().await; break; }
                Some(StreamEvent::Reset) | None => break,
            }
        }
    }
    carrier.streams.lock().await.remove(&sid);
    Ok(())
}

fn parse_host_port(value: &str, default_port: u16) -> Result<(String, u16)> {
    if let Some((host, port)) = value.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            return Ok((host.trim_matches(['[', ']']).to_string(), port));
        }
    }
    Ok((value.to_string(), default_port))
}

fn parse_http_target(target: &str, headers: &str) -> Result<(String, u16, String)> {
    if let Some(url) = target.strip_prefix("http://") {
        let (authority, path) = url.split_once('/').unwrap_or((url, ""));
        let (host, port) = parse_host_port(authority, 80)?;
        return Ok((
            host,
            port,
            if path.is_empty() {
                "/".into()
            } else {
                format!("/{path}")
            },
        ));
    }
    let host = headers
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .starts_with("host:")
                .then(|| line.split_once(':').map(|(_, v)| v.trim()))
                .flatten()
        })
        .context("HTTP request has no Host header")?;
    let (host, port) = parse_host_port(host, 80)?;
    Ok((host, port, target.to_string()))
}

async fn fast_handler(mut stream: TcpStream, state: Arc<ClientState>) -> Result<()> {
    let mut head = Vec::new();
    loop {
        let byte = stream.read_u8().await?;
        head.push(byte);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > 64 * 1024 {
            bail!("fetch request header too large");
        }
    }
    let text = String::from_utf8_lossy(&head);
    let mut lines = text.split("\r\n");
    let mut request_parts = lines.next().unwrap_or("").split_whitespace();
    let method = request_parts.next().unwrap_or("GET").to_ascii_uppercase();
    let raw_url = request_parts.next().unwrap_or("");
    let url = raw_url.trim_start_matches('/');
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\nPass /https://<host>/<path>\n").await?;
        return Ok(());
    }
    let carrier = state.wait_carrier().await?;
    let (sid, mut incoming) = carrier.register().await;
    let mut request = format!("{method}\n{url}");
    for line in lines.filter(|line| !line.is_empty()) {
        request.push('\n');
        request.push_str(line);
    }
    let seq = carrier.tx_seq.fetch_add(1, Ordering::Relaxed) + 1;
    let mut encoded = seq.to_be_bytes().to_vec();
    encoded.extend(xor_keystream(
        &carrier.tx_key,
        seq,
        &zlib(request.as_bytes())?,
    ));
    carrier.send(FT_FETCH, sid, &encoded).await?;
    while let Some(event) = incoming.recv().await {
        match event {
            StreamEvent::Data(data) => stream.write_all(&data).await?,
            StreamEvent::Fin | StreamEvent::Reset => break,
        }
    }
    carrier.streams.lock().await.remove(&sid);
    Ok(())
}

fn tls_connector() -> Result<TlsConnector> {
    let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let provider = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider();
    let config = TlsClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

async fn gh_handler(
    mut local: tokio::net::UnixStream,
    socks_port: u16,
    connector: TlsConnector,
) -> Result<()> {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        let mut b = [0];
        local.read_exact(&mut b).await?;
        header.push(b[0]);
        if header.len() > 65_536 {
            bail!("request header too large");
        }
    }
    let host_line = String::from_utf8_lossy(&header)
        .lines()
        .find(|line| line.to_ascii_lowercase().starts_with("host:"))
        .map(|line| {
            line.split_once(':')
                .map(|(_, v)| v.trim().to_string())
                .unwrap_or_default()
        })
        .unwrap_or_else(|| "api.github.com".to_string());
    let (hostname, port) = parse_host_port(&host_line, 443)?;
    let mut sock = TcpStream::connect(("127.0.0.1", socks_port)).await?;
    sock.write_all(&[5, 1, 0]).await?;
    let mut response = [0; 2];
    sock.read_exact(&mut response).await?;
    if response != [5, 0] {
        bail!("SOCKS5 authentication negotiation failed");
    }
    let name = hostname.as_bytes();
    if name.len() > 255 {
        bail!("hostname is too long for SOCKS5");
    }
    sock.write_all(&[5, 1, 0, 3, name.len() as u8]).await?;
    sock.write_all(name).await?;
    sock.write_u16(port).await?;
    let mut reply = [0; 4];
    sock.read_exact(&mut reply).await?;
    if reply[1] != 0 {
        bail!("SOCKS5 connect failed with code {}", reply[1]);
    }
    match reply[3] {
        1 => {
            let mut discard = [0; 4];
            sock.read_exact(&mut discard).await?;
        }
        4 => {
            let mut discard = [0; 16];
            sock.read_exact(&mut discard).await?;
        }
        3 => {
            let len = sock.read_u8().await?;
            let mut discard = vec![0; len as usize];
            sock.read_exact(&mut discard).await?;
        }
        _ => bail!("invalid SOCKS5 bind address"),
    }
    let dns_name = ServerName::try_from(hostname.clone()).context("invalid TLS hostname")?;
    let mut tls = connector.connect(dns_name, sock).await?;
    let request = String::from_utf8_lossy(&header);
    let mut lines = request.split("\r\n");
    let mut request_head = lines.next().unwrap_or_default().as_bytes().to_vec();
    request_head.extend_from_slice(b"\r\n");
    for line in lines {
        if line.is_empty() {
            break;
        }
        if !line.to_ascii_lowercase().starts_with("connection:") {
            request_head.extend_from_slice(line.as_bytes());
            request_head.extend_from_slice(b"\r\n");
        }
    }
    request_head.extend_from_slice(b"Connection: close\r\n\r\n");
    tls.write_all(&request_head).await?;
    io::copy_bidirectional(&mut local, &mut tls).await?;
    Ok(())
}

/// Runs the local proxies on the caller's Tokio runtime until cancelled or an error occurs.
///
/// Returns invalid configuration, DNS, and listener setup errors to the caller.
/// Carrier disconnections are logged and retried. Dropping this future closes its
/// TCP listeners and aborts its carrier, keepalive, and proxy tasks.
pub async fn run_client(config: ClientConfig) -> Result<()> {
    let ClientConfig {
        host,
        port,
        psk,
        carriers,
        listen_host,
        socks_port,
        http_port,
        fast_port,
        gh_socket,
    } = config;
    if psk.is_empty() {
        bail!("client pre-shared key must not be empty");
    }
    if carriers == 0 {
        bail!("client must have at least one carrier");
    }
    let server = tokio::net::lookup_host((host.as_str(), port))
        .await?
        .next()
        .context("server DNS lookup returned no addresses")?;
    let socks = TcpListener::bind((listen_host.as_str(), socks_port)).await?;
    let http = TcpListener::bind((listen_host.as_str(), http_port)).await?;
    let fast = TcpListener::bind((listen_host.as_str(), fast_port)).await?;
    let connector = tls_connector()?;
    let gh_listener = if let Some(path) = gh_socket.as_deref() {
        if Path::new(path).exists() {
            tokio::fs::remove_file(path).await?;
        }
        Some((tokio::net::UnixListener::bind(path)?, path.to_string()))
    } else {
        None
    };
    if let Some((_, path)) = &gh_listener {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
        }
    }
    let mut session = [0; 16];
    rand::rng().fill_bytes(&mut session);
    let state = Arc::new(ClientState {
        server,
        psk,
        session,
        carriers: Mutex::new(HashMap::new()),
    });
    let mut tasks = JoinSet::new();
    for idx in 1..=carriers {
        tasks.spawn(maintain_carrier(state.clone(), idx));
    }
    let keepalive_state = state.clone();
    tasks.spawn(async move {
        loop {
            time::sleep(Duration::from_secs(12)).await;
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64()
                .to_be_bytes();
            let live = keepalive_state
                .carriers
                .lock()
                .await
                .values()
                .cloned()
                .collect::<Vec<_>>();
            for carrier in live {
                let _ = carrier.send(FT_PING, 0, &timestamp).await;
            }
        }
    });
    println!(
        "[mux-v3-client] Ready! SOCKS5={listen_host}:{socks_port} | HTTP={listen_host}:{http_port} | 1-RTT-Gate={listen_host}:{fast_port} | {carriers} warm carriers"
    );
    loop {
        tokio::select! {
            accepted = socks.accept() => {
                let (stream, _) = accepted?;
                let state = state.clone();
                tasks.spawn(async move {
                    if let Err(error) = socks_handler(stream, state).await { eprintln!("[socks] {error:#}"); }
                });
            }
            accepted = http.accept() => {
                let (stream, _) = accepted?;
                let state = state.clone();
                tasks.spawn(async move {
                    if let Err(error) = http_handler(stream, state).await {
                        eprintln!("[http-proxy] {error:#}");
                    }
                });
            }
            accepted = fast.accept() => {
                let (stream, _) = accepted?;
                let state = state.clone();
                tasks.spawn(async move {
                    if let Err(error) = fast_handler(stream, state).await { eprintln!("[fetch-gate] {error:#}"); }
                });
            }
            accepted = async {
                match &gh_listener {
                    Some((listener, _)) => listener.accept().await.map(Some),
                    None => std::future::pending().await,
                }
            } => {
                if let Some((stream, _)) = accepted? {
                    let connector = connector.clone();
                    tasks.spawn(async move {
                        if let Err(error) = gh_handler(stream, socks_port, connector).await {
                            eprintln!("[gh-tls] {error:#}");
                        }
                    });
                }
            }
            Some(result) = tasks.join_next() => {
                result.context("client background task failed")?;
            }
        }
    }
}

fn tune_socket(stream: &TcpStream, mss: u32) {
    let _ = stream.set_nodelay(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        tune_socket_fd(stream.as_raw_fd(), mss);
    }
}

async fn connect_tuned(host: &str, port: u16, mss: u32) -> Result<TcpStream> {
    let addresses = tokio::net::lookup_host((host, port))
        .await?
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        bail!("target DNS lookup returned no addresses");
    }
    let mut last_error = None;
    for address in addresses {
        match connect_tuned_addr(address, mss).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.context("unable to connect to any target address")?)
}

async fn connect_tuned_addr(address: SocketAddr, mss: u32) -> Result<TcpStream> {
    let socket = if address.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        tune_socket_fd(socket.as_raw_fd(), mss);
    }
    let stream = socket.connect(address).await?;
    tune_socket(&stream, mss);
    Ok(stream)
}

#[cfg(target_os = "linux")]
fn tune_socket_fd(fd: std::os::fd::RawFd, mss: u32) {
    unsafe {
        let enabled: libc::c_int = 1;
        let buffer_size: libc::c_int = 2 * 1024 * 1024;
        let mss = mss as libc::c_int;
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&buffer_size as *const libc::c_int).cast(),
            std::mem::size_of_val(&buffer_size) as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            (&buffer_size as *const libc::c_int).cast(),
            std::mem::size_of_val(&buffer_size) as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_MAXSEG,
            (&mss as *const libc::c_int).cast(),
            std::mem::size_of_val(&mss) as libc::socklen_t,
        );
        let congestion = b"bbr\0";
        let _ = libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            congestion.as_ptr().cast(),
            congestion.len() as libc::socklen_t,
        );
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |diff, (x, y)| diff | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_derivation_matches_protocol_vectors() {
        let (c2s, s2c) = derive_keys(b"secret", &[7; 32], &[9; 16]);
        let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        assert_eq!(
            hex(&c2s),
            "4f7be30aeabac2588ba2b50a945e18a8b938fc451219071af97adf71a24a602f"
        );
        assert_eq!(
            hex(&s2c),
            "4dbe68e69e6fba3c9527f4c01d0963da65a4600be9eeb1026f1d1ce51fef5a96"
        );
        assert_eq!(
            xor_keystream(b"test key", 1, b"parity"),
            [0x66, 0xc2, 0x3b, 0x06, 0x47, 0xe7]
        );
    }

    #[test]
    fn encrypted_and_compressed_payload_round_trips() {
        let data = b"same response repeated; ".repeat(1000);
        let seq = AtomicU64::new(0);
        let frame = pack_data(b"test key", &seq, 42, &data, true, false).unwrap();
        assert_eq!(frame.kind, FT_DATA_ENC);
        assert_eq!(unpack_data(b"test key", frame).unwrap(), data);
        let plain = pack_data(b"test key", &seq, 43, &data, false, true).unwrap();
        assert_eq!(plain.kind, FT_DATA_ZLIB);
        assert_eq!(unpack_data(b"test key", plain).unwrap(), data);
    }

    #[test]
    fn http_proxy_target_parsing_matches_python_routes() {
        assert_eq!(
            parse_http_target(
                "http://example.test/a?b=1",
                "GET http://example.test/a?b=1 HTTP/1.1\r\n"
            )
            .unwrap(),
            ("example.test".into(), 80, "/a?b=1".into())
        );
        assert_eq!(
            parse_http_target("/path", "GET /path HTTP/1.1\r\nHost: example.test:8080\r\n")
                .unwrap(),
            ("example.test".into(), 8080, "/path".into())
        );
    }

    #[tokio::test]
    async fn frame_header_matches_python_big_endian_layout() {
        let (mut client, mut peer) = io::duplex(64);
        write_frame(&mut client, FT_OPEN, 0x0102_0304, &[0xaa, 0xbb])
            .await
            .unwrap();
        let frame = read_frame(&mut peer).await.unwrap();
        assert_eq!(frame.kind, FT_OPEN);
        assert_eq!(frame.sid, 0x0102_0304);
        assert_eq!(frame.payload, [0xaa, 0xbb]);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn linux_outbound_socket_applies_mss_before_connect() {
        use std::{mem::size_of, os::fd::AsRawFd};

        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let connect = connect_tuned_addr(address, 1200);
        let (client, accepted) = tokio::join!(connect, listener.accept());
        let client = client.unwrap();
        let _accepted = accepted.unwrap().0;

        let mut mss: libc::c_int = 0;
        let mut mss_len = size_of::<libc::c_int>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                client.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_MAXSEG,
                (&mut mss as *mut libc::c_int).cast(),
                &mut mss_len,
            )
        };
        assert_eq!(result, 0);
        assert!(mss > 0 && mss <= 1200, "configured MSS was {mss}");
    }

    #[tokio::test]
    async fn local_tcp_tunnel_round_trips_through_compatible_carrier() {
        let echo_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = echo_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0; 1024];
                    while let Ok(n) = stream.read(&mut buf).await {
                        if n == 0 {
                            break;
                        }
                        if stream.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    let _ = stream.shutdown().await;
                });
            }
        });

        let server_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let server_addr = server_listener.local_addr().unwrap();
        let psk = Arc::new(b"parity test key".to_vec());
        let fetch_client = Client::builder().build().unwrap();
        let server_psk = psk.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = server_listener.accept().await {
                let psk = server_psk.clone();
                let fetch_client = fetch_client.clone();
                tokio::spawn(async move {
                    if let Err(error) = accept_server(stream, psk, fetch_client).await {
                        eprintln!("test server carrier: {error:#}");
                    }
                });
            }
        });

        let state = Arc::new(ClientState {
            server: server_addr,
            psk: psk.as_ref().clone(),
            session: [31; 16],
            carriers: Mutex::new(HashMap::new()),
        });
        tokio::spawn(maintain_carrier(state.clone(), 1));
        time::timeout(Duration::from_secs(5), state.wait_carrier())
            .await
            .expect("carrier connection timed out")
            .unwrap();

        let local_listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let local_addr = local_listener.local_addr().unwrap();
        let (local, client) = tokio::join!(local_listener.accept(), TcpStream::connect(local_addr));
        let local = local.unwrap().0;
        let mut client = client.unwrap();
        let tunnel_state = state.clone();
        let tunnel = tokio::spawn(async move {
            open_tunnel(tunnel_state, local, "127.0.0.1".into(), echo_port).await
        });
        let message = b"python-compatible framing and stream relay";
        client.write_all(message).await.unwrap();
        let mut received = vec![0; message.len()];
        time::timeout(Duration::from_secs(5), client.read_exact(&mut received))
            .await
            .expect("tunnel response timed out")
            .unwrap();
        assert_eq!(received, message);
        client.shutdown().await.unwrap();
        let mut remainder = Vec::new();
        time::timeout(Duration::from_secs(5), client.read_to_end(&mut remainder))
            .await
            .expect("tunnel EOF timed out")
            .unwrap();
        time::timeout(Duration::from_secs(5), tunnel)
            .await
            .expect("tunnel task timed out")
            .unwrap()
            .unwrap();
    }
}
