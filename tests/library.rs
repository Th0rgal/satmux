use satmux::{ClientConfig, ServerConfig, run_client, run_server};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn configuration_is_explicit_and_client_defaults_match_proxy_ports() {
    let psk = vec![0x42; 32];
    let server = ServerConfig::new("0.0.0.0", 8444, psk.clone());
    assert_eq!(server.host, "0.0.0.0");
    assert_eq!(server.port, 8444);
    assert_eq!(server.psk, psk);

    let client = ClientConfig::new("relay.example", 8444, psk.clone());
    assert_eq!(client.host, "relay.example");
    assert_eq!(client.port, 8444);
    assert_eq!(client.psk, psk);
    assert_eq!(client.carriers, 12);
    assert_eq!(client.listen_host, "127.0.0.1");
    assert_eq!(client.socks_port, 1080);
    assert_eq!(client.http_port, 8080);
    assert_eq!(client.fast_port, 8081);
    assert!(client.gh_socket.is_none());
}

#[tokio::test]
async fn invalid_configuration_returns_errors_to_the_caller() {
    let server_error = run_server(ServerConfig::new("127.0.0.1", 0, Vec::new()))
        .await
        .unwrap_err();
    assert!(server_error.to_string().contains("key must not be empty"));

    let client_error = run_client(ClientConfig::new("127.0.0.1", 0, Vec::new()))
        .await
        .unwrap_err();
    assert!(client_error.to_string().contains("key must not be empty"));

    let mut client = ClientConfig::new("127.0.0.1", 0, vec![0x42; 32]);
    client.carriers = 0;
    let error = run_client(client).await.unwrap_err();
    assert!(error.to_string().contains("at least one carrier"));
}

#[tokio::test]
async fn occupied_listener_ports_return_errors_without_starting_carriers() {
    let occupied = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let port = occupied.local_addr().unwrap().port();
    let server = ServerConfig::new("127.0.0.1", port, vec![0x42; 32]);
    assert!(run_server(server).await.is_err());

    let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let mut client = ClientConfig::new(
        "127.0.0.1",
        upstream.local_addr().unwrap().port(),
        vec![0x42; 32],
    );
    client.socks_port = 0;
    client.http_port = port;
    client.fast_port = 0;
    assert!(run_client(client).await.is_err());
    assert!(
        timeout(Duration::from_millis(100), upstream.accept())
            .await
            .is_err(),
        "failed client setup must not leave a carrier connecting in the background"
    );
}

#[tokio::test]
async fn cancelling_client_closes_its_background_carrier() {
    let upstream = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let mut config = ClientConfig::new(
        "127.0.0.1",
        upstream.local_addr().unwrap().port(),
        vec![0x42; 32],
    );
    config.carriers = 1;
    config.socks_port = 0;
    config.http_port = 0;
    config.fast_port = 0;

    let task = tokio::spawn(run_client(config));
    let (mut carrier, _) = timeout(TEST_TIMEOUT, upstream.accept())
        .await
        .expect("client did not connect")
        .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let mut byte = [0];
    assert_eq!(
        timeout(TEST_TIMEOUT, carrier.read(&mut byte))
            .await
            .expect("cancelled client retained its carrier")
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn cancelling_server_closes_its_accepted_carriers() {
    let reservation = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);
    let config = ServerConfig::new("127.0.0.1", address.port(), vec![0x42; 32]);
    let mut server = Box::pin(run_server(config));
    let connect = async {
        loop {
            if let Ok(stream) = TcpStream::connect(address).await {
                return stream;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    let mut carrier = tokio::select! {
        result = &mut server => panic!("server stopped during setup: {result:?}"),
        result = timeout(TEST_TIMEOUT, connect) => result.expect("server did not start"),
    };
    let mut nonce = [0; 32];
    tokio::select! {
        result = &mut server => panic!("server stopped during handshake: {result:?}"),
        result = timeout(TEST_TIMEOUT, carrier.read_exact(&mut nonce)) => {
            result.expect("server did not send a nonce").unwrap();
        }
    }
    drop(server);
    let mut byte = [0];
    assert_eq!(
        timeout(TEST_TIMEOUT, carrier.read(&mut byte))
            .await
            .expect("cancelled server retained its carrier")
            .unwrap(),
        0
    );
    TcpListener::bind(address)
        .await
        .expect("cancelled server retained its listener");
}

#[tokio::test]
async fn public_entry_points_relay_socks_http_connect_and_fetch() {
    let mut reservations = Vec::new();
    for _ in 0..4 {
        reservations.push(TcpListener::bind(("127.0.0.1", 0)).await.unwrap());
    }
    let ports = reservations
        .iter()
        .map(|listener| listener.local_addr().unwrap().port())
        .collect::<Vec<_>>();
    let origin = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let origin_port = origin.local_addr().unwrap().port();
    let body = b"reusable satmux library response\n".repeat(2048);
    let response = [
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes(),
        body.clone(),
    ]
    .concat();
    let serve_origin = async {
        loop {
            let (mut stream, _) = origin.accept().await.unwrap();
            read_header(&mut stream).await;
            stream.write_all(&response).await.unwrap();
            stream.shutdown().await.unwrap();
        }
    };

    let psk = vec![0x42; 32];
    let server = ServerConfig::new("127.0.0.1", ports[0], psk.clone());
    let mut client = ClientConfig::new("127.0.0.1", ports[0], psk);
    client.carriers = 2;
    client.socks_port = ports[1];
    client.http_port = ports[2];
    client.fast_port = ports[3];
    drop(reservations);

    let exercise = async {
        println!("=== PUBLIC LIBRARY: SOCKS5 + HTTP + CONNECT + FETCH ===");
        let mut socks = loop {
            if let Ok(stream) = TcpStream::connect(("127.0.0.1", ports[1])).await {
                break stream;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        socks.write_all(&[5, 1, 0]).await.unwrap();
        let mut auth = [0; 2];
        socks.read_exact(&mut auth).await.unwrap();
        assert_eq!(auth, [5, 0]);
        socks.write_all(&[5, 1, 0, 1, 127, 0, 0, 1]).await.unwrap();
        socks.write_u16(origin_port).await.unwrap();
        let mut connected = [0; 10];
        socks.read_exact(&mut connected).await.unwrap();
        assert_eq!(connected, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        socks
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut received = Vec::new();
        socks.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, response);
        drop(socks);
        println!("SOCKS5: full response matches origin");

        let mut http = TcpStream::connect(("127.0.0.1", ports[2])).await.unwrap();
        http.write_all(
            format!("GET http://127.0.0.1:{origin_port}/ HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
        let mut received = Vec::new();
        http.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, response);
        println!("HTTP proxy: full response matches origin");

        let mut connect = TcpStream::connect(("127.0.0.1", ports[2])).await.unwrap();
        connect
            .write_all(
                format!("CONNECT 127.0.0.1:{origin_port} HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        assert_eq!(
            read_header(&mut connect).await,
            b"HTTP/1.1 200 Connection Established\r\n\r\n"
        );
        connect
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut received = Vec::new();
        connect.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, response);
        drop(connect);
        println!("HTTP CONNECT: full response matches origin");

        let mut fetch = TcpStream::connect(("127.0.0.1", ports[3])).await.unwrap();
        fetch
            .write_all(
                format!("GET /http://127.0.0.1:{origin_port}/ HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    .as_bytes(),
            )
            .await
            .unwrap();
        let header = read_header(&mut fetch).await;
        let header = String::from_utf8(header).unwrap();
        assert!(header.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(header.contains("X-Orb-Sat-Mux: 1-RTT-Ground-TLS\r\n"));
        let mut received = Vec::new();
        fetch.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, body);
        println!("Fetch gateway: encrypted/compressed response matches origin");
        println!("=== PUBLIC LIBRARY RELAY CHECKS PASSED ===");
    };
    tokio::select! {
        result = run_server(server) => panic!("server stopped: {result:?}"),
        result = run_client(client) => panic!("client stopped: {result:?}"),
        _ = serve_origin => unreachable!(),
        result = timeout(TEST_TIMEOUT, exercise) => result.expect("public relay round-trip timed out"),
    }
}

async fn read_header(stream: &mut TcpStream) -> Vec<u8> {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(stream.read_u8().await.unwrap());
        assert!(header.len() <= 65_536);
    }
    header
}
