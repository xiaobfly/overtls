//! Regression: audit finding SEC-18 (client TLS fingerprint deviates from a browser).
//!
//! Current behaviour (`src/tls.rs:31-38`): the client's `CHROME_CIPHERS` list contains exactly five
//! suites - TLS 1.3 AES256/AES128/CHACHA20 followed by two TLS 1.2 ECDHE-AES128 suites - and no
//! ALPN is configured anywhere, so the ClientHello carries no `0x0010` extension. The assertions
//! below describe that current behaviour; the `// post-fix:` comments name the expectation to flip
//! to once the fingerprint is either browser-like (ALPN `h2,http/1.1`, GREASE, full TLS 1.2 set) or
//! the misleading naming is dropped.

mod common;

use common::{client_config, free_port, spawn_role, work_dir, write_json};
use serde_json::json;
use std::{
    io::{ErrorKind, Read},
    net::TcpListener,
    time::{Duration, Instant},
};

/// The parsed pieces of a ClientHello the assertions care about.
struct ClientHello {
    cipher_suites: Vec<u16>,
    extensions: Vec<(u16, Vec<u8>)>,
}

/// Parse a `TLSPlaintext` record that carries a ClientHello, panicking with the raw bytes on any
/// structural problem (the record is captured from the wire, so every failure is a test bug).
fn parse_client_hello(record: &[u8]) -> ClientHello {
    assert!(record.len() >= 5, "no TLS record header in {:02x?}", record);
    assert_eq!(record[0], 0x16, "expected a handshake record (0x16), got 0x{:02x}", record[0]);
    let record_len = u16::from_be_bytes([record[3], record[4]]) as usize;
    assert!(
        record.len() >= 5 + record_len,
        "truncated TLS record: {} of {} bytes: {:02x?}",
        record.len(),
        5 + record_len,
        record
    );
    let handshake = &record[5..5 + record_len];
    assert_eq!(handshake[0], 0x01, "expected a ClientHello (0x01), got 0x{:02x}", handshake[0]);
    let handshake_len = u32::from_be_bytes([0, handshake[1], handshake[2], handshake[3]]) as usize;
    assert!(
        handshake.len() >= 4 + handshake_len,
        "truncated ClientHello: {} of {} bytes",
        handshake.len(),
        4 + handshake_len
    );
    let body = &handshake[4..4 + handshake_len];

    // legacy_version (2 bytes) + random (32 bytes) + session id (1 + len).
    assert!(body.len() > 34, "ClientHello without a session id");
    let mut pos = 34;
    let session_id_len = body[pos] as usize;
    pos += 1 + session_id_len;

    // cipher suites (2 byte total length + list) + compression methods (1 + len).
    assert!(body.len() >= pos + 3, "ClientHello without a cipher suite list");
    let suites_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    assert!(body.len() > pos + suites_len, "truncated cipher suite list");
    let cipher_suites = body[pos..pos + suites_len]
        .chunks_exact(2)
        .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    pos += suites_len;
    let compression_len = body[pos] as usize;
    pos += 1 + compression_len;

    // extensions (2 byte total length + repeated type/length/data).
    assert!(body.len() >= pos + 2, "ClientHello without an extension block");
    let extensions_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    assert!(body.len() >= pos + extensions_len, "truncated extension block");
    let end = pos + extensions_len;
    let mut extensions = Vec::new();
    while pos + 4 <= end {
        let extension_type = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let extension_len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        assert!(
            pos + extension_len <= end,
            "extension 0x{extension_type:04x} overruns the extension block"
        );
        extensions.push((extension_type, body[pos..pos + extension_len].to_vec()));
        pos += extension_len;
    }
    assert_eq!(pos, end, "trailing bytes inside the extension block");

    ClientHello { cipher_suites, extensions }
}

/// Accept connections until one sends data, then read until that first TLS record is complete.
///
/// The client opens a bare TCP connection for its startup config check (no bytes at all) before the
/// UDP tunnel loop starts the TLS connection, and it retries that connection about once per second.
fn capture_first_tls_record(listener: &TcpListener, timeout: Duration) -> Vec<u8> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let (mut stream, _peer) = match listener.accept() {
            Ok(pair) => pair,
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            Err(error) => panic!("accept failed: {error}"),
        };
        stream.set_read_timeout(Some(Duration::from_secs(2))).expect("set read timeout");

        let mut chunk = [0u8; 4096];
        let mut record = Vec::new();
        // Skip the config-check probe: it connects and closes without sending a single byte.
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => continue,
            Ok(n) => record.extend_from_slice(&chunk[..n]),
        }

        let record_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let remaining = if record.len() < 5 {
                5
            } else {
                5 + u16::from_be_bytes([record[3], record[4]]) as usize
            };
            if record.len() >= remaining || Instant::now() >= record_deadline {
                break;
            }
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => record.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
        if record.first() == Some(&0x16) {
            return record;
        }
    }
    Vec::new()
}

/// The ClientHello offers the five hard-coded suites, no ALPN, but an SNI extension (SEC-18).
#[test]
fn client_hello_no_alpn_five_ciphers() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake server");
    listener.set_nonblocking(true).expect("non-blocking listener");
    let fake_port = listener.local_addr().expect("listener addr").port();
    let client_port = free_port();
    let dir = work_dir("audit_tls_fingerprint");
    let value = client_config(
        fake_port,
        client_port,
        json!({}),
        json!({
            // The helper template is a plaintext test setup; SEC-18 needs the real TLS client path.
            "disable_tls": false,
            // A `cafile` that cannot be read is silently ignored (SEC-08): the trust decision does
            // not matter here, the ClientHello is sent before any certificate is verified.
            "cafile": dir.join("missing-ca.pem"),
            // rustls only sends SNI for DNS names, so the IP-literal default would omit it.
            "server_domain": "example.com",
        }),
    );
    let cfg = write_json(&dir, "client.json", &value);
    let mut client = spawn_role("client", &cfg, &["-v", "debug"], &dir);

    let record = capture_first_tls_record(&listener, Duration::from_secs(5));
    // post-fix: the ClientHello keeps being sent, so this guard stays true; the flip happens on the
    // parsed content asserted below.
    assert!(
        !record.is_empty(),
        "no TLS ClientHello reached the fake server within 5s\nclient log:\n{}",
        client.logs()
    );

    let hello = parse_client_hello(&record);
    let extension_types: Vec<u16> = hello.extensions.iter().map(|(kind, _)| *kind).collect();

    // Current behaviour: the wire list is the five `CHROME_CIPHERS` suites plus the renegotiation
    // SCSV (0x00ff) that rustls appends to every ClientHello.
    // post-fix: a browser-like list carries GREASE and the full TLS 1.2 set, so the tail assertion
    // and the entry count below must change.
    let scsv = 0x00ffu16;
    assert_eq!(
        hello.cipher_suites.last(),
        Some(&scsv),
        "current behaviour: rustls appends the renegotiation SCSV, got {:04x?}",
        hello.cipher_suites
    );
    let offered: Vec<u16> = hello.cipher_suites.iter().copied().filter(|suite| *suite != scsv).collect();
    // Current behaviour: `CHROME_CIPHERS` holds five entries (3x TLS 1.3 + 2x TLS 1.2 ECDHE-AES128).
    // post-fix: the count must change (GREASE + full TLS 1.2 set).
    assert_eq!(
        offered.len(),
        5,
        "current behaviour: five hard-coded suites (plus the SCSV), got {offered:04x?}\nclient log:\n{}",
        client.logs()
    );
    // Current behaviour: TLS 1.3 order is AES256 -> AES128 -> CHACHA20 (with GREASE in front of it
    // in a browser, so even the first entry differs).
    // post-fix: flip to the target fingerprint order (with GREASE, the expected prefix changes).
    assert_eq!(
        offered[..3],
        [0x1302, 0x1301, 0x1303][..],
        "current behaviour: fixed TLS 1.3 order, got {offered:04x?}"
    );
    // Current behaviour: the TLS 1.2 tail is only ECDHE-AES128 (ECDSA + RSA).
    // post-fix: a browser-like list also offers CHACHA20 and AES256 for TLS 1.2.
    assert_eq!(
        offered[3..],
        [0xc02b, 0xc02f][..],
        "current behaviour: two hard-coded TLS 1.2 suites, got {offered:04x?}"
    );
    // Current behaviour (SEC-18): no ALPN anywhere in the repository, so no 0x0010 extension.
    // post-fix: ALPN must be present and contain `h2`/`http/1.1`, so this must flip to an equality.
    assert!(
        !hello.extensions.iter().any(|(kind, _)| *kind == 0x0010),
        "current behaviour: no ALPN offered, extensions: {:04x?}",
        extension_types
    );
    // post-fix: SNI stays present; the flip happens on the ALPN/cipher assertions above.
    let sni = hello
        .extensions
        .iter()
        .find(|(kind, _)| *kind == 0x0000)
        .unwrap_or_else(|| panic!("the SNI extension must be present, extensions: {extension_types:04x?}"));
    // SNI payload: 2 byte list length + 1 byte name type + 2 byte name length + name.
    // post-fix: the SNI name stays `example.com`; the flip happens on the ALPN/cipher assertions.
    assert_eq!(
        sni.1.get(5..),
        Some(b"example.com".as_slice()),
        "SNI must carry server_domain, got {:02x?}",
        sni.1
    );

    // post-fix: stays true, the client keeps retrying while the handshake never completes.
    assert!(
        !client.exited(),
        "the client must stay alive while the fake server withholds the ServerHello:\n{}",
        client.logs()
    );
}
