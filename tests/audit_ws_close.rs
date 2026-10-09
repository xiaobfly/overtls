//! Regression: audit finding COR-09 (WS close handshake never completed).
//!
//! Current behaviour (measured, `p6_ws_close.py`): the server takes its `Message::Close` branch
//! (`src/server.rs:503-506`), logs `incoming connection closed normally`, drops the session and
//! closes the TCP connection *without* sending a Close frame back - RFC 6455 §5.5.1 is not
//! satisfied (`src/client.rs:454-457` behaves the same way on the other side).
//!
//! Every assertion below describes that current behaviour; the `// post-fix:` comments name the
//! expectation to flip to when COR-09 is fixed.

mod common;

use common::{free_port, poll_until, server_config, start_server, ws};
use serde_json::json;
use std::{net::SocketAddr, time::Duration};

/// A masked Close(1000) is answered with silence and a FIN: no Close frame is echoed (COR-09).
#[test]
fn close_frame_not_echoed() {
    let port = free_port();
    let value = server_config(port, None, json!({}), json!({}));
    let (_dir, mut server) = start_server("audit_ws_close", &value, port, "debug");
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    let (mut ws, header) = ws::Ws::connect(addr, &ws::Handshake::new("/t/", "127.0.0.1")).expect("ws handshake");
    // post-fix: the upgrade itself is unchanged by the fix, only the Close reply is.
    assert!(
        ws::Ws::status_line(&header).contains("101"),
        "the tunnel must upgrade first, got: {header:?}"
    );

    ws.send_close(1000).expect("send masked close frame");

    // Current behaviour: the server sends nothing back before closing.
    // post-fix: `recv_frame` must return `Some((ws::OPCODE_CLOSE, vec![0x03, 0xE8]))` (the echoed
    // Close frame with code 1000), so this assertion has to be flipped into an equality check.
    let frame = ws.recv_frame(Duration::from_secs(1));
    assert!(
        frame.is_none(),
        "no reply to Close is the current behaviour, got: {frame:?}\nserver log:\n{}",
        server.logs()
    );

    // `recv_frame` returns `None` on a read timeout as well, so `is_closed` proves that the peer
    // actually sent EOF within the 1s budget instead of the test just timing out.
    // post-fix: this stays true (the fix adds a Close frame, it does not keep the connection open).
    assert!(
        ws.is_closed(),
        "the server must close the connection within 1s after the Close frame\nserver log:\n{}",
        server.logs()
    );

    // Current behaviour: zero bytes follow the Close frame (the audit observed 0 bytes + FIN).
    // post-fix: exactly the 4 bytes of the echoed Close frame are read here (2 bytes header + 2
    // bytes status code, unmasked), so this becomes a length/payload assertion.
    let tail = ws.read_until_eof(Duration::from_millis(500));
    assert!(
        tail.is_empty(),
        "nothing follows the Close frame, got {:02x?}\nserver log:\n{}",
        tail,
        server.logs()
    );

    // post-fix: the fix keeps this branch (it sends Close and then leaves), so the line stays.
    assert!(
        poll_until(Duration::from_secs(5), || server
            .logs()
            .contains("incoming connection closed normally")),
        "the server must have handled the frame in its Message::Close branch:\n{}",
        server.logs()
    );
    // post-fix: stays true - only the missing Close frame changes.
    assert!(!server.exited(), "the server must survive the closed session:\n{}", server.logs());
}
