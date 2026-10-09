//! A minimal WebSocket client used to drive the overtls server tunnel protocol directly.
//!
//! Only `std`: handshake by hand, masked client frames, 7/16/64 bit length encoding.
#![allow(dead_code)]

use std::{
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    time::{Duration, Instant},
};
use uuid::Uuid;

use super::{b64, socks5_addr_v4};

pub const OPCODE_CONTINUATION: u8 = 0x0;
pub const OPCODE_TEXT: u8 = 0x1;
pub const OPCODE_BINARY: u8 = 0x2;
pub const OPCODE_CLOSE: u8 = 0x8;
pub const OPCODE_PING: u8 = 0x9;
pub const OPCODE_PONG: u8 = 0xA;

/// Handshake parameters understood by the overtls server.
pub struct Handshake {
    pub path: String,
    pub host: String,
    pub udp_tunnel: bool,
    pub client_id: Option<Uuid>,
    pub target_address: Option<SocketAddr>,
}

impl Handshake {
    /// Handshake for `path` with only the mandatory WebSocket headers.
    pub fn new(path: &str, host: &str) -> Self {
        Self {
            path: path.to_string(),
            host: host.to_string(),
            udp_tunnel: false,
            client_id: None,
            target_address: None,
        }
    }

    /// Raw HTTP upgrade request.
    pub fn request(&self) -> Vec<u8> {
        let mut request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {}\r\n",
            self.path,
            self.host,
            b64(b"overtls-test-key")
        );
        if self.udp_tunnel {
            request.push_str("UDP-Tunnel: true\r\n");
        }
        if let Some(client_id) = &self.client_id {
            request.push_str(&format!("Client-Id: {client_id}\r\n"));
        }
        if let Some(target) = &self.target_address {
            request.push_str(&format!("Target-Address: {}\r\n", b64(&socks5_addr_v4(*target))));
        }
        request.push_str("\r\n");
        request.into_bytes()
    }
}

/// A connected WebSocket client.
pub struct Ws {
    stream: TcpStream,
    buffer: Vec<u8>,
    closed: bool,
}

impl Ws {
    /// Connect and perform the upgrade handshake; returns the raw response header block.
    ///
    /// The response is deliberately *not* validated: several audit regressions assert what happens
    /// when the peer answers something other than `101`.
    pub fn connect(addr: SocketAddr, handshake: &Handshake) -> std::io::Result<(Ws, String)> {
        let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        stream.write_all(&handshake.request())?;
        let mut raw = Vec::new();
        let mut chunk = [0u8; 1024];
        while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => raw.extend_from_slice(&chunk[..n]),
                Err(e) => return Err(e),
            }
        }
        let split = raw.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4);
        let (header, rest) = match split {
            Some(split) => (raw[..split].to_vec(), raw[split..].to_vec()),
            None => (raw, Vec::new()),
        };
        stream.set_read_timeout(None)?;
        Ok((
            Ws {
                stream,
                buffer: rest,
                closed: false,
            },
            String::from_utf8_lossy(&header).to_string(),
        ))
    }

    /// The first line of the handshake response, e.g. `HTTP/1.1 101 Switching Protocols`.
    pub fn status_line(header: &str) -> String {
        header.lines().next().unwrap_or_default().trim().to_string()
    }

    /// Send a text frame.
    pub fn send_text(&mut self, text: &str) -> std::io::Result<()> {
        self.send_frame(OPCODE_TEXT, text.as_bytes())
    }

    /// Send a binary frame.
    pub fn send_binary(&mut self, payload: &[u8]) -> std::io::Result<()> {
        self.send_frame(OPCODE_BINARY, payload)
    }

    /// Send a masked close frame with a status code.
    pub fn send_close(&mut self, code: u16) -> std::io::Result<()> {
        self.send_frame(OPCODE_CLOSE, &code.to_be_bytes())
    }

    /// Send a ping frame.
    pub fn send_ping(&mut self, payload: &[u8]) -> std::io::Result<()> {
        self.send_frame(OPCODE_PING, payload)
    }

    /// Send one masked frame.
    pub fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> std::io::Result<()> {
        let mut frame = vec![0x80 | (opcode & 0x0f)];
        let mask_bit = 0x80u8;
        let len = payload.len();
        if len < 126 {
            frame.push(mask_bit | len as u8);
        } else if len <= u16::MAX as usize {
            frame.push(mask_bit | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(mask_bit | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        let key = [0x21u8, 0x43, 0x65, 0x87];
        frame.extend_from_slice(&key);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ key[i % 4]));
        self.stream.write_all(&frame)
    }

    /// Wait for the next frame; `None` on timeout, EOF or protocol error.
    pub fn recv_frame(&mut self, d: Duration) -> Option<(u8, Vec<u8>)> {
        let deadline = Instant::now() + d;
        loop {
            if let Some(frame) = self.take_frame() {
                return Some(frame);
            }
            if self.closed {
                return None;
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            if !self.fill(deadline - now) {
                return None;
            }
        }
    }

    /// Read the next frame, ignoring pings.
    pub fn recv_data_frame(&mut self, d: Duration) -> Option<(u8, Vec<u8>)> {
        loop {
            let (opcode, payload) = self.recv_frame(d)?;
            if opcode != OPCODE_PING && opcode != OPCODE_PONG {
                return Some((opcode, payload));
            }
        }
    }

    /// Read everything until EOF/timeout, including bytes already buffered.
    pub fn read_until_eof(&mut self, d: Duration) -> Vec<u8> {
        let deadline = Instant::now() + d;
        while !self.closed {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            if !self.fill(deadline - now) {
                break;
            }
        }
        std::mem::take(&mut self.buffer)
    }

    /// Close the underlying socket.
    pub fn shutdown(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }

    /// Whether the peer closed the connection (EOF or a hard read error).
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    fn fill(&mut self, timeout: Duration) -> bool {
        if self.closed {
            return false;
        }
        if self.stream.set_read_timeout(Some(timeout.max(Duration::from_millis(50)))).is_err() {
            return false;
        }
        let mut chunk = [0u8; 8192];
        match self.stream.read(&mut chunk) {
            Ok(0) => {
                self.closed = true;
                false
            }
            Ok(n) => {
                self.buffer.extend_from_slice(&chunk[..n]);
                true
            }
            // A read timeout is not a close; a hard error (e.g. connection reset) is.
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => false,
            Err(_) => {
                self.closed = true;
                false
            }
        }
    }

    fn take_frame(&mut self) -> Option<(u8, Vec<u8>)> {
        if self.buffer.len() < 2 {
            return None;
        }
        let opcode = self.buffer[0] & 0x0f;
        let masked = self.buffer[1] & 0x80 != 0;
        let len_byte = self.buffer[1] & 0x7f;
        let mut offset = 2;
        let len = match len_byte {
            126 => {
                if self.buffer.len() < offset + 2 {
                    return None;
                }
                let len = u16::from_be_bytes([self.buffer[offset], self.buffer[offset + 1]]) as usize;
                offset += 2;
                len
            }
            127 => {
                if self.buffer.len() < offset + 8 {
                    return None;
                }
                let mut raw = [0u8; 8];
                raw.copy_from_slice(&self.buffer[offset..offset + 8]);
                offset += 8;
                u64::from_be_bytes(raw) as usize
            }
            len => len as usize,
        };
        let mut mask = [0u8; 4];
        if masked {
            if self.buffer.len() < offset + 4 {
                return None;
            }
            mask.copy_from_slice(&self.buffer[offset..offset + 4]);
            offset += 4;
        }
        if self.buffer.len() < offset + len {
            return None;
        }
        let mut payload = self.buffer[offset..offset + len].to_vec();
        if masked {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[i % 4];
            }
        }
        self.buffer.drain(..offset + len);
        Some((opcode, payload))
    }
}
