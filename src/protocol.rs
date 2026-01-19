//! Protocol messages for TCP relay server communication
//!
//! The relay server uses JSON messages over TCP (newline-delimited)
//! 
//! Protocol flow:
//! 1. Client -> Server: register
//! 2. Server -> Client: registered
//! 3. Server -> Client: peer_info (when both peers connected)
//! 4. Client -> Server: ready (when prepared for hole punch)
//! 5. Server -> Client: go (synchronized start time)

use serde::{Deserialize, Serialize};
use crate::hole_punch::PeerAddress;

/// Client registration message to relay server
#[derive(Debug, Clone, Serialize)]
pub struct RegisterMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub session_id: String,
    pub role: String,
    pub local_port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prediction_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prediction_range_extra_pct: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_connections: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_ports: Option<Vec<u16>>,
}

impl RegisterMessage {
    pub fn new(
        session_id: &str,
        role: &str,
        local_port: u16,
        prediction_mode: Option<String>,
        prediction_range_extra_pct: Option<f64>,
        tcp_connections: Option<u8>,
        local_ports: Option<Vec<u16>>,
    ) -> Self {
        Self {
            msg_type: "register".to_string(),
            session_id: session_id.to_string(),
            role: role.to_string(),
            local_port,
            private_ip: get_private_ip(),
            prediction_mode,
            prediction_range_extra_pct,
            tcp_connections,
            local_ports,
        }
    }
}

/// Get private/local IP address for LAN detection
fn get_private_ip() -> Option<String> {
    // Try to get local IP by connecting to a public address (doesn't actually send data)
    use std::net::UdpSocket;
    
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0") {
        // Connect to Google DNS (doesn't send data, just sets up routing)
        if socket.connect("8.8.8.8:80").is_ok() {
            if let Ok(addr) = socket.local_addr() {
                return Some(addr.ip().to_string());
            }
        }
    }
    None
}

/// Ready message - sent when client is prepared for hole punch
#[derive(Debug, Clone, Serialize)]
pub struct ReadyMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
}

impl Default for ReadyMessage {
    fn default() -> Self {
        Self {
            msg_type: "ready".to_string(),
        }
    }
}

/// Keepalive message
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct KeepaliveMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
}

impl Default for KeepaliveMessage {
    fn default() -> Self {
        Self {
            msg_type: "keepalive".to_string(),
        }
    }
}

/// Punch result report
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct PunchResultMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub success: bool,
}

#[allow(dead_code)]
impl PunchResultMessage {
    pub fn new(success: bool) -> Self {
        Self {
            msg_type: "punch_result".to_string(),
            success,
        }
    }
}

/// Peer address info from server
#[derive(Debug, Clone, Deserialize)]
pub struct PeerAddressInfo {
    pub ip: String,
    pub port: u16,
    #[serde(rename = "type")]
    pub addr_type: String,
    #[allow(dead_code)]
    #[serde(default)]
    pub priority: Option<i32>,
    #[allow(dead_code)]
    #[serde(default)]
    pub confidence: Option<f64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PeerPortAnalysis {
    pub local_port: u16,
    #[serde(default)]
    pub nat_analysis: NATAnalysis,
}

/// NAT Analysis from server - Focus on PORT RANGE!
#[derive(Debug, Clone, Deserialize, Default)]
pub struct NATAnalysis {
    #[allow(dead_code)]
    #[serde(default)]
    pub probed_ports: Vec<u16>,
    #[allow(dead_code)]
    #[serde(default)]
    pub local_ports: Vec<u16>,
    
    // KEY METRICS
    #[allow(dead_code)]
    #[serde(default)]
    pub min_port: u16,
    #[allow(dead_code)]
    #[serde(default)]
    pub max_port: u16,
    #[serde(default)]
    pub port_range: u16,

    #[serde(default)]
    pub predicted_port: u16,
    #[serde(default)]
    pub error_range: u16,
    #[allow(dead_code)]
    #[serde(default)]
    pub delta_min: i32,
    #[allow(dead_code)]
    #[serde(default)]
    pub delta_max: i32,
    #[serde(default)]
    pub delta_median: f64,
    
    // Classification
    #[serde(default)]
    pub pattern_type: String,
    #[serde(default)]
    pub needs_scan: bool,
    #[serde(default)]
    pub scan_start: u16,
    #[serde(default)]
    pub scan_end: u16,
}

impl NATAnalysis {
    /// Get friendly description of NAT type
    pub fn description(&self) -> &'static str {
        match self.pattern_type.as_str() {
            "port_preserved" => "Port-preserving NAT (easy)",
            "constant_delta" => "Constant delta NAT (easy)",
            "small_delta_range" => "Small delta range NAT (should work)",
            "medium_delta_range" => "Medium delta range NAT (may work)",
            "large_delta_range" => "Large delta range NAT (difficult)",
            "random_like" => "Random-like NAT (very difficult)",
            "constant" => "Constant port NAT (easy)",
            "small_range" => "Small range NAT (should work)",
            "medium_range" => "Medium range NAT (may work)",
            "large_range" => "Large range NAT (difficult)",
            "random" => "Random NAT (very difficult)",
            "insufficient_data" => "Unknown (no probe data)",
            _ => "Unknown NAT type",
        }
    }
    
    /// Get number of ports to scan
    pub fn scan_count(&self) -> u32 {
        if self.needs_scan && self.scan_end >= self.scan_start {
            (self.scan_end - self.scan_start + 1) as u32
        } else {
            0
        }
    }
}

/// Probe message for NAT analysis
#[derive(Debug, Clone, Serialize)]
pub struct ProbeMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
    pub session_id: String,
    pub local_port: u16,
    pub probe_num: u32,
}

impl ProbeMessage {
    pub fn new(session_id: &str, local_port: u16, probe_num: u32) -> Self {
        Self {
            msg_type: "probe".to_string(),
            session_id: session_id.to_string(),
            local_port,
            probe_num,
        }
    }
}

/// Probes complete message
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize)]
pub struct ProbesCompleteMessage {
    #[serde(rename = "type")]
    pub msg_type: String,
}

impl Default for ProbesCompleteMessage {
    fn default() -> Self {
        Self {
            msg_type: "probes_complete".to_string(),
        }
    }
}

impl From<PeerAddressInfo> for PeerAddress {
    fn from(info: PeerAddressInfo) -> Self {
        PeerAddress {
            ip: info.ip,
            port: info.port,
            addr_type: info.addr_type,
        }
    }
}

/// Generic server message
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum RelayMessage {
    #[serde(rename = "registered")]
    Registered {
        your_public_addr: Vec<serde_json::Value>,
        your_role: String,
        session_id: String,
        #[serde(default)]
        server_time: Option<f64>,  // Server timestamp for clock sync
        #[serde(default)]
        #[allow(dead_code)]
        initial_delta: Option<i32>,  // NAT port delta
        #[serde(default)]
        #[allow(dead_code)]
        port_preserved: Option<bool>,  // Is port preserved?
        #[serde(default)]
        probe_port: Option<u16>,  // Port for NAT probing
        #[serde(default)]
        needs_probing: Option<bool>,  // Does this peer need NAT probing?
    },
    
    #[serde(rename = "peer_info")]
    PeerInfo {
        peer_public_addr: Vec<serde_json::Value>,
        peer_local_port: u16,
        peer_addresses: Vec<PeerAddressInfo>,
        #[allow(dead_code)]
        your_role: String,
        same_network: bool,
        #[serde(default)]
        peer_nat_analysis: Option<NATAnalysis>,
        #[serde(default)]
        peer_port_analyses: Option<Vec<PeerPortAnalysis>>,
    },
    
    #[serde(rename = "go")]
    Go {
        start_at: f64,
        #[serde(default)]
        message: String,
    },
    
    #[serde(rename = "ping")]
    Ping {},
    
    #[serde(rename = "keepalive_ack")]
    KeepaliveAck {},
    
    #[serde(rename = "error")]
    Error {
        message: String,
    },
}

impl RelayMessage {
    /// Parse peer address from JSON array [ip, port]
    pub fn parse_addr(addr: &[serde_json::Value]) -> Option<(String, u16)> {
        if addr.len() != 2 {
            return None;
        }
        let ip = addr[0].as_str()?.to_string();
        let port = addr[1].as_u64()? as u16;
        Some((ip, port))
    }
}

/// File transfer protocol messages (binary, over the direct TCP connection)
#[allow(dead_code)]
pub mod transfer {
    use bytes::{Buf, BufMut, Bytes, BytesMut};

    /// Message types for file transfer
    #[repr(u8)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum MessageType {
        Hello = 1,       // Initial handshake
        FileInfo = 2,    // File metadata
        FileInfoAck = 3, // Acknowledge file info
        Data = 4,        // File data chunk (reserved for future use)
        Done = 5,        // Transfer complete
        Ack = 6,         // Final acknowledgment
        Error = 7,       // Error message (reserved for future use)
        MultiHello = 8,      // Multi-conn handshake
        MultiPlan = 9,       // Multi-conn plan
        MultiPlanAck = 10,   // Multi-conn plan ack
        MultiReady = 11,     // Connection ready
        MultiStart = 12,     // Start transfer
        ChunkHeader = 13,    // Chunk header (offset-based)
        ChunkAck = 14,       // Chunk ack
        ChunkNack = 15,      // Chunk nack
        TransferDone = 16,   // Transfer done (multi)
        TransferDoneAck = 17,// Transfer done ack (multi)
    }

    impl MessageType {
        pub fn from_u8(v: u8) -> Option<Self> {
            match v {
                1 => Some(Self::Hello),
                2 => Some(Self::FileInfo),
                3 => Some(Self::FileInfoAck),
                4 => Some(Self::Data),
                5 => Some(Self::Done),
                6 => Some(Self::Ack),
                7 => Some(Self::Error),
                8 => Some(Self::MultiHello),
                9 => Some(Self::MultiPlan),
                10 => Some(Self::MultiPlanAck),
                11 => Some(Self::MultiReady),
                12 => Some(Self::MultiStart),
                13 => Some(Self::ChunkHeader),
                14 => Some(Self::ChunkAck),
                15 => Some(Self::ChunkNack),
                16 => Some(Self::TransferDone),
                17 => Some(Self::TransferDoneAck),
                _ => None,
            }
        }
    }

    /// Hello message for initial handshake after hole punch
    #[derive(Debug, Clone)]
    pub struct HelloMessage {
        pub role: String, // "sender" or "receiver"
    }

    impl HelloMessage {
        pub fn encode(&self) -> BytesMut {
            let role_bytes = self.role.as_bytes();
            let mut buf = BytesMut::with_capacity(5 + role_bytes.len());
            buf.put_u8(MessageType::Hello as u8);
            buf.put_u32(role_bytes.len() as u32);
            buf.put_slice(role_bytes);
            buf
        }

        pub fn decode(data: &[u8]) -> Option<Self> {
            if data.len() < 5 {
                return None;
            }
            let mut cursor = &data[1..];
            let len = cursor.get_u32() as usize;
            if data.len() < 5 + len {
                return None;
            }
            let role = String::from_utf8(data[5..5 + len].to_vec()).ok()?;
            Some(Self { role })
        }
    }


    /// Multi-connection hello message
    #[derive(Debug, Clone)]
    pub struct MultiHelloMessage {
        pub role: String,
        pub total_conns: u8,
        pub conn_id: u8,
    }

    impl MultiHelloMessage {
        pub fn encode(&self) -> BytesMut {
            let role_bytes = self.role.as_bytes();
            let mut buf = BytesMut::with_capacity(7 + role_bytes.len());
            buf.put_u8(MessageType::MultiHello as u8);
            buf.put_u8(self.total_conns);
            buf.put_u8(self.conn_id);
            buf.put_u32(role_bytes.len() as u32);
            buf.put_slice(role_bytes);
            buf
        }

        pub fn decode(data: &[u8]) -> Option<Self> {
            if data.len() < 7 {
                return None;
            }
            let total_conns = data[1];
            let conn_id = data[2];
            let mut cursor = &data[3..];
            let len = cursor.get_u32() as usize;
            if data.len() < 7 + len {
                return None;
            }
            let role = String::from_utf8(data[7..7 + len].to_vec()).ok()?;
            Some(Self {
                role,
                total_conns,
                conn_id,
            })
        }
    }

    /// Multi-connection plan message
    #[derive(Debug, Clone)]
    pub struct MultiPlanMessage {
        pub total_conns: u8,
        pub retry_limit: u8,
        pub start_at: f64,
        pub local_ports: Vec<u16>,
    }

    impl MultiPlanMessage {
        pub fn encode(&self) -> BytesMut {
            let mut buf = BytesMut::with_capacity(12 + (self.local_ports.len() * 2));
            buf.put_u8(MessageType::MultiPlan as u8);
            buf.put_u8(self.total_conns);
            buf.put_u8(self.retry_limit);
            buf.put_u64(self.start_at.to_bits());
            buf.put_u8(self.local_ports.len() as u8);
            for port in &self.local_ports {
                buf.put_u16(*port);
            }
            buf
        }

        pub fn decode(data: &[u8]) -> Option<Self> {
            if data.len() < 12 {
                return None;
            }
            let total_conns = data[1];
            let retry_limit = data[2];
            let mut cursor = &data[3..];
            let start_at = f64::from_bits(cursor.get_u64());
            let port_count = cursor.get_u8() as usize;
            if cursor.remaining() < port_count * 2 {
                return None;
            }
            let mut local_ports = Vec::with_capacity(port_count);
            for _ in 0..port_count {
                local_ports.push(cursor.get_u16());
            }
            Some(Self {
                total_conns,
                retry_limit,
                start_at,
                local_ports,
            })
        }
    }


    /// Multi-connection plan ack message
    #[derive(Debug, Clone)]
    pub struct MultiPlanAckMessage {
        pub total_conns: u8,
        pub local_ports: Vec<u16>,
    }

    impl MultiPlanAckMessage {
        pub fn encode(&self) -> BytesMut {
            let mut buf = BytesMut::with_capacity(3 + (self.local_ports.len() * 2));
            buf.put_u8(MessageType::MultiPlanAck as u8);
            buf.put_u8(self.total_conns);
            buf.put_u8(self.local_ports.len() as u8);
            for port in &self.local_ports {
                buf.put_u16(*port);
            }
            buf
        }

        pub fn decode(data: &[u8]) -> Option<Self> {
            if data.len() < 3 {
                return None;
            }
            let total_conns = data[1];
            let port_count = data[2] as usize;
            if data.len() < 3 + (port_count * 2) {
                return None;
            }
            let mut cursor = &data[3..];
            let mut local_ports = Vec::with_capacity(port_count);
            for _ in 0..port_count {
                local_ports.push(cursor.get_u16());
            }
            Some(Self {
                total_conns,
                local_ports,
            })
        }
    }

    /// Multi-connection ready message
    #[derive(Debug, Clone)]
    pub struct MultiReadyMessage {
        pub conn_id: u8,
    }

    impl MultiReadyMessage {
        pub fn encode(&self) -> BytesMut {
            let mut buf = BytesMut::with_capacity(2);
            buf.put_u8(MessageType::MultiReady as u8);
            buf.put_u8(self.conn_id);
            buf
        }

        pub fn decode(data: &[u8]) -> Option<Self> {
            if data.len() < 2 {
                return None;
            }
            Some(Self { conn_id: data[1] })
        }
    }

    /// Chunk header message
    #[derive(Debug, Clone)]
    pub struct ChunkHeaderMessage {
        pub chunk_id: u32,
        pub offset: u64,
        pub len: u32,
        pub hash32: u32,
    }

    impl ChunkHeaderMessage {
        pub fn encode(&self) -> BytesMut {
            let mut buf = BytesMut::with_capacity(21);
            buf.put_u8(MessageType::ChunkHeader as u8);
            buf.put_u32(self.chunk_id);
            buf.put_u64(self.offset);
            buf.put_u32(self.len);
            buf.put_u32(self.hash32);
            buf
        }

        pub fn decode(data: &[u8]) -> Option<Self> {
            if data.len() < 21 {
                return None;
            }
            let mut cursor = &data[1..];
            let chunk_id = cursor.get_u32();
            let offset = cursor.get_u64();
            let len = cursor.get_u32();
            let hash32 = cursor.get_u32();
            Some(Self {
                chunk_id,
                offset,
                len,
                hash32,
            })
        }
    }

    /// Chunk ack/nack message
    #[derive(Debug, Clone)]
    pub struct ChunkAckMessage {
        pub chunk_id: u32,
        pub is_nack: bool,
    }

    impl ChunkAckMessage {
        pub fn encode(&self) -> BytesMut {
            let mut buf = BytesMut::with_capacity(5);
            let msg_type = if self.is_nack {
                MessageType::ChunkNack
            } else {
                MessageType::ChunkAck
            };
            buf.put_u8(msg_type as u8);
            buf.put_u32(self.chunk_id);
            buf
        }

        pub fn decode(data: &[u8]) -> Option<Self> {
            if data.len() < 5 {
                return None;
            }
            let msg_type = MessageType::from_u8(data[0])?;
            if msg_type != MessageType::ChunkAck && msg_type != MessageType::ChunkNack {
                return None;
            }
            let mut cursor = &data[1..];
            let chunk_id = cursor.get_u32();
            Some(Self {
                chunk_id,
                is_nack: msg_type == MessageType::ChunkNack,
            })
        }
    }

    /// File info message
    #[derive(Debug, Clone)]
    pub struct FileInfoMessage {
        pub filename: String,
        pub file_size: u64,
        pub sha256: [u8; 32],
    }

    impl FileInfoMessage {
        /// Encode: type(1) + name_len(4) + size(8) + name(n) + sha256(32)
        pub fn encode(&self) -> BytesMut {
            let name_bytes = self.filename.as_bytes();
            let mut buf = BytesMut::with_capacity(1 + 4 + 8 + name_bytes.len() + 32);
            buf.put_u8(MessageType::FileInfo as u8);
            buf.put_u32(name_bytes.len() as u32);
            buf.put_u64(self.file_size);
            buf.put_slice(name_bytes);
            buf.put_slice(&self.sha256);
            buf
        }

        pub fn decode(data: &[u8]) -> Option<Self> {
            if data.len() < 13 {
                return None;
            }
            let mut cursor = &data[1..];
            let name_len = cursor.get_u32() as usize;
            let file_size = cursor.get_u64();
            
            if data.len() < 13 + name_len + 32 {
                return None;
            }
            
            let filename = String::from_utf8(data[13..13 + name_len].to_vec()).ok()?;
            let mut sha256 = [0u8; 32];
            sha256.copy_from_slice(&data[13 + name_len..13 + name_len + 32]);
            
            Some(Self {
                filename,
                file_size,
                sha256,
            })
        }
    }

    /// Simple acknowledgment messages
    pub fn encode_simple(msg_type: MessageType) -> Bytes {
        Bytes::from(vec![msg_type as u8])
    }

    /// Parse message type from first byte
    pub fn parse_type(data: &[u8]) -> Option<MessageType> {
        if data.is_empty() {
            return None;
        }
        MessageType::from_u8(data[0])
    }
}
