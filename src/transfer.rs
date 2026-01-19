//! TCP File Transfer Implementation - Optimized HIGH-THROUGHPUT
//!
//! Optimizations:
//! - CHUNK_SIZE: 8MB (configurable via --chunk) - fewer syscalls
//! - BUFFER_SIZE: 16MB for efficient I/O
//! - TCP Socket buffers: 64MB send/recv (OS may cap lower)
//! - Pipeline Depth: 16 chunks (~128MB in flight)
//! - Hybrid progress: every 10MB OR every 2 seconds
//! - SHA256 only at the end (from disk)
//! - CRC32 per chunk during transfer with ACK/NACK
//! - Pipelined I/O - Disk reads and network writes run in parallel!

use std::collections::VecDeque;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, Notify};
use bytes::Buf;
use crc32fast::Hasher;
use sha2::{Sha256, Digest};
use indicatif::{ProgressBar, ProgressStyle};
use anyhow::{Result, anyhow};
use tracing::{info, warn, error, debug};
use socket2::Socket;

use crate::protocol::transfer::*;

/// Default chunk size for reading/writing (8MB) - fewer syscalls
/// Can be overridden via --chunk flag
pub const DEFAULT_CHUNK_SIZE: usize = 8 * 1024 * 1024;

/// Buffer size for file I/O (16MB)  
const BUFFER_SIZE: usize = 16 * 1024 * 1024;

/// TCP socket buffer size (64MB each for send/recv)
/// Note: OS may cap this lower - we'll log actual values
const TCP_BUFFER_SIZE: usize = 64 * 1024 * 1024;

/// Pipeline depth for async I/O (16 chunks = ~128MB in flight at 8MB chunks)
const PIPELINE_DEPTH: usize = 16;

/// Progress update interval in bytes (10MB)
const PROGRESS_BYTE_INTERVAL: u64 = 10 * 1024 * 1024;

/// Progress update interval in time (2 seconds)
const PROGRESS_TIME_INTERVAL: Duration = Duration::from_secs(2);

/// Timeout for individual read/write operations
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Protocol timeout for handshake
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Max bad chunks allowed per connection before closing
const MAX_BAD_CHUNKS_PER_CONN: u32 = 5;

/// Good chunks needed before reducing bad chunk count
const BAD_CHUNKS_DECAY_STREAK: u32 = 2;

/// Global chunk size (set from main.rs)
static mut CHUNK_SIZE: usize = DEFAULT_CHUNK_SIZE;

/// Set the chunk size (called from main.rs)
pub fn set_chunk_size(size: usize) {
    unsafe {
        CHUNK_SIZE = size;
    }
}

/// Get the current chunk size
fn get_chunk_size() -> usize {
    unsafe { CHUNK_SIZE }
}

/// Configure TCP socket for optimal performance
fn configure_tcp_socket(stream: &TcpStream) -> Result<()> {
    let std_stream = stream.as_ref();
    std_stream.set_nodelay(true)?;
    
    // Set large TCP buffers for high throughput
    #[cfg(unix)]
    {
        use std::os::unix::io::{AsRawFd, FromRawFd};
        let fd = std_stream.as_raw_fd();
        let socket = unsafe { Socket::from_raw_fd(fd) };
        
        // Request large buffers
        let _ = socket.set_send_buffer_size(TCP_BUFFER_SIZE);
        let _ = socket.set_recv_buffer_size(TCP_BUFFER_SIZE);
        
        // Log actual buffer sizes (OS may cap lower)
        let actual_send = socket.send_buffer_size().unwrap_or(0);
        let actual_recv = socket.recv_buffer_size().unwrap_or(0);
        info!("TCP buffers: send={}MB recv={}MB (requested {}MB)", 
            actual_send / (1024 * 1024),
            actual_recv / (1024 * 1024),
            TCP_BUFFER_SIZE / (1024 * 1024));
        
        std::mem::forget(socket);
    }
    
    #[cfg(windows)]
    {
        use std::os::windows::io::{AsRawSocket, FromRawSocket};
        let raw = std_stream.as_raw_socket();
        let socket = unsafe { Socket::from_raw_socket(raw) };
        
        // Request large buffers
        let _ = socket.set_send_buffer_size(TCP_BUFFER_SIZE);
        let _ = socket.set_recv_buffer_size(TCP_BUFFER_SIZE);
        
        // Log actual buffer sizes (OS may cap lower)
        let actual_send = socket.send_buffer_size().unwrap_or(0);
        let actual_recv = socket.recv_buffer_size().unwrap_or(0);
        info!("TCP buffers: send={}MB recv={}MB (requested {}MB)", 
            actual_send / (1024 * 1024),
            actual_recv / (1024 * 1024),
            TCP_BUFFER_SIZE / (1024 * 1024));
        
        std::mem::forget(socket);
    }
    
    debug!("TCP_NODELAY enabled");
    Ok(())
}

/// Create a progress bar for file transfer
fn create_progress_bar(total_bytes: u64, filename: &str) -> ProgressBar {
    let pb = ProgressBar::new(total_bytes);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}) {msg}")
        .unwrap()
        .progress_chars("=>-"));
    pb.set_message(filename.to_string());
    pb
}

/// Progress tracker with hybrid (bytes OR time) updates
struct ProgressTracker {
    bar: ProgressBar,
    last_update_bytes: u64,
    last_update_time: Instant,
}

impl ProgressTracker {
    fn new(total_bytes: u64, filename: &str) -> Self {
        Self {
            bar: create_progress_bar(total_bytes, filename),
            last_update_bytes: 0,
            last_update_time: Instant::now(),
        }
    }
    
    fn update(&mut self, current_bytes: u64) {
        let bytes_since_update = current_bytes - self.last_update_bytes;
        let time_since_update = self.last_update_time.elapsed();
        
        if bytes_since_update >= PROGRESS_BYTE_INTERVAL || time_since_update >= PROGRESS_TIME_INTERVAL {
            self.bar.set_position(current_bytes);
            self.last_update_bytes = current_bytes;
            self.last_update_time = Instant::now();
        }
    }
    
    fn set_position(&self, pos: u64) {
        self.bar.set_position(pos);
    }
    
    fn finish_with_message(&self, msg: String) {
        self.bar.finish_with_message(msg);
    }
    
    fn set_message(&self, msg: &str) {
        self.bar.set_message(msg.to_string());
    }
}

/// Calculate SHA256 hash of a file
pub async fn calculate_sha256(file_path: &str) -> Result<([u8; 32], u64)> {
    let path = Path::new(file_path);
    let file_size = tokio::fs::metadata(path).await?.len();
    let hash = sha256_file(path).await?;
    Ok((hash, file_size))
}

/// Calculate SHA256 hash of a file (internal)
async fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    let mut file = File::open(path).await?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; get_chunk_size()];
    
    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    Ok(hash)
}

/// Format hash as hex string
pub fn sha256_to_hex(hash: &[u8; 32]) -> String {
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Read exactly n bytes with timeout
async fn read_exact_timeout(stream: &mut TcpStream, buf: &mut [u8], timeout: Duration) -> Result<()> {
    match tokio::time::timeout(timeout, stream.read_exact(buf)).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(anyhow!("Read error: {}", e)),
        Err(_) => Err(anyhow!("Read timeout")),
    }
}

/// Write all bytes with timeout
async fn write_all_timeout(stream: &mut TcpStream, buf: &[u8], timeout: Duration) -> Result<()> {
    match tokio::time::timeout(timeout, stream.write_all(buf)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(anyhow!("Write error: {}", e)),
        Err(_) => Err(anyhow!("Write timeout")),
    }
}


/// Multi-connection plan info received from peer
pub struct MultiPlanInfo {
    pub retry_limit: u8,
    pub start_at: f64,
    pub peer_local_ports: Vec<u16>,
}

async fn read_multi_hello_message(stream: &mut TcpStream) -> Result<MultiHelloMessage> {
    let mut header = [0u8; 7];
    read_exact_timeout(stream, &mut header, HANDSHAKE_TIMEOUT).await?;
    if header[0] != MessageType::MultiHello as u8 {
        return Err(anyhow!("Expected MULTI_HELLO, got type {}", header[0]));
    }
    let len = (&header[3..7]).get_u32() as usize;
    let mut role_buf = vec![0u8; len];
    read_exact_timeout(stream, &mut role_buf, HANDSHAKE_TIMEOUT).await?;

    let mut data = Vec::with_capacity(7 + len);
    data.extend_from_slice(&header);
    data.extend_from_slice(&role_buf);

    MultiHelloMessage::decode(&data).ok_or_else(|| anyhow!("Failed to parse MULTI_HELLO"))
}

async fn read_multi_plan_message(stream: &mut TcpStream) -> Result<MultiPlanMessage> {
    let mut header = [0u8; 12];
    read_exact_timeout(stream, &mut header, HANDSHAKE_TIMEOUT).await?;
    if header[0] != MessageType::MultiPlan as u8 {
        return Err(anyhow!("Expected MULTI_PLAN, got type {}", header[0]));
    }
    let port_count = header[11] as usize;
    let mut ports = vec![0u8; port_count * 2];
    read_exact_timeout(stream, &mut ports, HANDSHAKE_TIMEOUT).await?;

    let mut data = Vec::with_capacity(12 + ports.len());
    data.extend_from_slice(&header);
    data.extend_from_slice(&ports);

    MultiPlanMessage::decode(&data).ok_or_else(|| anyhow!("Failed to parse MULTI_PLAN"))
}

async fn read_multi_plan_ack_message(stream: &mut TcpStream) -> Result<MultiPlanAckMessage> {
    let mut header = [0u8; 3];
    read_exact_timeout(stream, &mut header, HANDSHAKE_TIMEOUT).await?;
    if header[0] != MessageType::MultiPlanAck as u8 {
        return Err(anyhow!("Expected MULTI_PLAN_ACK, got type {}", header[0]));
    }
    let port_count = header[2] as usize;
    let mut ports = vec![0u8; port_count * 2];
    read_exact_timeout(stream, &mut ports, HANDSHAKE_TIMEOUT).await?;

    let mut data = Vec::with_capacity(3 + ports.len());
    data.extend_from_slice(&header);
    data.extend_from_slice(&ports);

    MultiPlanAckMessage::decode(&data).ok_or_else(|| anyhow!("Failed to parse MULTI_PLAN_ACK"))
}

async fn read_multi_ready_message(stream: &mut TcpStream) -> Result<MultiReadyMessage> {
    let mut buf = [0u8; 2];
    read_exact_timeout(stream, &mut buf, HANDSHAKE_TIMEOUT).await?;
    if buf[0] != MessageType::MultiReady as u8 {
        return Err(anyhow!("Expected MULTI_READY, got type {}", buf[0]));
    }
    MultiReadyMessage::decode(&buf).ok_or_else(|| anyhow!("Failed to parse MULTI_READY"))
}

pub async fn multi_hello_sender(
    stream: &mut TcpStream,
    total_conns: u8,
    conn_id: u8,
) -> Result<()> {
    configure_tcp_socket(stream)?;

    let hello = MultiHelloMessage {
        role: "sender".to_string(),
        total_conns,
        conn_id,
    };
    write_all_timeout(stream, &hello.encode(), HANDSHAKE_TIMEOUT).await?;

    let peer = read_multi_hello_message(stream).await?;
    if peer.role != "receiver" {
        return Err(anyhow!("Expected receiver, got {}", peer.role));
    }
    if peer.conn_id != conn_id || peer.total_conns != total_conns {
        return Err(anyhow!("Unexpected MULTI_HELLO values"));
    }

    Ok(())
}

pub async fn multi_hello_receiver(
    stream: &mut TcpStream,
    total_conns: u8,
    conn_id: u8,
) -> Result<()> {
    configure_tcp_socket(stream)?;

    let peer = read_multi_hello_message(stream).await?;
    if peer.role != "sender" {
        return Err(anyhow!("Expected sender, got {}", peer.role));
    }
    if peer.conn_id != conn_id || peer.total_conns != total_conns {
        return Err(anyhow!("Unexpected MULTI_HELLO values"));
    }

    let hello = MultiHelloMessage {
        role: "receiver".to_string(),
        total_conns,
        conn_id,
    };
    write_all_timeout(stream, &hello.encode(), HANDSHAKE_TIMEOUT).await?;

    Ok(())
}

pub async fn multi_handshake_sender(
    stream: &mut TcpStream,
    total_conns: u8,
    retry_limit: u8,
    start_at: f64,
    local_ports: &[u16],
) -> Result<Vec<u16>> {
    if local_ports.len() != total_conns as usize {
        return Err(anyhow!("Local ports count does not match total_conns"));
    }

    multi_hello_sender(stream, total_conns, 0).await?;

    let plan = MultiPlanMessage {
        total_conns,
        retry_limit,
        start_at,
        local_ports: local_ports.to_vec(),
    };
    write_all_timeout(stream, &plan.encode(), HANDSHAKE_TIMEOUT).await?;

    let ack = read_multi_plan_ack_message(stream).await?;
    if ack.total_conns != total_conns {
        return Err(anyhow!("MULTI_PLAN_ACK total_conns mismatch"));
    }
    if ack.local_ports.len() != total_conns as usize {
        return Err(anyhow!("MULTI_PLAN_ACK local_ports mismatch"));
    }

    Ok(ack.local_ports)
}

pub async fn multi_handshake_receiver(
    stream: &mut TcpStream,
    total_conns: u8,
    local_ports: &[u16],
) -> Result<MultiPlanInfo> {
    if local_ports.len() != total_conns as usize {
        return Err(anyhow!("Local ports count does not match total_conns"));
    }

    multi_hello_receiver(stream, total_conns, 0).await?;

    let plan = read_multi_plan_message(stream).await?;
    if plan.total_conns != total_conns {
        return Err(anyhow!("MULTI_PLAN total_conns mismatch"));
    }
    if plan.local_ports.len() != total_conns as usize {
        return Err(anyhow!("MULTI_PLAN local_ports mismatch"));
    }

    let ack = MultiPlanAckMessage {
        total_conns,
        local_ports: local_ports.to_vec(),
    };
    write_all_timeout(stream, &ack.encode(), HANDSHAKE_TIMEOUT).await?;

    Ok(MultiPlanInfo {
        retry_limit: plan.retry_limit,
        start_at: plan.start_at,
        peer_local_ports: plan.local_ports,
    })
}

pub async fn send_multi_ready(stream: &mut TcpStream, conn_id: u8) -> Result<()> {
    let msg = MultiReadyMessage { conn_id };
    write_all_timeout(stream, &msg.encode(), HANDSHAKE_TIMEOUT).await
}

pub async fn read_multi_ready(stream: &mut TcpStream) -> Result<u8> {
    let msg = read_multi_ready_message(stream).await?;
    Ok(msg.conn_id)
}

pub async fn send_multi_start(stream: &mut TcpStream) -> Result<()> {
    let msg = encode_simple(MessageType::MultiStart);
    write_all_timeout(stream, &msg, HANDSHAKE_TIMEOUT).await
}

pub async fn read_multi_start(stream: &mut TcpStream) -> Result<()> {
    let mut buf = [0u8; 1];
    read_exact_timeout(stream, &mut buf, HANDSHAKE_TIMEOUT).await?;
    if buf[0] != MessageType::MultiStart as u8 {
        return Err(anyhow!("Expected MULTI_START, got type {}", buf[0]));
    }
    Ok(())
}

async fn read_chunk_ack_message(stream: &mut TcpStream) -> Result<ChunkAckMessage> {
    let mut buf = [0u8; 5];
    read_exact_timeout(stream, &mut buf, IO_TIMEOUT).await?;
    ChunkAckMessage::decode(&buf).ok_or_else(|| anyhow!("Failed to parse CHUNK_ACK"))
}

/// File sender over TCP
pub struct TcpSender {
    stream: TcpStream,
    file_path: String,
    file_size: u64,
    sha256: [u8; 32],
}

impl TcpSender {
    /// Create a sender with pre-calculated hash
    pub fn new_with_hash(stream: TcpStream, file_path: &str, file_size: u64, sha256: [u8; 32]) -> Self {
        Self {
            stream,
            file_path: file_path.to_string(),
            file_size,
            sha256,
        }
    }

    async fn handshake(&mut self) -> Result<()> {
        info!("Performing sender handshake...");
        configure_tcp_socket(&self.stream)?;
        
        let hello = HelloMessage { role: "sender".to_string() };
        write_all_timeout(&mut self.stream, &hello.encode(), HANDSHAKE_TIMEOUT).await?;
        debug!("Sent HELLO");
        
        let mut buf = [0u8; 256];
        read_exact_timeout(&mut self.stream, &mut buf[..5], HANDSHAKE_TIMEOUT).await?;
        
        if buf[0] != MessageType::Hello as u8 {
            return Err(anyhow!("Expected HELLO, got type {}", buf[0]));
        }
        
        let len = (&buf[1..5]).get_u32() as usize;
        read_exact_timeout(&mut self.stream, &mut buf[5..5+len], HANDSHAKE_TIMEOUT).await?;
        
        if let Some(hello) = HelloMessage::decode(&buf[..5+len]) {
            if hello.role != "receiver" {
                return Err(anyhow!("Expected receiver, got {}", hello.role));
            }
            info!("Received HELLO from receiver");
        } else {
            return Err(anyhow!("Failed to parse HELLO"));
        }
        
        Ok(())
    }

    async fn send_file_info(&mut self) -> Result<()> {
        let filename = Path::new(&self.file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();
        
        let file_info = FileInfoMessage {
            filename: filename.clone(),
            file_size: self.file_size,
            sha256: self.sha256,
        };
        
        info!("Sending file info: {} ({:.2} MB)", filename, self.file_size as f64 / (1024.0 * 1024.0));
        info!("Chunk size: {} KB", get_chunk_size() / 1024);
        
        write_all_timeout(&mut self.stream, &file_info.encode(), HANDSHAKE_TIMEOUT).await?;
        
        let mut buf = [0u8; 1];
        read_exact_timeout(&mut self.stream, &mut buf, HANDSHAKE_TIMEOUT).await?;
        
        if buf[0] != MessageType::FileInfoAck as u8 {
            return Err(anyhow!("Expected FILE_INFO_ACK, got type {}", buf[0]));
        }
        
        info!("File info acknowledged");
        Ok(())
    }

    pub async fn run(&mut self) -> Result<()> {
        let start = Instant::now();
        
        self.handshake().await?;
        self.send_file_info().await?;
        
        let filename = Path::new(&self.file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        
        let mut progress = ProgressTracker::new(self.file_size, filename);
        
        // ============================================================
        // PIPELINED I/O: Read and Write run in parallel!
        // ============================================================
        // Channel allows disk reads to run ahead while network writes are in progress
        let (tx, mut rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(PIPELINE_DEPTH);
        
        let chunk_size = get_chunk_size();
        let file_path = self.file_path.clone();
        
        info!("Starting PIPELINED file transfer (depth={})...", PIPELINE_DEPTH);
        
        // READER TASK: Reads from disk into channel (runs ahead!)
        let reader_handle = tokio::spawn(async move {
            let file = File::open(&file_path).await?;
            let mut reader = BufReader::with_capacity(BUFFER_SIZE, file);
            let mut buffer = vec![0u8; chunk_size];
            
            loop {
                let n = reader.read(&mut buffer).await?;
                if n == 0 {
                    break; // EOF
                }
                // Send chunk to writer (blocks if channel full - backpressure!)
                if tx.send(bytes::Bytes::copy_from_slice(&buffer[..n])).await.is_err() {
                    // Writer dropped - transfer aborted
                    break;
                }
            }
            Ok::<_, anyhow::Error>(())
        });
        
        // WRITER: Consumes from channel and sends over TCP
        let mut total_sent: u64 = 0;
        while let Some(data) = rx.recv().await {
            write_all_timeout(&mut self.stream, &data, IO_TIMEOUT).await?;
            total_sent += data.len() as u64;
            progress.update(total_sent);
        }
        
        // Wait for reader to complete and check for errors
        reader_handle.await
            .map_err(|e| anyhow!("Reader task panicked: {}", e))?
            .map_err(|e| anyhow!("Reader error: {}", e))?;
        
        self.stream.flush().await?;
        progress.set_position(total_sent);
        
        let done = encode_simple(MessageType::Done);
        write_all_timeout(&mut self.stream, &done, HANDSHAKE_TIMEOUT).await?;
        info!("Sent DONE, waiting for final ACK...");
        
        let mut buf = [0u8; 1];
        read_exact_timeout(&mut self.stream, &mut buf, Duration::from_secs(120)).await?;
        
        if buf[0] != MessageType::Ack as u8 {
            return Err(anyhow!("Expected final ACK, got type {}", buf[0]));
        }
        
        let elapsed = start.elapsed();
        let speed_mbps = (self.file_size as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
        
        progress.finish_with_message(format!("✅ Transfer complete! ({:.1} MB/s)", speed_mbps));
        info!("Transfer complete: {:.2} MB in {:.1}s ({:.1} MB/s) [PIPELINED]", 
            self.file_size as f64 / (1024.0 * 1024.0),
            elapsed.as_secs_f64(),
            speed_mbps);
        
        Ok(())
    }
}

/// File receiver over TCP
pub struct TcpReceiver {
    stream: Option<TcpStream>,
}

impl TcpReceiver {
    pub fn new(stream: TcpStream) -> Self {
        Self { stream: Some(stream) }
    }

    async fn handshake(&mut self) -> Result<()> {
        info!("Performing receiver handshake...");
        let stream = self.stream.as_mut().ok_or_else(|| anyhow!("Stream not available"))?;
        configure_tcp_socket(stream)?;
        
        let mut buf = [0u8; 256];
        read_exact_timeout(stream, &mut buf[..5], HANDSHAKE_TIMEOUT).await?;
        
        if buf[0] != MessageType::Hello as u8 {
            return Err(anyhow!("Expected HELLO, got type {}", buf[0]));
        }
        
        let len = (&buf[1..5]).get_u32() as usize;
        read_exact_timeout(stream, &mut buf[5..5+len], HANDSHAKE_TIMEOUT).await?;
        
        if let Some(hello) = HelloMessage::decode(&buf[..5+len]) {
            if hello.role != "sender" {
                return Err(anyhow!("Expected sender, got {}", hello.role));
            }
            info!("Received HELLO from sender");
        } else {
            return Err(anyhow!("Failed to parse HELLO"));
        }
        
        let hello = HelloMessage { role: "receiver".to_string() };
        write_all_timeout(stream, &hello.encode(), HANDSHAKE_TIMEOUT).await?;
        debug!("Sent HELLO");
        
        Ok(())
    }

    async fn receive_file_info(&mut self) -> Result<FileInfoMessage> {
        let stream = self.stream.as_mut().ok_or_else(|| anyhow!("Stream not available"))?;
        
        let mut header = [0u8; 13];
        read_exact_timeout(stream, &mut header, HANDSHAKE_TIMEOUT).await?;
        
        if header[0] != MessageType::FileInfo as u8 {
            return Err(anyhow!("Expected FILE_INFO, got type {}", header[0]));
        }
        
        let name_len = (&header[1..5]).get_u32() as usize;
        let file_size = (&header[5..13]).get_u64();
        
        let mut name_and_hash = vec![0u8; name_len + 32];
        read_exact_timeout(stream, &mut name_and_hash, HANDSHAKE_TIMEOUT).await?;
        
        let filename = String::from_utf8(name_and_hash[..name_len].to_vec())
            .map_err(|_| anyhow!("Invalid filename encoding"))?;
        
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&name_and_hash[name_len..]);
        
        let info = FileInfoMessage { filename, file_size, sha256 };
        
        info!("Receiving: {} ({:.2} MB)", info.filename, info.file_size as f64 / (1024.0 * 1024.0));
        info!("Expected SHA256: {}", sha256_to_hex(&info.sha256));
        
        let ack = encode_simple(MessageType::FileInfoAck);
        write_all_timeout(stream, &ack, HANDSHAKE_TIMEOUT).await?;
        info!("File info acknowledged");
        
        Ok(info)
    }

    pub async fn run(&mut self) -> Result<()> {
        let start = Instant::now();
        
        self.handshake().await?;
        let file_info = self.receive_file_info().await?;
        
        let temp_path = format!("{}.tmp", file_info.filename);
        let progress = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let progress_clone = progress.clone();
        
        // ============================================================
        // PIPELINED I/O: Network reads and Disk writes run in parallel!
        // ============================================================
        let (tx, mut rx) = tokio::sync::mpsc::channel::<bytes::Bytes>(PIPELINE_DEPTH);
        
        let file_size = file_info.file_size;
        let chunk_size = get_chunk_size();
        
        info!("Starting PIPELINED file transfer (depth={})...", PIPELINE_DEPTH);
        
        // Take ownership of stream for the reader task (safe with Option::take)
        let mut stream = self.stream.take()
            .ok_or_else(|| anyhow!("Stream not available"))?;
        
        // READER TASK: Reads from network into channel (runs ahead!)
        let reader_handle = tokio::spawn(async move {
            let mut total_received: u64 = 0;
            let mut buffer = vec![0u8; chunk_size];
            
            while total_received < file_size {
                let remaining = file_size - total_received;
                let to_read = std::cmp::min(remaining as usize, chunk_size);
                
                let n = match tokio::time::timeout(IO_TIMEOUT, stream.read(&mut buffer[..to_read])).await {
                    Ok(Ok(0)) => return Err(anyhow!("Connection closed unexpectedly")),
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => return Err(anyhow!("Read error: {}", e)),
                    Err(_) => return Err(anyhow!("Read timeout")),
                };
                
                // Send chunk to writer (blocks if channel full - backpressure!)
                if tx.send(bytes::Bytes::copy_from_slice(&buffer[..n])).await.is_err() {
                    break; // Writer dropped - transfer aborted
                }
                
                total_received += n as u64;
                progress_clone.store(total_received, std::sync::atomic::Ordering::Relaxed);
            }
            
            // Wait for DONE message
            let mut done_buf = [0u8; 1];
            match read_exact_timeout(&mut stream, &mut done_buf, HANDSHAKE_TIMEOUT).await {
                Ok(_) if done_buf[0] == MessageType::Done as u8 => {},
                Ok(_) => warn!("Expected DONE, got type {}", done_buf[0]),
                Err(e) => warn!("Error reading DONE: {}", e),
            }
            
            Ok::<_, anyhow::Error>(stream)
        });
        
        // WRITER TASK: Writes to disk (runs in parallel!)
        let temp_path_clone = temp_path.clone();
        let writer_handle = tokio::spawn(async move {
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&temp_path_clone)
                .await?;
            
            file.set_len(file_size).await?;
            let mut writer = BufWriter::with_capacity(BUFFER_SIZE, file);
            
            while let Some(data) = rx.recv().await {
                writer.write_all(&data).await?;
            }
            
            writer.flush().await?;
            Ok::<_, anyhow::Error>(())
        });
        
        // Progress display in main thread
        let mut progress_bar = ProgressTracker::new(file_info.file_size, &file_info.filename);
        let check_interval = Duration::from_millis(100);
        
        loop {
            tokio::time::sleep(check_interval).await;
            let current = progress.load(std::sync::atomic::Ordering::Relaxed);
            progress_bar.update(current);
            
            if current >= file_size {
                break;
            }
            
            // Check if tasks are still running
            if reader_handle.is_finished() || writer_handle.is_finished() {
                break;
            }
        }
        
        // Wait for both tasks to complete
        let stream = reader_handle.await
            .map_err(|e| anyhow!("Reader task panicked: {}", e))?
            .map_err(|e| anyhow!("Reader error: {}", e))?;
        
        writer_handle.await
            .map_err(|e| anyhow!("Writer task panicked: {}", e))?
            .map_err(|e| anyhow!("Writer error: {}", e))?;
        
        // Restore stream for final ACK
        self.stream = Some(stream);
        
        let transfer_time = start.elapsed();
        let transfer_speed = (file_info.file_size as f64 / (1024.0 * 1024.0)) / transfer_time.as_secs_f64();
        info!("Transfer complete: {:.1} MB/s [PIPELINED]", transfer_speed);
        
        progress_bar.set_position(file_size);
        
        // Verify SHA256 from disk (end-to-end verification)
        progress_bar.set_message("Verifying SHA256...");
        info!("Calculating SHA256 from disk...");
        let verify_start = Instant::now();
        let calculated_hash = sha256_file(Path::new(&temp_path)).await?;
        let verify_time = verify_start.elapsed();
        info!("SHA256 verification took {:.1}s", verify_time.as_secs_f64());
        
        if calculated_hash == file_info.sha256 {
            tokio::fs::rename(&temp_path, &file_info.filename).await?;
            
            let ack = encode_simple(MessageType::Ack);
            let stream = self.stream.as_mut().ok_or_else(|| anyhow!("Stream not available"))?;
            write_all_timeout(stream, &ack, HANDSHAKE_TIMEOUT).await?;
            
            let elapsed = start.elapsed();
            let speed_mbps = (file_info.file_size as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
            
            progress_bar.finish_with_message(format!("✅ Complete! SHA256 verified ({:.1} MB/s)", speed_mbps));
            info!("✅ Transfer complete! SHA256 verified.");
            info!("File saved: {}", file_info.filename);
            info!("Speed: {:.1} MB/s (incl. verification)", speed_mbps);
            
            Ok(())
        } else {
            tokio::fs::remove_file(&temp_path).await.ok();
            
            error!("SHA256 mismatch!");
            error!("Expected: {}", sha256_to_hex(&file_info.sha256));
            error!("Got:      {}", sha256_to_hex(&calculated_hash));
            
            progress_bar.finish_with_message("❌ SHA256 verification failed!".to_string());
            Err(anyhow!("SHA256 verification failed"))
        }
    }
}


async fn send_file_info_on_stream(
    stream: &mut TcpStream,
    file_path: &str,
    file_size: u64,
    sha256: [u8; 32],
) -> Result<()> {
    let filename = Path::new(file_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();

    let file_info = FileInfoMessage {
        filename: filename.clone(),
        file_size,
        sha256,
    };

    info!("Sending file info: {} ({:.2} MB)", filename, file_size as f64 / (1024.0 * 1024.0));
    info!("Chunk size: {} KB", get_chunk_size() / 1024);

    write_all_timeout(stream, &file_info.encode(), HANDSHAKE_TIMEOUT).await?;

    let mut buf = [0u8; 1];
    read_exact_timeout(stream, &mut buf, HANDSHAKE_TIMEOUT).await?;

    if buf[0] != MessageType::FileInfoAck as u8 {
        return Err(anyhow!("Expected FILE_INFO_ACK, got type {}", buf[0]));
    }

    info!("File info acknowledged");
    Ok(())
}

async fn receive_file_info_on_stream(stream: &mut TcpStream) -> Result<FileInfoMessage> {
    let mut header = [0u8; 13];
    read_exact_timeout(stream, &mut header, HANDSHAKE_TIMEOUT).await?;

    if header[0] != MessageType::FileInfo as u8 {
        return Err(anyhow!("Expected FILE_INFO, got type {}", header[0]));
    }

    let name_len = (&header[1..5]).get_u32() as usize;
    let file_size = (&header[5..13]).get_u64();

    let mut name_and_hash = vec![0u8; name_len + 32];
    read_exact_timeout(stream, &mut name_and_hash, HANDSHAKE_TIMEOUT).await?;

    let filename = String::from_utf8(name_and_hash[..name_len].to_vec())
        .map_err(|_| anyhow!("Invalid filename encoding"))?;

    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&name_and_hash[name_len..]);

    let info = FileInfoMessage { filename, file_size, sha256 };

    info!("Receiving: {} ({:.2} MB)", info.filename, info.file_size as f64 / (1024.0 * 1024.0));
    info!("Expected SHA256: {}", sha256_to_hex(&info.sha256));

    let ack = encode_simple(MessageType::FileInfoAck);
    write_all_timeout(stream, &ack, HANDSHAKE_TIMEOUT).await?;
    info!("File info acknowledged");

    Ok(info)
}

async fn sender_worker(
    mut stream: TcpStream,
    file_path: String,
    file_size: u64,
    pending: Arc<Mutex<VecDeque<u32>>>,
    notify: Arc<Notify>,
    completed_chunks: Arc<AtomicUsize>,
    completed_bytes: Arc<AtomicU64>,
    total_chunks: u32,
    chunk_size: usize,
) -> Result<TcpStream> {
    let mut file = File::open(&file_path).await?;
    let mut buffer = vec![0u8; chunk_size];

    loop {
        let chunk_id = {
            let mut queue = pending.lock().await;
            queue.pop_front()
        };

        let chunk_id = match chunk_id {
            Some(id) => id,
            None => {
                if completed_chunks.load(Ordering::Relaxed) as u32 >= total_chunks {
                    break;
                }
                notify.notified().await;
                continue;
            }
        };

        let offset = chunk_id as u64 * chunk_size as u64;
        let remaining = file_size.saturating_sub(offset);
        let len = std::cmp::min(remaining, chunk_size as u64) as usize;

        file.seek(std::io::SeekFrom::Start(offset)).await?;
        file.read_exact(&mut buffer[..len]).await?;

        let mut hasher = Hasher::new();
        hasher.update(&buffer[..len]);
        let hash32 = hasher.finalize();

        let header = ChunkHeaderMessage {
            chunk_id,
            offset,
            len: len as u32,
            hash32,
        };

        let send_res = async {
            write_all_timeout(&mut stream, &header.encode(), IO_TIMEOUT).await?;
            write_all_timeout(&mut stream, &buffer[..len], IO_TIMEOUT).await?;
            read_chunk_ack_message(&mut stream).await
        }.await;

        match send_res {
            Ok(ack) if ack.is_nack => {
                let mut queue = pending.lock().await;
                queue.push_back(chunk_id);
                notify.notify_one();
                continue;
            }
            Ok(_ack) => {}
            Err(e) => {
                let mut queue = pending.lock().await;
                queue.push_back(chunk_id);
                notify.notify_one();
                return Err(e);
            }
        }

        completed_chunks.fetch_add(1, Ordering::Relaxed);
        completed_bytes.fetch_add(len as u64, Ordering::Relaxed);
        if completed_chunks.load(Ordering::Relaxed) as u32 >= total_chunks {
            notify.notify_waiters();
        }
    }

    Ok(stream)
}

async fn receiver_worker(
    conn_id: u8,
    mut stream: TcpStream,
    temp_path: String,
    file_size: u64,
    received_flags: Arc<Vec<AtomicBool>>,
    received_count: Arc<AtomicUsize>,
    received_bytes: Arc<AtomicU64>,
    done_received: Arc<AtomicBool>,
    done_notify: Arc<Notify>,
) -> Result<TcpStream> {
    let mut file = OpenOptions::new()
        .write(true)
        .open(&temp_path)
        .await?;
    let chunk_size = get_chunk_size();
    let total_chunks = received_flags.len() as u32;

    struct BadChunkTracker {
        bad_chunks: u32,
        good_streak: u32,
    }

    impl BadChunkTracker {
        fn new() -> Self {
            Self {
                bad_chunks: 0,
                good_streak: 0,
            }
        }

        fn record_bad(&mut self, conn_id: u8, reason: &str, chunk_id: u32) -> Result<()> {
            self.bad_chunks += 1;
            self.good_streak = 0;
            warn!(
                "Conn {}: bad chunk {} ({}/{}): {}",
                conn_id,
                chunk_id,
                self.bad_chunks,
                MAX_BAD_CHUNKS_PER_CONN,
                reason,
            );
            if self.bad_chunks >= MAX_BAD_CHUNKS_PER_CONN {
                return Err(anyhow!("Too many bad chunks on conn {}", conn_id));
            }
            Ok(())
        }

        fn record_good(&mut self) {
            if self.bad_chunks == 0 {
                return;
            }
            self.good_streak += 1;
            if self.good_streak >= BAD_CHUNKS_DECAY_STREAK {
                self.bad_chunks -= 1;
                self.good_streak = 0;
            }
        }
    }

    let mut tracker = BadChunkTracker::new();

    loop {
        if done_received.load(Ordering::Relaxed) {
            break;
        }

        let mut type_buf = [0u8; 1];
        let read_res = tokio::select! {
            _ = done_notify.notified() => {
                return Ok(stream);
            }
            res = read_exact_timeout(&mut stream, &mut type_buf, IO_TIMEOUT) => res,
        };

        if let Err(e) = read_res {
            if done_received.load(Ordering::Relaxed) {
                break;
            }
            return Err(e);
        }

        let msg_type = MessageType::from_u8(type_buf[0])
            .ok_or_else(|| anyhow!("Unknown message type {}", type_buf[0]))?;

        match msg_type {
            MessageType::ChunkHeader => {
                let mut header_rest = [0u8; 20];
                read_exact_timeout(&mut stream, &mut header_rest, IO_TIMEOUT).await?;

                let mut header_buf = [0u8; 21];
                header_buf[0] = type_buf[0];
                header_buf[1..].copy_from_slice(&header_rest);

                let header = ChunkHeaderMessage::decode(&header_buf)
                    .ok_or_else(|| anyhow!("Failed to parse CHUNK_HEADER"))?;

                let len = header.len as usize;
                if len == 0 || len > chunk_size {
                    tracker.record_bad(conn_id, "invalid chunk length", header.chunk_id)?;
                    return Err(anyhow!("Invalid chunk length {}", len));
                }
                if header.chunk_id >= total_chunks {
                    tracker.record_bad(conn_id, "chunk_id out of range", header.chunk_id)?;
                    let mut discard = vec![0u8; len];
                    read_exact_timeout(&mut stream, &mut discard, IO_TIMEOUT).await?;
                    let nack = ChunkAckMessage { chunk_id: header.chunk_id, is_nack: true };
                    write_all_timeout(&mut stream, &nack.encode(), IO_TIMEOUT).await?;
                    continue;
                }

                let expected_offset = header.chunk_id as u64 * chunk_size as u64;
                if header.offset != expected_offset {
                    tracker.record_bad(conn_id, "offset mismatch", header.chunk_id)?;
                    let mut discard = vec![0u8; len];
                    read_exact_timeout(&mut stream, &mut discard, IO_TIMEOUT).await?;
                    let nack = ChunkAckMessage { chunk_id: header.chunk_id, is_nack: true };
                    write_all_timeout(&mut stream, &nack.encode(), IO_TIMEOUT).await?;
                    continue;
                }
                if header.offset + header.len as u64 > file_size {
                    tracker.record_bad(conn_id, "chunk out of bounds", header.chunk_id)?;
                    let mut discard = vec![0u8; len];
                    read_exact_timeout(&mut stream, &mut discard, IO_TIMEOUT).await?;
                    let nack = ChunkAckMessage { chunk_id: header.chunk_id, is_nack: true };
                    write_all_timeout(&mut stream, &nack.encode(), IO_TIMEOUT).await?;
                    continue;
                }

                let mut data = vec![0u8; len];
                read_exact_timeout(&mut stream, &mut data, IO_TIMEOUT).await?;

                let mut hasher = Hasher::new();
                hasher.update(&data);
                let hash32 = hasher.finalize();

                if hash32 != header.hash32 {
                    tracker.record_bad(conn_id, "crc32 mismatch", header.chunk_id)?;
                    let nack = ChunkAckMessage { chunk_id: header.chunk_id, is_nack: true };
                    write_all_timeout(&mut stream, &nack.encode(), IO_TIMEOUT).await?;
                    continue;
                }

                file.seek(std::io::SeekFrom::Start(header.offset)).await?;
                file.write_all(&data).await?;

                let mut was_set = false;
                if let Some(flag) = received_flags.get(header.chunk_id as usize) {
                    was_set = flag.swap(true, Ordering::AcqRel);
                }

                if !was_set {
                    received_count.fetch_add(1, Ordering::Relaxed);
                    received_bytes.fetch_add(len as u64, Ordering::Relaxed);
                }

                let ack = ChunkAckMessage { chunk_id: header.chunk_id, is_nack: false };
                write_all_timeout(&mut stream, &ack.encode(), IO_TIMEOUT).await?;
                tracker.record_good();
            }
            MessageType::TransferDone => {
                done_received.store(true, Ordering::Relaxed);
                done_notify.notify_waiters();
                let ack = encode_simple(MessageType::TransferDoneAck);
                write_all_timeout(&mut stream, &ack, HANDSHAKE_TIMEOUT).await?;
                break;
            }
            _ => return Err(anyhow!("Unexpected message type {}", msg_type as u8)),
        }
    }

    Ok(stream)
}

/// Multi-stream file sender
pub struct MultiSender {
    streams: Vec<TcpStream>,
    file_path: String,
    file_size: u64,
    sha256: [u8; 32],
}

impl MultiSender {
    pub fn new_with_hash(
        streams: Vec<TcpStream>,
        file_path: &str,
        file_size: u64,
        sha256: [u8; 32],
    ) -> Self {
        Self {
            streams,
            file_path: file_path.to_string(),
            file_size,
            sha256,
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        if self.streams.is_empty() {
            return Err(anyhow!("No streams available"));
        }

        let start = Instant::now();
        for stream in &self.streams {
            configure_tcp_socket(stream)?;
        }

        send_file_info_on_stream(&mut self.streams[0], &self.file_path, self.file_size, self.sha256).await?;

        let filename = Path::new(&self.file_path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");

        let mut progress = ProgressTracker::new(self.file_size, filename);

        let chunk_size = get_chunk_size();
        let total_chunks = ((self.file_size + chunk_size as u64 - 1) / chunk_size as u64) as u32;

        let pending = Arc::new(Mutex::new(VecDeque::with_capacity(total_chunks as usize)));
        {
            let mut queue = pending.lock().await;
            for id in 0..total_chunks {
                queue.push_back(id);
            }
        }
        let notify = Arc::new(Notify::new());
        let completed_chunks = Arc::new(AtomicUsize::new(0));
        let completed_bytes = Arc::new(AtomicU64::new(0));

        let streams = std::mem::take(&mut self.streams);
        let mut handles = Vec::with_capacity(streams.len());

        for (conn_id, stream) in streams.into_iter().enumerate() {
            let file_path = self.file_path.clone();
            let pending = pending.clone();
            let notify = notify.clone();
            let completed_chunks = completed_chunks.clone();
            let completed_bytes = completed_bytes.clone();
            let file_size = self.file_size;
            let handle = tokio::spawn(async move {
                let res = sender_worker(
                    stream,
                    file_path,
                    file_size,
                    pending,
                    notify,
                    completed_chunks,
                    completed_bytes,
                    total_chunks,
                    chunk_size,
                ).await;
                (conn_id as u8, res)
            });
            handles.push(handle);
        }

        loop {
            let done_bytes = completed_bytes.load(Ordering::Relaxed);
            progress.update(done_bytes);
            if completed_chunks.load(Ordering::Relaxed) as u32 >= total_chunks {
                break;
            }
            if handles.iter().all(|h| h.is_finished()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let mut returned_streams: Vec<Option<TcpStream>> = Vec::with_capacity(handles.len());
        returned_streams.resize_with(handles.len(), || None);
        for handle in handles {
            let (conn_id, res) = handle.await
                .map_err(|e| anyhow!("Worker task panicked: {}", e))?;
            if let Ok(stream) = res {
                if let Some(slot) = returned_streams.get_mut(conn_id as usize) {
                    *slot = Some(stream);
                }
            }
        }

        if completed_chunks.load(Ordering::Relaxed) as u32 != total_chunks {
            return Err(anyhow!("Transfer incomplete: not all chunks acked"));
        }

        let mut done_stream = returned_streams
            .get_mut(0)
            .and_then(|s| s.take())
            .or_else(|| {
                returned_streams.into_iter().flatten().next()
            })
            .ok_or_else(|| anyhow!("No stream available for TransferDone"))?;

        let done = encode_simple(MessageType::TransferDone);
        write_all_timeout(&mut done_stream, &done, HANDSHAKE_TIMEOUT).await?;

        let mut ack_buf = [0u8; 1];
        read_exact_timeout(&mut done_stream, &mut ack_buf, Duration::from_secs(120)).await?;
        if ack_buf[0] != MessageType::TransferDoneAck as u8 {
            return Err(anyhow!("Expected TRANSFER_DONE_ACK, got type {}", ack_buf[0]));
        }

        let elapsed = start.elapsed();
        let speed_mbps = (self.file_size as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();

        progress.finish_with_message(format!("Transfer complete ({:.1} MB/s)", speed_mbps));
        info!("Transfer complete: {:.2} MB in {:.1}s ({:.1} MB/s)",
            self.file_size as f64 / (1024.0 * 1024.0),
            elapsed.as_secs_f64(),
            speed_mbps);

        Ok(())
    }
}

/// Multi-stream file receiver
pub struct MultiReceiver {
    streams: Vec<TcpStream>,
}

impl MultiReceiver {
    pub fn new(streams: Vec<TcpStream>) -> Self {
        Self { streams }
    }

    pub async fn run(&mut self) -> Result<()> {
        if self.streams.is_empty() {
            return Err(anyhow!("No streams available"));
        }

        let start = Instant::now();
        for stream in &self.streams {
            configure_tcp_socket(stream)?;
        }

        let file_info = receive_file_info_on_stream(&mut self.streams[0]).await?;
        let temp_path = format!("{}.tmp", file_info.filename);

        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&temp_path)
            .await?;
        file.set_len(file_info.file_size).await?;
        drop(file);

        let chunk_size = get_chunk_size();
        let total_chunks = ((file_info.file_size + chunk_size as u64 - 1) / chunk_size as u64) as u32;

        let received_flags = Arc::new((0..total_chunks)
            .map(|_| AtomicBool::new(false))
            .collect::<Vec<_>>());
        let received_count = Arc::new(AtomicUsize::new(0));
        let received_bytes = Arc::new(AtomicU64::new(0));
        let done_received = Arc::new(AtomicBool::new(false));
        let done_notify = Arc::new(Notify::new());

        let streams = std::mem::take(&mut self.streams);
        let mut handles = Vec::with_capacity(streams.len());

        for (conn_id, stream) in streams.into_iter().enumerate() {
            let temp_path = temp_path.clone();
            let received_flags = received_flags.clone();
            let received_count = received_count.clone();
            let received_bytes = received_bytes.clone();
            let done_received = done_received.clone();
            let done_notify = done_notify.clone();
            let handle = tokio::spawn(async move {
                let res = receiver_worker(
                    conn_id as u8,
                    stream,
                    temp_path,
                    file_info.file_size,
                    received_flags,
                    received_count,
                    received_bytes,
                    done_received,
                    done_notify,
                ).await;
                (conn_id as u8, res)
            });
            handles.push(handle);
        }

        let mut progress_bar = ProgressTracker::new(file_info.file_size, &file_info.filename);
        loop {
            let current = received_bytes.load(Ordering::Relaxed);
            progress_bar.update(current);

            if done_received.load(Ordering::Relaxed) {
                break;
            }
            if handles.iter().all(|h| h.is_finished()) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        for handle in handles {
            let (_conn_id, res) = handle.await
                .map_err(|e| anyhow!("Worker task panicked: {}", e))?;
            if let Err(e) = res {
                if !done_received.load(Ordering::Relaxed) {
                    return Err(e);
                }
            }
        }

        if received_count.load(Ordering::Relaxed) as u32 != total_chunks {
            return Err(anyhow!("Transfer incomplete: missing chunks"));
        }

        progress_bar.set_position(file_info.file_size);
        progress_bar.set_message("Verifying SHA256...");

        let verify_start = Instant::now();
        let calculated_hash = sha256_file(Path::new(&temp_path)).await?;
        let verify_time = verify_start.elapsed();
        info!("SHA256 verification took {:.1}s", verify_time.as_secs_f64());

        if calculated_hash == file_info.sha256 {
            tokio::fs::rename(&temp_path, &file_info.filename).await?;

            let elapsed = start.elapsed();
            let speed_mbps = (file_info.file_size as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();

            progress_bar.finish_with_message(format!("Complete! SHA256 verified ({:.1} MB/s)", speed_mbps));
            info!("Transfer complete! SHA256 verified.");
            info!("File saved: {}", file_info.filename);
            info!("Speed: {:.1} MB/s (incl. verification)", speed_mbps);

            Ok(())
        } else {
            tokio::fs::remove_file(&temp_path).await.ok();

            error!("SHA256 mismatch!");
            error!("Expected: {}", sha256_to_hex(&file_info.sha256));
            error!("Got:      {}", sha256_to_hex(&calculated_hash));

            progress_bar.finish_with_message("SHA256 verification failed!".to_string());
            Err(anyhow!("SHA256 verification failed"))
        }
    }
}
