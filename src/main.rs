//! TCP File Transfer Client with NAT Traversal
//!
//! This client uses TCP hole punching to establish direct peer-to-peer
//! connections through NAT, then transfers files using TCP streams.
//!
//! Protocol flow:
//! 1. Connect to relay server and register with session ID + role
//! 2. Wait for peer_info (when other peer connects)
//! 3. Send "ready" to signal we're prepared
//! 4. Wait for synchronized "go" signal with start_at timestamp
//! 5. At start_at, begin simultaneous hole punch
//! 6. Transfer file over established connection
//!
//! Usage:
//!   Receive: tcp-transfer -s relay:port -i SESSION_ID -m receive
//!   Send:    tcp-transfer -s relay:port -i SESSION_ID -m send -f file.mp4

use std::collections::HashSet;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::Duration;
use clap::{Parser, ValueEnum};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use socket2::{Socket, Domain, Type, Protocol, SockAddr};
use anyhow::{Result, anyhow};
use tracing::{info, error, warn, Level, debug};
use tracing_subscriber::FmtSubscriber;

mod protocol;
mod hole_punch;
mod transfer;

use protocol::{RegisterMessage, ReadyMessage, RelayMessage, ProbeMessage, NATAnalysis};
use hole_punch::{HolePunchConfig, HolePunchResult, PeerAddress, do_hole_punch};
use transfer::{
    TcpSender,
    TcpReceiver,
    MultiSender,
    MultiReceiver,
    calculate_sha256,
    set_chunk_size,
    multi_handshake_sender,
    multi_handshake_receiver,
    multi_hello_sender,
    multi_hello_receiver,
    send_multi_ready,
    read_multi_ready,
    send_multi_start,
    read_multi_start,
};

/// Number of NAT probes to send
const DEFAULT_NAT_PROBE_COUNT: u32 = 10;
const MIN_PORT: u16 = 1024;
const MAX_PORT: u16 = 65535;
const MAX_SCAN_PORTS: usize = 512;
const MULTI_START_DELAY_SEC: f64 = 2.0;
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Mode {
    Send,
    Receive,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum PredictionMode {
    Delta,
    External,
}

impl PredictionMode {
    fn as_str(self) -> &'static str {
        match self {
            PredictionMode::Delta => "delta",
            PredictionMode::External => "external",
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "tcp-transfer")]
#[command(author = "TCP Transfer Team")]
#[command(version)]
#[command(about = "TCP file transfer with NAT traversal (hole punching)")]
struct Args {
    /// Relay server address (host:port)
    #[arg(short, long)]
    server: String,
    
    /// Session ID (both sender and receiver must use the same ID)
    #[arg(short = 'i', long)]
    session_id: String,
    
    /// Mode: send or receive
    #[arg(short, long, value_enum)]
    mode: Mode,
    
    /// File to send (sender mode only)
    #[arg(short, long)]
    file: Option<String>,
    
    /// Hole punch timeout in seconds
    #[arg(long, default_value = "30")]
    timeout: u64,

    /// Number of NAT probes to send (higher can improve symmetric/random NAT success)
    #[arg(long, default_value_t = DEFAULT_NAT_PROBE_COUNT)]
    probe_count: u32,

    /// Run probe-only debug mode and print observed ports
    #[arg(long)]
    probe_debug: bool,

    /// NAT prediction mode: delta or external
    #[arg(long, value_enum, default_value_t = PredictionMode::Delta)]
    prediction_mode: PredictionMode,

    /// Expand prediction scan range by percentage (applies to delta and external)
    #[arg(long, default_value_t = 0.0)]
    prediction_range_extra_pct: f64,
    
    /// Number of parallel TCP connections (multi TCP)
    #[arg(long, default_value_t = 1, help_heading = "Multi-TCP")]
    tcp_connections: u8,
    
    /// Global scan budget across all connections (0 = unlimited)
    #[arg(long, default_value_t = 1024, help_heading = "Multi-TCP")]
    scan_budget: u32,
    
    /// Enable debug logging
    #[arg(long)]
    debug: bool,
    
    /// Chunk size for transfer (e.g., 512KB, 1MB, 2MB)
    #[arg(long, default_value = "8MB")]
    chunk: String,
}

/// Parse chunk size from string (e.g., "512KB", "1MB", "2MB")
fn parse_chunk_size(s: &str) -> Result<usize> {
    let s = s.trim().to_uppercase();
    
    if s.ends_with("MB") {
        let num: f64 = s.trim_end_matches("MB").trim().parse()
            .map_err(|_| anyhow!("Invalid chunk size: {}", s))?;
        Ok((num * 1024.0 * 1024.0) as usize)
    } else if s.ends_with("KB") {
        let num: f64 = s.trim_end_matches("KB").trim().parse()
            .map_err(|_| anyhow!("Invalid chunk size: {}", s))?;
        Ok((num * 1024.0) as usize)
    } else if s.ends_with("B") {
        let num: usize = s.trim_end_matches("B").trim().parse()
            .map_err(|_| anyhow!("Invalid chunk size: {}", s))?;
        Ok(num)
    } else {
        // Try parsing as bytes
        s.parse::<usize>()
            .map_err(|_| anyhow!("Invalid chunk size: {}. Use format like 512KB, 1MB, 2MB", s))
    }
}

/// Session state for hole punch coordination
struct Session {
    peer_public_addr: Option<SocketAddr>,
    peer_addresses: Vec<PeerAddress>,
    peer_nat_analysis: Option<protocol::NATAnalysis>,
    peer_port_analyses: Option<Vec<protocol::PeerPortAnalysis>>,
    same_network: bool,
    start_at: Option<f64>,
    /// Time offset for clock sync: local_time + offset = server_time
    time_offset: f64,
    /// Our own public port as seen by server
    our_public_port: Option<u16>,
    /// Our port delta: public_port - local_port
    our_delta: i32,
    /// Port preservation: true if our_delta == 0
    port_preserved: bool,
}

fn parse_host_port(input: &str) -> Result<(String, u16)> {
    let input = input.trim();
    if input.starts_with('[') {
        let end = input.find(']').ok_or_else(|| anyhow!("Invalid address '{}': missing closing ']'", input))?;
        let host = &input[1..end];
        let rest = &input[end + 1..];
        if !rest.starts_with(':') {
            return Err(anyhow!("Invalid address '{}': expected [host]:port", input));
        }
        let port_str = &rest[1..];
        if host.is_empty() || port_str.is_empty() {
            return Err(anyhow!("Invalid address '{}': expected [host]:port", input));
        }
        let port = port_str.parse::<u16>()
            .map_err(|_| anyhow!("Invalid port in address '{}'", input))?;
        return Ok((host.to_string(), port));
    }

    let idx = input.rfind(':')
        .ok_or_else(|| anyhow!("Invalid address '{}': expected host:port", input))?;
    let host = &input[..idx];
    let port_str = &input[idx + 1..];
    if host.is_empty() || port_str.is_empty() {
        return Err(anyhow!("Invalid address '{}': expected host:port", input));
    }
    if host.contains(':') {
        return Err(anyhow!("Invalid address '{}': IPv6 must be in [addr]:port format", input));
    }
    let port = port_str.parse::<u16>()
        .map_err(|_| anyhow!("Invalid port in address '{}'", input))?;
    Ok((host.to_string(), port))
}

fn resolve_host_port(host: &str, port: u16) -> Result<SocketAddr> {
    let mut addrs = (host, port).to_socket_addrs()
        .map_err(|e| anyhow!("Failed to resolve '{}': {}", host, e))?;
    addrs.next()
        .ok_or_else(|| anyhow!("Failed to resolve '{}': no addresses found", host))
}

fn resolve_socket_addr(input: &str) -> Result<SocketAddr> {
    let (host, port) = parse_host_port(input)?;
    resolve_host_port(&host, port)
}

/// Do NAT probing - send multiple connections to probe server to determine port range
async fn do_nat_probing(probe_addr: SocketAddr, session_id: &str, count: u32) -> Result<()> {
    info!("🔍 Starting NAT probing ({} connections to {})...", count, probe_addr);
    
    let mut successful = 0;
    
    for i in 0..count {
        // Each probe uses a NEW local port to get different NAT mapping
        match TcpStream::connect(probe_addr).await {
            Ok(stream) => {
                let local_port = stream.local_addr().map(|a| a.port()).unwrap_or(0);
                
                // Send probe message
                let probe = ProbeMessage::new(session_id, local_port, i);
                let msg = serde_json::to_string(&probe).unwrap_or_default() + "\n";
                
                // Use split to send
                let (_, mut writer) = stream.into_split();
                if let Ok(_) = tokio::io::AsyncWriteExt::write_all(&mut writer, msg.as_bytes()).await {
                    successful += 1;
                    debug!("  Probe #{}: local port {}", i, local_port);
                }
            }
            Err(e) => {
                warn!("  Probe #{} failed: {}", i, e);
            }
        }
        
        // Small delay between probes
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    
    if successful >= 5 {
        info!("  ✓ Sent {}/{} probes successfully", successful, count);
        Ok(())
    } else {
        warn!("  ⚠️ Only {}/{} probes succeeded - NAT analysis may be incomplete", successful, count);
        Ok(()) // Continue anyway
    }
}

/// Get a free local port by binding temporarily
fn get_free_port() -> Result<u16> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    
    let addr: SocketAddr = "0.0.0.0:0".parse()?;
    socket.bind(&addr.into())?;
    
    let local_addr = socket.local_addr()?;
    let port = local_addr.as_socket().ok_or_else(|| anyhow!("No socket address"))?.port();
    
    // Socket is dropped here, freeing the port but we remember it
    Ok(port)
}

/// Create a TCP socket bound to a specific local port
fn create_bound_socket(local_port: u16) -> Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    
    // CRITICAL: Enable address reuse so we can reuse this port for hole punching
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    
    // Disable Nagle for faster small packet transmission
    socket.set_nodelay(true)?;
    
    // Bind to the specific local port
    let local_addr: SocketAddr = format!("0.0.0.0:{}", local_port).parse()?;
    socket.bind(&SockAddr::from(local_addr))?;
    
    Ok(socket)
}


struct PredictionRange {
    predicted_port: u16,
    scan_start: u16,
    scan_end: u16,
    needs_scan: bool,
    pattern_type: String,
    min_port: u16,
}

fn current_timestamp() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

fn clamp_port(port: i32) -> u16 {
    port.clamp(MIN_PORT as i32, MAX_PORT as i32) as u16
}

fn apply_range_extra(scan_start: i32, scan_end: i32, pct: f64) -> (i32, i32) {
    if pct <= 0.0 {
        return (scan_start, scan_end);
    }
    if scan_end <= scan_start {
        return (scan_start, scan_end);
    }
    let span = (scan_end - scan_start) as f64;
    let extra_total = (span * (pct / 100.0)).round() as i32;
    if extra_total <= 0 {
        return (scan_start, scan_end);
    }
    let pad_low = extra_total / 2;
    let pad_high = extra_total - pad_low;
    let new_start = (scan_start - pad_low).max(MIN_PORT as i32);
    let new_end = (scan_end + pad_high).min(MAX_PORT as i32);
    (new_start, new_end)
}

fn compute_prediction_range(
    peer_local_port: u16,
    nat: &NATAnalysis,
    prediction_mode: PredictionMode,
    prediction_range_extra_pct: f64,
) -> PredictionRange {
    let mut predicted_port = nat.predicted_port;
    if matches!(prediction_mode, PredictionMode::Delta) {
        let predicted = (peer_local_port as f64 + nat.delta_median).round() as i32;
        predicted_port = clamp_port(predicted);
    }
    if predicted_port == 0 {
        predicted_port = peer_local_port;
    }

    let mut scan_start = predicted_port as i32 - nat.error_range as i32;
    let mut scan_end = predicted_port as i32 + nat.error_range as i32;
    scan_start = scan_start.max(MIN_PORT as i32);
    scan_end = scan_end.min(MAX_PORT as i32);

    if nat.pattern_type == "random_like" && nat.min_port > 0 && nat.max_port >= nat.min_port {
        scan_start = nat.min_port as i32;
        scan_end = nat.max_port as i32;
    }

    let (scan_start, scan_end) = apply_range_extra(scan_start, scan_end, prediction_range_extra_pct);
    let needs_scan = scan_end > scan_start;

    PredictionRange {
        predicted_port,
        scan_start: scan_start as u16,
        scan_end: scan_end as u16,
        needs_scan,
        pattern_type: nat.pattern_type.clone(),
        min_port: nat.min_port,
    }
}
fn prediction_range_from_analysis(peer_local_port: u16, nat: &NATAnalysis) -> PredictionRange {
    let mut predicted_port = nat.predicted_port;
    if predicted_port == 0 {
        predicted_port = peer_local_port;
    }
    if predicted_port == 0 && nat.scan_start > 0 {
        predicted_port = nat.scan_start;
    }

    let mut scan_start = nat.scan_start;
    let mut scan_end = nat.scan_end;
    if scan_start == 0 && scan_end == 0 {
        scan_start = predicted_port;
        scan_end = predicted_port;
    }

    let needs_scan = nat.needs_scan && scan_end > scan_start;

    PredictionRange {
        predicted_port,
        scan_start,
        scan_end,
        needs_scan,
        pattern_type: nat.pattern_type.clone(),
        min_port: nat.min_port,
    }
}


fn build_candidate_ports(range: &PredictionRange, max_ports: usize) -> Vec<u16> {
    if !range.needs_scan {
        return Vec::new();
    }
    if range.scan_end < range.scan_start {
        return Vec::new();
    }

    if range.pattern_type == "random_like" {
        let mut ports = Vec::new();
        let mut seen = HashSet::new();

        let add_port = |port: u16, ports: &mut Vec<u16>, seen: &mut HashSet<u16>| {
            if port < range.scan_start || port > range.scan_end {
                return;
            }
            if seen.insert(port) {
                ports.push(port);
            }
        };

        if range.predicted_port > 0 {
            add_port(range.predicted_port, &mut ports, &mut seen);
        }

        let base = range.min_port;
        for delta in 1..=5u16 {
            add_port(base.saturating_add(delta), &mut ports, &mut seen);
        }

        let remaining = max_ports.saturating_sub(ports.len());
        if remaining > 0 {
            let span = range.scan_end - range.scan_start;
            let step = if span > 0 {
                std::cmp::max(1, (span as usize) / remaining)
            } else {
                1
            };
            let mut p = range.scan_start;
            while p <= range.scan_end && ports.len() < max_ports {
                add_port(p, &mut ports, &mut seen);
                p = p.saturating_add(step as u16);
            }
        }

        return ports;
    }

    let total = (range.scan_end - range.scan_start + 1) as usize;
    if total <= max_ports {
        return (range.scan_start..=range.scan_end).collect();
    }

    let predicted = if range.predicted_port != 0 {
        range.predicted_port
    } else {
        range.scan_start + (range.scan_end - range.scan_start) / 2
    };

    let half = max_ports / 2;
    let mut window_start = predicted.saturating_sub(half as u16);
    if window_start < range.scan_start {
        window_start = range.scan_start;
    }
    let mut window_end = window_start + max_ports as u16 - 1;
    if window_end > range.scan_end {
        window_end = range.scan_end;
        window_start = window_end.saturating_sub(max_ports as u16 - 1);
        if window_start < range.scan_start {
            window_start = range.scan_start;
        }
    }

    (window_start..=window_end).collect()
}

fn build_peer_addresses_for_conn(
    peer_ip: &str,
    peer_public_port: u16,
    peer_local_port: u16,
    prediction_mode: PredictionMode,
    prediction_range_extra_pct: f64,
    nat: Option<&NATAnalysis>,
    port_analysis: Option<&NATAnalysis>,
    include_public_port: bool,
) -> Vec<PeerAddress> {
    let mut addresses = Vec::new();
    let mut seen = HashSet::new();

    let mut add_port = |port: u16, addr_type: &str| {
        if seen.insert(port) {
            addresses.push(PeerAddress {
                ip: peer_ip.to_string(),
                port,
                addr_type: addr_type.to_string(),
            });
        }
    };

    if include_public_port {
        add_port(peer_public_port, "public");
    }

    if let Some(nat) = port_analysis {
        let range = prediction_range_from_analysis(peer_local_port, nat);
        if range.predicted_port > 0 {
            add_port(range.predicted_port, "predicted");
        }
        if peer_local_port != peer_public_port {
            add_port(peer_local_port, "public_local_port");
        }
        if range.needs_scan {
            for port in build_candidate_ports(&range, MAX_SCAN_PORTS) {
                add_port(port, "predicted_range");
            }
        }
    } else if let Some(nat) = nat {
        let range = compute_prediction_range(peer_local_port, nat, prediction_mode, prediction_range_extra_pct);
        if range.predicted_port > 0 {
            add_port(range.predicted_port, "predicted");
        }
        if peer_local_port != peer_public_port {
            add_port(peer_local_port, "public_local_port");
        }
        if range.needs_scan {
            for port in build_candidate_ports(&range, MAX_SCAN_PORTS) {
                add_port(port, "predicted_range");
            }
        }
    } else if peer_local_port != peer_public_port {
        add_port(peer_local_port, "public_local_port");
    }

    addresses
}

fn apply_scan_budget(lists: Vec<Vec<PeerAddress>>, budget: u32) -> Result<Vec<Vec<PeerAddress>>> {
    if budget == 0 {
        return Ok(lists);
    }

    let total_conns = lists.len();
    if total_conns == 0 {
        return Ok(lists);
    }

    for list in &lists {
        if list.is_empty() {
            return Err(anyhow!("No candidate ports available for one connection"));
        }
    }

    if budget < total_conns as u32 {
        return Err(anyhow!("scan_budget too low for {} connections", total_conns));
    }

    let mut result: Vec<Vec<PeerAddress>> = vec![Vec::new(); total_conns];
    let mut indices = vec![0usize; total_conns];
    let mut used = 0u32;

    for i in 0..total_conns {
        result[i].push(lists[i][0].clone());
        indices[i] = 1;
        used += 1;
    }

    while used < budget {
        let mut progressed = false;
        for i in 0..total_conns {
            if used >= budget {
                break;
            }
            if indices[i] < lists[i].len() {
                result[i].push(lists[i][indices[i]].clone());
                indices[i] += 1;
                used += 1;
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
    }

    Ok(result)
}

fn collect_local_ports(total_conns: u8, control_port: u16) -> Result<Vec<u16>> {
    let mut ports = Vec::with_capacity(total_conns as usize);
    let mut seen = HashSet::new();
    seen.insert(control_port);
    ports.push(control_port);

    while ports.len() < total_conns as usize {
        let port = get_free_port()?;
        if seen.insert(port) {
            ports.push(port);
        }
    }

    Ok(ports)
}

/// Connect to relay server and handle the full protocol
async fn run_relay_protocol(
    server_addr: &str,
    session_id: &str,
    role: &str,
    local_port: u16,
    local_ports: Option<&[u16]>,
    tcp_connections: u8,
    _timeout: Duration,
    probe_count: u32,
    prediction_mode: PredictionMode,
    prediction_range_extra_pct: f64,
) -> Result<(TcpStream, Session)> {
    info!("Connecting to relay server: {}", server_addr);
    
    // CRITICAL FIX: Connect FROM the local_port so NAT mapping matches hole punch!
    let server_sock_addr = resolve_socket_addr(server_addr)?;
    
    let socket = create_bound_socket(local_port)?;
    socket.set_nonblocking(true)?;
    
    // Start async connect
    let _ = socket.connect(&SockAddr::from(server_sock_addr));
    
    let std_stream: std::net::TcpStream = socket.into();
    let stream = TcpStream::from_std(std_stream)?;
    
    // Wait for connection to complete
    stream.writable().await?;
    
    // Check for connection errors
    if let Err(e) = stream.peer_addr() {
        return Err(anyhow!("Failed to connect to relay server: {}", e));
    }
    
    info!("Connected from local port {} to {}", local_port, server_addr);
    
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    
    // Send registration
    let local_ports_payload = local_ports
        .map(|ports| ports.to_vec())
        .filter(|ports| !ports.is_empty());
    let tcp_connections_payload = if tcp_connections > 1 {
        Some(tcp_connections)
    } else {
        None
    };

    let register = RegisterMessage::new(
        session_id,
        role,
        local_port,
        Some(prediction_mode.as_str().to_string()),
        Some(prediction_range_extra_pct),
        tcp_connections_payload,
        local_ports_payload,
    );
    let msg = serde_json::to_string(&register)? + "\n";
    writer.write_all(msg.as_bytes()).await?;
    writer.flush().await?;
    
    info!("Registered as {} for session {} (local_port={})", role, session_id, local_port);
    
    // Track timing for clock offset calculation
    let register_sent_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    
    let mut session = Session {
        peer_public_addr: None,
        peer_addresses: vec![],
        peer_nat_analysis: None,
        peer_port_analyses: None,
        same_network: false,
        start_at: None,
        time_offset: 0.0,
        our_public_port: None,
        our_delta: 0,
        port_preserved: true,
    };
    
    // Read messages from server until we get the GO signal
    loop {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(120), reader.read_line(&mut line)).await
            .map_err(|_| anyhow!("Timeout waiting for server response"))??;
        
        if n == 0 {
            return Err(anyhow!("Server closed connection"));
        }
        
        debug!("Server message: {}", line.trim());
        
        let msg: RelayMessage = serde_json::from_str(&line)
            .map_err(|e| anyhow!("Failed to parse server message: {} - {}", e, line.trim()))?;
        
        match msg {
            RelayMessage::Registered { your_public_addr, your_role, session_id: sess_id, server_time, probe_port, needs_probing, .. } => {
                if let Some((ip, port)) = RelayMessage::parse_addr(&your_public_addr) {
                    // Store our public port and calculate delta
                    let public_port = port;
                    session.our_public_port = Some(public_port);
                    session.our_delta = public_port as i32 - local_port as i32;
                    session.port_preserved = session.our_delta == 0;
                    
                    info!("✓ Registered! Public address: {}:{}", ip, port);
                    info!("  Role: {}, Session: {}", your_role, sess_id);
                    info!("  Local port: {} → NAT port: {}", local_port, public_port);
                    
                    // Show port delta analysis
                    let needs_probe = needs_probing.unwrap_or(false);
                    if session.port_preserved {
                        info!("  ✅ Port Preserved! (delta=0) - NAT is friendly");
                    } else {
                        warn!("  ⚠️ Port Changed! Delta = {} (NAT may be Symmetric)", session.our_delta);
                        if needs_probe {
                            info!("     Will do NAT probing to determine port range...");
                        }
                    }
                    
                    // Calculate clock offset if server_time is provided
                    if let Some(srv_time) = server_time {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap()
                            .as_secs_f64();
                        let rtt = now - register_sent_at;
                        session.time_offset = srv_time - (register_sent_at + rtt / 2.0);
                        
                        if session.time_offset.abs() > 0.1 {
                            info!("⏱️ Clock offset: {:.3}s (local {} server)", 
                                session.time_offset,
                                if session.time_offset > 0.0 { "behind" } else { "ahead of" });
                        }
                        if session.time_offset.abs() > 60.0 {
                            warn!("⚠️ Large clock offset detected! Consider syncing system time.");
                        }
                    }
                    
                    // Do NAT probing if server provided probe_port AND needs_probing is true
                    if needs_probe {
                        if let Some(pp) = probe_port {
                            // Build probe server address using the relay server IP
                            let probe_addr = SocketAddr::new(server_sock_addr.ip(), pp);
                            if let Err(e) = do_nat_probing(probe_addr, session_id, probe_count).await {
                                warn!("NAT probing failed: {} - continuing anyway", e);
                            }
                        }
                    }
                    
                    // Send probes_complete message to server
                    info!("Sending probes_complete...");
                    let probes_complete_msg = r#"{"type":"probes_complete"}"#.to_string() + "\n";
                    writer.write_all(probes_complete_msg.as_bytes()).await?;
                    writer.flush().await?;
                    info!("✓ Probes complete sent");
                } else {
                    warn!("Could not parse public address");
                }
            }
            
            RelayMessage::PeerInfo { peer_public_addr, peer_local_port, peer_addresses, your_role: _, same_network, peer_nat_analysis, peer_port_analyses } => {
                if let Some((ip, port)) = RelayMessage::parse_addr(&peer_public_addr) {
                    let addr: SocketAddr = format!("{}:{}", ip, port).parse()?;
                    session.peer_public_addr = Some(addr);
                    session.peer_addresses = peer_addresses.into_iter()
                        .map(|pa| pa.into())
                        .collect();
                    session.same_network = same_network;
                    session.peer_nat_analysis = peer_nat_analysis.clone();
                    session.peer_port_analyses = peer_port_analyses.clone();
                    if let Some(port_analyses) = &peer_port_analyses {
                        debug!("Peer per-port NAT analyses: {}", port_analyses.len());
                        for entry in port_analyses {
                            let nat = &entry.nat_analysis;
                            debug!(
                                "  local_port={} pattern={} predicted={} error={} scan={}..{} needs_scan={} range={}",
                                entry.local_port,
                                nat.pattern_type,
                                nat.predicted_port,
                                nat.error_range,
                                nat.scan_start,
                                nat.scan_end,
                                nat.needs_scan,
                                nat.port_range,
                            );
                        }
                    }
                    
                    let addr_count = session.peer_addresses.len();
                    
                    info!("✓ Peer info received!");
                    info!("  Peer: {} (local port {})", addr, peer_local_port);
                    
                    // Show peer's NAT analysis
                    if let Some(nat) = &peer_nat_analysis {
                        info!("  NAT: {} | Range: {} ports", nat.description(), nat.port_range);
                        if nat.needs_scan {
                            info!("  🔍 Will scan {} ports ({}..{})", nat.scan_count(), nat.scan_start, nat.scan_end);
                        }
                    } else if addr_count == 1 {
                        info!("  NAT: ✅ Port-Preserving (single address)");
                    }
                    
                    // Send READY signal
                    let ready = ReadyMessage::default();
                    let msg = serde_json::to_string(&ready)? + "\n";
                    writer.write_all(msg.as_bytes()).await?;
                    writer.flush().await?;
                    info!("✓ READY sent, waiting for GO...");
                }
            }
            
            RelayMessage::Go { start_at, message } => {
                session.start_at = Some(start_at);
                info!("✓ GO signal received!");
                info!("  Start at: {} (in {:.2}s)", start_at, start_at - std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs_f64());
                if !message.is_empty() {
                    info!("  Message: {}", message);
                }
                
                // Reunite the stream for returning
                let stream = reader.into_inner().reunite(writer)?;
                return Ok((stream, session));
            }
            
            RelayMessage::Ping {} => {
                // Respond with keepalive
                let msg = r#"{"type":"keepalive"}"# .to_string() + "\n";
                writer.write_all(msg.as_bytes()).await?;
                writer.flush().await?;
                debug!("Responded to ping");
            }
            
            RelayMessage::KeepaliveAck {} => {
                debug!("Keepalive acknowledged");
            }
            
            RelayMessage::Error { message } => {
                return Err(anyhow!("Server error: {}", message));
            }
        }
    }
}

/// Run the sender
async fn run_sender(
    server_addr: &str,
    session_id: &str,
    file_path: &str,
    timeout: Duration,
    probe_count: u32,
    prediction_mode: PredictionMode,
    prediction_range_extra_pct: f64,
    tcp_connections: u8,
    scan_budget: u32,
) -> Result<()> {
    debug!("Multi-TCP: connections={} scan_budget={}", tcp_connections, scan_budget);
    // FIRST: Calculate SHA256 BEFORE connecting to relay
    // This can take a long time for large files, and we don't want to
    // block the other peer or timeout while hashing
    info!("Calculating SHA256 hash (this may take a while for large files)...");
    let (sha256, file_size) = calculate_sha256(file_path).await?;
    info!("SHA256: {}", transfer::sha256_to_hex(&sha256));
    info!("File size: {:.2} MB", file_size as f64 / (1024.0 * 1024.0));
    info!("");

    if tcp_connections > 1 {
        return run_sender_multi(
            server_addr,
            session_id,
            file_path,
            file_size,
            sha256,
            timeout,
            probe_count,
            prediction_mode,
            prediction_range_extra_pct,
            tcp_connections,
            scan_budget,
        ).await;
    }
    
    debug!("Multi-TCP: connections={} scan_budget={}", tcp_connections, scan_budget);
    // Get local port for hole punching
    let local_port = get_free_port()?;
    info!("Using local port: {}", local_port);
    
    // Run relay protocol to get peer info and GO signal
    let (_relay_stream, session) = run_relay_protocol(
        server_addr,
        session_id,
        "sender",
        local_port,
        None,
        tcp_connections,
        timeout,
        probe_count,
        prediction_mode,
        prediction_range_extra_pct,
    ).await?;
    
    // We can close relay connection now - we have all the info we need
    // (The relay keeps the connection open but we don't need it anymore)
    
    let peer_addr = session.peer_public_addr
        .ok_or_else(|| anyhow!("No peer address received"))?;
    let start_at = session.start_at
        .ok_or_else(|| anyhow!("No start_at received"))?;
    
    // Perform hole punch with clock offset compensation
    let config = HolePunchConfig {
        local_port,
        peer_primary_addr: peer_addr,
        peer_addresses: session.peer_addresses,
        start_at,
        timeout,
        same_network: session.same_network,
        time_offset: session.time_offset,
    };
    
    let stream = match do_hole_punch(config).await? {
        HolePunchResult::Success(stream) => stream,
        HolePunchResult::Timeout => {
            return Err(anyhow!("Hole punch timed out - could not establish connection"));
        }
    };
    
    info!("✅ Direct P2P connection established!");
    info!("   Local:  {}", stream.local_addr()?);
    info!("   Remote: {}", stream.peer_addr()?);
    
    // Start file transfer with pre-calculated hash
    let mut sender = TcpSender::new_with_hash(stream, file_path, file_size, sha256);
    sender.run().await
}

/// Run the receiver
async fn run_receiver(
    server_addr: &str,
    session_id: &str,
    timeout: Duration,
    probe_count: u32,
    prediction_mode: PredictionMode,
    prediction_range_extra_pct: f64,
    tcp_connections: u8,
    scan_budget: u32,
) -> Result<()> {
    if tcp_connections > 1 {
        return run_receiver_multi(
            server_addr,
            session_id,
            timeout,
            probe_count,
            prediction_mode,
            prediction_range_extra_pct,
            tcp_connections,
            scan_budget,
        ).await;
    }

    // Get local port for hole punching
    let local_port = get_free_port()?;
    info!("Using local port: {}", local_port);
    
    // Run relay protocol to get peer info and GO signal
    let (_relay_stream, session) = run_relay_protocol(
        server_addr,
        session_id,
        "receiver",
        local_port,
        None,
        tcp_connections,
        timeout,
        probe_count,
        prediction_mode,
        prediction_range_extra_pct,
    ).await?;
    
    let peer_addr = session.peer_public_addr
        .ok_or_else(|| anyhow!("No peer address received"))?;
    let start_at = session.start_at
        .ok_or_else(|| anyhow!("No start_at received"))?;
    
    // Perform hole punch with clock offset compensation
    let config = HolePunchConfig {
        local_port,
        peer_primary_addr: peer_addr,
        peer_addresses: session.peer_addresses,
        start_at,
        timeout,
        same_network: session.same_network,
        time_offset: session.time_offset,
    };
    
    let stream = match do_hole_punch(config).await? {
        HolePunchResult::Success(stream) => stream,
        HolePunchResult::Timeout => {
            return Err(anyhow!("Hole punch timed out - could not establish connection"));
        }
    };
    
    info!("✅ Direct P2P connection established!");
    info!("   Local:  {}", stream.local_addr()?);
    info!("   Remote: {}", stream.peer_addr()?);
    
    // Start file transfer
    let mut receiver = TcpReceiver::new(stream);
    receiver.run().await
}


async fn run_sender_multi(
    server_addr: &str,
    session_id: &str,
    file_path: &str,
    file_size: u64,
    sha256: [u8; 32],
    timeout: Duration,
    probe_count: u32,
    prediction_mode: PredictionMode,
    prediction_range_extra_pct: f64,
    tcp_connections: u8,
    scan_budget: u32,
) -> Result<()> {
    info!("Multi-TCP enabled with {} connections", tcp_connections);

    let control_port = get_free_port()?;
    let local_ports = collect_local_ports(tcp_connections, control_port)?;
    info!("Using control port: {}", control_port);

    let (_relay_stream, session) = run_relay_protocol(
        server_addr,
        session_id,
        "sender",
        control_port,
        Some(&local_ports),
        tcp_connections,
        timeout,
        probe_count,
        prediction_mode,
        prediction_range_extra_pct,
    ).await?;

    let peer_addr = session.peer_public_addr
        .ok_or_else(|| anyhow!("No peer address received"))?;
    let relay_start_at = session.start_at
        .ok_or_else(|| anyhow!("No start_at received"))?;

    let config = HolePunchConfig {
        local_port: control_port,
        peer_primary_addr: peer_addr,
        peer_addresses: session.peer_addresses,
        start_at: relay_start_at,
        timeout,
        same_network: session.same_network,
        time_offset: session.time_offset,
    };

    let mut control_stream = match do_hole_punch(config).await? {
        HolePunchResult::Success(stream) => stream,
        HolePunchResult::Timeout => {
            return Err(anyhow!("Hole punch timed out - could not establish control connection"));
        }
    };

    info!("Control connection established");

    let start_at = current_timestamp() + MULTI_START_DELAY_SEC;
    let retry_limit = 3u8;

    let peer_local_ports = multi_handshake_sender(
        &mut control_stream,
        tcp_connections,
        retry_limit,
        start_at,
        &local_ports,
    ).await?;

    let peer_ip = peer_addr.ip().to_string();
    let peer_public_port = peer_addr.port();
    let nat = session.peer_nat_analysis.as_ref();

    let mut candidate_lists = Vec::new();
    let mut conn_ids = Vec::new();
    for conn_id in 1..tcp_connections {
        let peer_local_port = *peer_local_ports
            .get(conn_id as usize)
            .ok_or_else(|| anyhow!("Missing peer local port for conn_id {}", conn_id))?;
        let port_analysis = session
            .peer_port_analyses
            .as_ref()
            .and_then(|items| items.iter().find(|item| item.local_port == peer_local_port))
            .map(|item| &item.nat_analysis);
        let candidates = build_peer_addresses_for_conn(
            &peer_ip,
            peer_public_port,
            peer_local_port,
            prediction_mode,
            prediction_range_extra_pct,
            nat,
            port_analysis,
            false,
        );
        candidate_lists.push(candidates);
        conn_ids.push(conn_id);
    }

    let candidate_lists = apply_scan_budget(candidate_lists, scan_budget)?;

    let mut configs = Vec::new();
    for (idx, conn_id) in conn_ids.iter().enumerate() {
        let list = &candidate_lists[idx];
        if list.is_empty() {
            return Err(anyhow!("No candidate ports for conn_id {}", conn_id));
        }
        let primary = list[0].to_socket_addr()?;
        let extras = list[1..].to_vec();
        let config = HolePunchConfig {
            local_port: local_ports[*conn_id as usize],
            peer_primary_addr: primary,
            peer_addresses: extras,
            start_at,
            timeout,
            same_network: session.same_network,
            time_offset: 0.0,
        };
        configs.push((*conn_id, config));
    }

    let mut extra_streams = Vec::new();
    if !configs.is_empty() {
        extra_streams = hole_punch::do_hole_punch_multi(configs, retry_limit).await?;
        for (conn_id, stream) in extra_streams.iter_mut() {
            multi_hello_sender(stream, tcp_connections, *conn_id).await?;
        }
    }

    for conn_id in 0..tcp_connections {
        send_multi_ready(&mut control_stream, conn_id).await?;
    }

    let mut ready = HashSet::new();
    while ready.len() < tcp_connections as usize {
        let conn_id = tokio::time::timeout(Duration::from_secs(30), read_multi_ready(&mut control_stream)).await
            .map_err(|_| anyhow!("Timeout waiting for MULTI_READY"))??;
        ready.insert(conn_id);
    }

    send_multi_start(&mut control_stream).await?;

    let mut streams: Vec<Option<TcpStream>> = Vec::with_capacity(tcp_connections as usize);
    streams.resize_with(tcp_connections as usize, || None);
    streams[0] = Some(control_stream);
    for (conn_id, stream) in extra_streams {
        if let Some(slot) = streams.get_mut(conn_id as usize) {
            *slot = Some(stream);
        }
    }

    let mut final_streams = Vec::new();
    for (idx, item) in streams.into_iter().enumerate() {
        let stream = item.ok_or_else(|| anyhow!("Missing stream for conn_id {}", idx))?;
        final_streams.push(stream);
    }

    let mut sender = MultiSender::new_with_hash(final_streams, file_path, file_size, sha256);
    sender.run().await
}

async fn run_receiver_multi(
    server_addr: &str,
    session_id: &str,
    timeout: Duration,
    probe_count: u32,
    prediction_mode: PredictionMode,
    prediction_range_extra_pct: f64,
    tcp_connections: u8,
    scan_budget: u32,
) -> Result<()> {
    info!("Multi-TCP enabled with {} connections", tcp_connections);

    let control_port = get_free_port()?;
    let local_ports = collect_local_ports(tcp_connections, control_port)?;
    info!("Using control port: {}", control_port);

    let (_relay_stream, session) = run_relay_protocol(
        server_addr,
        session_id,
        "receiver",
        control_port,
        Some(&local_ports),
        tcp_connections,
        timeout,
        probe_count,
        prediction_mode,
        prediction_range_extra_pct,
    ).await?;

    let peer_addr = session.peer_public_addr
        .ok_or_else(|| anyhow!("No peer address received"))?;
    let relay_start_at = session.start_at
        .ok_or_else(|| anyhow!("No start_at received"))?;

    let config = HolePunchConfig {
        local_port: control_port,
        peer_primary_addr: peer_addr,
        peer_addresses: session.peer_addresses,
        start_at: relay_start_at,
        timeout,
        same_network: session.same_network,
        time_offset: session.time_offset,
    };

    let mut control_stream = match do_hole_punch(config).await? {
        HolePunchResult::Success(stream) => stream,
        HolePunchResult::Timeout => {
            return Err(anyhow!("Hole punch timed out - could not establish control connection"));
        }
    };

    info!("Control connection established");

    let plan = multi_handshake_receiver(&mut control_stream, tcp_connections, &local_ports).await?;
    let start_at = plan.start_at;
    let retry_limit = plan.retry_limit;
    let peer_local_ports = plan.peer_local_ports;

    let peer_ip = peer_addr.ip().to_string();
    let peer_public_port = peer_addr.port();
    let nat = session.peer_nat_analysis.as_ref();

    let mut candidate_lists = Vec::new();
    let mut conn_ids = Vec::new();
    for conn_id in 1..tcp_connections {
        let peer_local_port = *peer_local_ports
            .get(conn_id as usize)
            .ok_or_else(|| anyhow!("Missing peer local port for conn_id {}", conn_id))?;
        let port_analysis = session
            .peer_port_analyses
            .as_ref()
            .and_then(|items| items.iter().find(|item| item.local_port == peer_local_port))
            .map(|item| &item.nat_analysis);
        let candidates = build_peer_addresses_for_conn(
            &peer_ip,
            peer_public_port,
            peer_local_port,
            prediction_mode,
            prediction_range_extra_pct,
            nat,
            port_analysis,
            false,
        );
        candidate_lists.push(candidates);
        conn_ids.push(conn_id);
    }

    let candidate_lists = apply_scan_budget(candidate_lists, scan_budget)?;

    let mut configs = Vec::new();
    for (idx, conn_id) in conn_ids.iter().enumerate() {
        let list = &candidate_lists[idx];
        if list.is_empty() {
            return Err(anyhow!("No candidate ports for conn_id {}", conn_id));
        }
        let primary = list[0].to_socket_addr()?;
        let extras = list[1..].to_vec();
        let config = HolePunchConfig {
            local_port: local_ports[*conn_id as usize],
            peer_primary_addr: primary,
            peer_addresses: extras,
            start_at,
            timeout,
            same_network: session.same_network,
            time_offset: 0.0,
        };
        configs.push((*conn_id, config));
    }

    let mut extra_streams = Vec::new();
    if !configs.is_empty() {
        extra_streams = hole_punch::do_hole_punch_multi(configs, retry_limit).await?;
        for (conn_id, stream) in extra_streams.iter_mut() {
            multi_hello_receiver(stream, tcp_connections, *conn_id).await?;
        }
    }

    for conn_id in 0..tcp_connections {
        send_multi_ready(&mut control_stream, conn_id).await?;
    }

    tokio::time::timeout(Duration::from_secs(30), read_multi_start(&mut control_stream)).await
        .map_err(|_| anyhow!("Timeout waiting for MULTI_START"))??;

    let mut streams: Vec<Option<TcpStream>> = Vec::with_capacity(tcp_connections as usize);
    streams.resize_with(tcp_connections as usize, || None);
    streams[0] = Some(control_stream);
    for (conn_id, stream) in extra_streams {
        if let Some(slot) = streams.get_mut(conn_id as usize) {
            *slot = Some(stream);
        }
    }

    let mut final_streams = Vec::new();
    for (idx, item) in streams.into_iter().enumerate() {
        let stream = item.ok_or_else(|| anyhow!("Missing stream for conn_id {}", idx))?;
        final_streams.push(stream);
    }

    let mut receiver = MultiReceiver::new(final_streams);
    receiver.run().await
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    
    // Set up logging
    let level = if args.debug { Level::DEBUG } else { Level::INFO };
    let _subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .init();

    if args.probe_debug {
        run_probe_debug(&args.server, &args.session_id, args.probe_count).await?;
        return Ok(());
    }
    
    // Parse and set chunk size
    let chunk_size = parse_chunk_size(&args.chunk)?;
    if chunk_size < 64 * 1024 {
        return Err(anyhow!("Chunk size must be at least 64KB"));
    }
    if chunk_size > 16 * 1024 * 1024 {
        return Err(anyhow!("Chunk size must be at most 16MB"));
    }
    set_chunk_size(chunk_size);
    
    info!("TCP File Transfer Client v{} (ICE)", APP_VERSION);
    info!("===================================");
    info!("TCP connections: {}", args.tcp_connections);
    if args.tcp_connections > 1 {
        if args.scan_budget == 0 {
            info!("Scan budget: unlimited");
        } else {
            info!("Scan budget: {}", args.scan_budget);
        }
    }
    debug!("Chunk: {} KB | Buffer: 8MB | TCP Buffer: 16MB", chunk_size / 1024);
    
    // Validate arguments
    if matches!(args.mode, Mode::Send) && args.file.is_none() {
        return Err(anyhow!("--file required for send mode"));
    }
    
    let allowed_connections = [1u8, 2, 4, 8];
    if !allowed_connections.contains(&args.tcp_connections) {
        return Err(anyhow!("--tcp-connections must be one of 1,2,4,8"));
    }
    
    let timeout = Duration::from_secs(args.timeout);
    
    // Handle Ctrl+C
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        error!("🛑 Ctrl+C received, exiting...");
        std::process::exit(1);
    });
    
    // Run based on mode
    match args.mode {
        Mode::Send => {
            let file_path = args.file.as_ref().unwrap();
            
            // Check file exists
            if !std::path::Path::new(file_path).exists() {
                return Err(anyhow!("File not found: {}", file_path));
            }
            
            info!("Mode: SEND");
            info!("File: {}", file_path);
            info!("Session: {}", args.session_id);
            info!("");
            
            run_sender(
                &args.server,
                &args.session_id,
                file_path,
                timeout,
                args.probe_count,
                args.prediction_mode,
                args.prediction_range_extra_pct,
                args.tcp_connections,
                args.scan_budget,
            ).await
        }
        Mode::Receive => {
            info!("Mode: RECEIVE");
            info!("Session: {}", args.session_id);
            info!("");
            
            run_receiver(
                &args.server,
                &args.session_id,
                timeout,
                args.probe_count,
                args.prediction_mode,
                args.prediction_range_extra_pct,
                args.tcp_connections,
                args.scan_budget,
            ).await
        }
    }
}

async fn run_probe_debug(server_addr: &str, session_id: &str, count: u32) -> Result<()> {
    let probe_addr = derive_probe_addr(server_addr)?;

    println!("PROBE DEBUG MODE");
    println!("Server: {}", server_addr);
    println!("Probe:  {}", probe_addr);
    println!("Session: {}", session_id);
    println!("Count: {}", count);
    println!();

    if count == 0 {
        println!("No probes requested.");
        return Ok(());
    }

    struct ProbeSample {
        nat_port: u16,
        delta: i32,
    }

    let mut samples: Vec<ProbeSample> = Vec::new();
    let mut failures = 0u32;

    for i in 0..count {
        match TcpStream::connect(probe_addr).await {
            Ok(stream) => {
                let local_port = stream.local_addr().map(|a| a.port()).unwrap_or(0);
                let (reader, mut writer) = stream.into_split();
                let mut reader = BufReader::new(reader);

                let probe = ProbeMessage::new(session_id, local_port, i);
                let msg = serde_json::to_string(&probe)? + "\n";
                if writer.write_all(msg.as_bytes()).await.is_err() {
                    failures += 1;
                    continue;
                }
                let _ = writer.flush().await;

                let mut line = String::new();
                match tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut line)).await {
                    Ok(Ok(0)) => {
                        failures += 1;
                    }
                    Ok(Ok(_n)) => {
                        let v: serde_json::Value = serde_json::from_str(&line)
                            .map_err(|e| anyhow!("Failed to parse probe_ack: {}", e))?;
                        let nat_port = v.get("your_nat_port").and_then(|p| p.as_u64())
                            .ok_or_else(|| anyhow!("probe_ack missing your_nat_port"))? as u16;
                        let delta = nat_port as i32 - local_port as i32;
                        samples.push(ProbeSample { nat_port, delta });
                    }
                    _ => {
                        failures += 1;
                    }
                }
            }
            Err(_) => {
                failures += 1;
            }
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    if samples.is_empty() {
        println!("No probe acknowledgements received.");
        return Ok(());
    }

    println!("Samples received: {}", samples.len());

    let nat_ports: Vec<u16> = samples.iter().map(|s| s.nat_port).collect();
    let mut deltas: Vec<i32> = samples.iter().map(|s| s.delta).collect();

    let min_nat = *nat_ports.iter().min().unwrap();
    let max_nat = *nat_ports.iter().max().unwrap();
    let range_nat = max_nat - min_nat;

    let min_delta = *deltas.iter().min().unwrap();
    let max_delta = *deltas.iter().max().unwrap();
    let median_delta = median_i32(&mut deltas);
    let mean_delta = deltas.iter().map(|d| *d as f64).sum::<f64>() / deltas.len() as f64;
    let var_delta = deltas.iter().map(|d| {
        let diff = *d as f64 - mean_delta;
        diff * diff
    }).sum::<f64>() / deltas.len() as f64;
    let stdev_delta = var_delta.sqrt();

    let unique_nat: HashSet<u16> = nat_ports.iter().cloned().collect();

    println!("NAT ports: min={} max={} range={} unique={}", min_nat, max_nat, range_nat, unique_nat.len());
    println!("Delta: min={} max={} median={:.1} stdev={:.2}", min_delta, max_delta, median_delta, stdev_delta);
    let max_dev = deltas.iter()
        .map(|d| ((*d as f64) - median_delta).abs())
        .fold(0.0, f64::max);
    let jitter = (stdev_delta * 2.0).round().max(2.0);
    let error_range = (max_dev + jitter).round() as i32;
    let delta_spread = max_delta - min_delta;
    let port_preserved = samples.iter().all(|s| s.delta == 0);
    let nat_type = if port_preserved {
        "port_preserved"
    } else if delta_spread == 0 {
        "constant_delta"
    } else if error_range <= 5 {
        "small_delta_range"
    } else if error_range <= 30 {
        "medium_delta_range"
    } else if error_range <= 100 {
        "large_delta_range"
    } else {
        "random_like"
    };
    println!("Estimated NAT type: {}", nat_type);
    println!();

    if failures > 0 {
        println!("Probe failures: {}/{}", failures, count);
    }

    Ok(())
}

fn derive_probe_addr(server_addr: &str) -> Result<SocketAddr> {
    let (host, port) = parse_host_port(server_addr)?;
    if port <= 1 {
        return Err(anyhow!("Server port {} is too low to derive probe port", port));
    }
    let resolved = resolve_host_port(&host, port)?;
    Ok(SocketAddr::new(resolved.ip(), port - 1))
}

fn median_i32(values: &mut Vec<i32>) -> f64 {
    values.sort_unstable();
    let len = values.len();
    if len == 0 {
        return 0.0;
    }
    if len % 2 == 1 {
        values[len / 2] as f64
    } else {
        let a = values[(len / 2) - 1] as f64;
        let b = values[len / 2] as f64;
        (a + b) / 2.0
    }
}
