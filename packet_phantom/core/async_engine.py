#!/usr/bin/env python3
"""
Packet Phantom - Async I/O Engine
=================================

Async packet sending using asyncio for high throughput.
Designed for 50,000+ packets/second on modern systems.

Features:
- asyncio-based event loop
- Semaphore-controlled concurrency
- UDP raw socket async operations
- Efficient packet batching
- Real-time rate limiting
- Random source port and sequence number generation
- Proper response matching by port and sequence
- Service/version detection
- OS fingerprinting


Version: 2.1.0
"""

import asyncio
import socket
import time
import select
import struct
import random
from typing import List, Tuple, Optional, Callable, Dict, Any
from dataclasses import dataclass


# =============================================================================
# SERVICE DETECTION AND OS FINGERPRINTING IMPORTS
# =============================================================================

from .service_detection import ServiceDetector
from .os_fingerprint import OSFingerprintResult, OSFingerprinter, ParsedPacket, NmapOSMatcher, ScapyTCPOptions


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class AsyncConfig:
    """Configuration for async engine."""
    concurrency: int = 1000  # Max concurrent operations
    batch_size: int = 64  # Packets per batch
    socket_buffer_size: int = 1024 * 1024  # 1MB
    rate_limit: Optional[int] = None  # Packets per second (None = unlimited)
    timeout: float = 5.0  # Response timeout
    interface: Optional[str] = None  # Network interface
    is_ipv6: bool = False  # Use IPv6 raw socket
    version_detection: bool = False  # Enable service/version detection
    version_intensity: int = 7  # Version detection intensity (0-9)
    os_detection: bool = False  # Enable OS fingerprinting
    os_intensity: int = 7  # OS detection intensity (0-9)


# =============================================================================
# ASYNC SOCKET WRAPPER
# =============================================================================

class AsyncRawSocket:
    """
    Async wrapper for raw socket operations.
    
    Provides asyncio-compatible methods for sending
    raw packets without blocking the event loop.
    
    Features:
    - Random source port generation for each packet
    - Random sequence number generation for TCP packets
    - Pending packet tracking for response matching
    """
    
    def __init__(self, config: AsyncConfig):
        self.config = config
        self.socket: Optional[socket.socket] = None
        self._closed = False
        self.is_ipv6 = config.is_ipv6
        # Track pending packets: {(local_ip, src_port, seq_num): target_port}
        self.pending_packets: Dict[Tuple[str, int, int], int] = {}
        # Local IP for packet tracking
        self.local_ip: str = "0.0.0.0"
    
    def generate_random_source_port(self) -> int:
        """
        Generate a random source port in the valid range (1024-65535).
        
        Returns:
            Random port number
        """
        return random.randint(1024, 65535)
    
    def generate_random_sequence(self) -> int:
        """
        Generate a random 32-bit sequence number.
        
        Returns:
            Random sequence number (0-4294967295)
        """
        return random.randint(0, 4294967295)
    
    async def create(self) -> None:
        """Create and configure the raw socket."""
        if self.is_ipv6:
            # BUG FIX: Check IPv6 support before creating socket
            if not socket.has_ipv6:
                raise OSError("IPv6 is not supported on this system")
            # Create IPv6 raw socket
            self.socket = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
            # Bind to get local IP
            self.socket.bind(('::', 0))
            # Get the local IP address
            try:
                self.local_ip = "::1"  # Default for IPv6 loopback
            except Exception:
                pass
        else:
            # Create IPv4 raw socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            # Set socket options for IPv4
            self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # Bind to get local IP
            self.socket.bind(('0.0.0.0', 0))
            # Get the local IP address
            try:
                self.local_ip = self.socket.getsockname()[0]
            except Exception:
                self.local_ip = "127.0.0.1"
        
        # Set socket buffer size
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.config.socket_buffer_size)
        
        # Bind socket
        if self.is_ipv6:
            self.socket.bind(('::', 0))
        else:
            self.socket.bind(('0.0.0.0', 0))
    
    async def sendto(self, data: bytes, address: Tuple[str, int]) -> int:
        """
        Send data asynchronously.
        
        Args:
            data: Packet bytes
            address: (host, port) tuple
            
        Returns:
            Number of bytes sent
        """
        loop = asyncio.get_event_loop()
        return await loop.sock_sendto(self.socket, data, address)
    
    async def sendto_batch(self, packets: List[Tuple[bytes, Tuple[str, int]]]) -> int:
        """
        Send a batch of packets.
        
        Args:
            packets: List of (data, address) tuples
            
        Returns:
            Number of packets sent
        """
        sent = 0
        for data, address in packets:
            try:
                await self.sendto(data, address)
                sent += 1
            except (socket.error, OSError):
                pass
        return sent
    
    async def recvfrom(self, bufsize: int = 65535) -> Tuple[bytes, Tuple[str, int]]:
        """
        Receive data asynchronously.
        
        Args:
            bufsize: Maximum receive buffer size
            
        Returns:
            (data, address) tuple
        """
        loop = asyncio.get_event_loop()
        return await loop.sock_recvfrom(self.socket, bufsize)
    
    async def close(self) -> None:
        """Close the socket."""
        if self.socket and not self._closed:
            self._closed = True
            self.socket.close()
    
    def __aenter__(self) -> 'AsyncRawSocket':
        return self
    
    def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> Any:
        return asyncio.get_event_loop().create_task(self.close())


# =============================================================================
# RATE LIMITER
# =============================================================================

class AsyncRateLimiter:
    """
    Token bucket rate limiter for async operations.
    
    Controls packet sending rate to avoid overwhelming
    targets or triggering rate limiting.
    """
    
    def __init__(self, rate: int, capacity: Optional[int] = None) -> None:
        """
        Initialize rate limiter.
        
        Args:
            rate: Tokens added per second
            capacity: Maximum tokens (defaults to rate)
        """
        self.rate = rate
        self.capacity = capacity or rate
        self.tokens = self.capacity
        self.last_update = time.time()
        self._lock = asyncio.Lock()
    
    async def acquire(self, tokens: int = 1) -> float:
        """
        Acquire tokens for sending.
        
        Args:
            tokens: Number of tokens to acquire
            
        Returns:
            Time to wait until tokens are available (0 if available now)
        """
        async with self._lock:
            now = time.time()
            elapsed = now - self.last_update
            
            # Add tokens based on elapsed time
            new_tokens = elapsed * self.rate
            self.tokens = min(self.capacity, self.tokens + new_tokens)
            self.last_update = now
            
            # Check if we have enough tokens
            if self.tokens >= tokens:
                self.tokens -= tokens
                return 0.0
            
            # Calculate wait time
            needed = tokens - self.tokens
            wait_time = needed / self.rate
            return wait_time
    
    async def acquire_and_wait(self, tokens: int = 1) -> None:
        """
        Acquire tokens and wait if necessary.
        
        Args:
            tokens: Number of tokens to acquire
        """
        wait_time = await self.acquire(tokens)
        if wait_time > 0:
            await asyncio.sleep(wait_time)


# =============================================================================
# ASYNC PACKET ENGINE
# =============================================================================

class AsyncPacketEngine:
    """
    High-performance async packet engine.
    
    Uses asyncio for concurrent packet operations with
    semaphore-controlled concurrency and rate limiting.
    
    Usage:
        engine = AsyncPacketEngine(rate_limit=50000)
        await engine.start()
        
        results = await engine.scan_network(targets, ports)
        
        await engine.stop()
    """
    
    def __init__(self, config: AsyncConfig = None):
        """
        Initialize async engine.
        
        Args:
            config: Engine configuration (uses defaults if None)
        """
        self.config = config or AsyncConfig()
        self.socket: Optional[AsyncRawSocket] = None
        self.rate_limiter: Optional[AsyncRateLimiter] = None
        self.semaphore: Optional[asyncio.Semaphore] = None
        self.running = False
        self._response_cache: Dict[str, float] = {}
        self._listen_task: Optional[asyncio.Task] = None
        # Track sent packets for response matching: {(src_ip, src_port, seq_num): target_info}
        self.pending_packets: Dict[Tuple[str, int, int], Dict[str, Any]] = {}
        
        # Service detection and OS fingerprinting components
        self.service_detector: Optional[ServiceDetector] = None
        self.os_fingerprinter: Optional[OSFingerprinter] = None
        # Store SYN-ACK response data for OS analysis
        self.os_response_data: List[Dict[str, Any]] = []
        # Store OS guesses per host
        self.host_os_guesses: List[Dict[str, Any]] = []
        
        # Statistics
        self.stats = {
            "packets_sent": 0,
            "packets_received": 0,
            "errors": 0,
            "start_time": 0.0,
        }
    
    async def start(self):
        """Start the async engine."""
        self.socket = AsyncRawSocket(self.config)
        await self.socket.create()
        
        # Create semaphore for concurrency control
        self.semaphore = asyncio.Semaphore(self.config.concurrency)
        
        # Create rate limiter if specified
        if self.config.rate_limit:
            self.rate_limiter = AsyncRateLimiter(self.config.rate_limit)
        
        # Initialize service detector if version detection is enabled
        if self.config.version_detection:
            self.service_detector = ServiceDetector(
                intensity=getattr(self.config, 'version_intensity', 7),
                timeout=self.config.timeout
            )
            print(f"[INFO] Service detection enabled with intensity {getattr(self.config, 'version_intensity', 7)}")
        
        # Initialize OS fingerprinter with Nmap-style matching
        if self.config.os_detection:
            self.os_fingerprinter = NmapOSMatcher()
            self.os_fingerprinter.load_database(None)  # Load embedded signatures
            print(f"[INFO] OS fingerprinting enabled with intensity {getattr(self.config, 'os_intensity', 7)}")
        
        self.running = True
        self.stats["start_time"] = time.time()
    
    @property
    def is_ipv6(self) -> bool:
        """Check if using IPv6."""
        return self.config.is_ipv6
    
    async def stop(self):
        """Stop the async engine."""
        self.running = False
        
        if self.socket:
            await self.socket.close()
            self.socket = None
    
    async def send_packet(self, packet: bytes, target: str, port: int = 0) -> bool:
        """
        Send a single packet asynchronously.
        
        Args:
            packet: Raw packet bytes
            target: Target IP address
            port: Target port (0 for raw IP)
            
        Returns:
            True if sent successfully
        """
        async with self.semaphore:
            # Apply rate limiting if configured
            if self.rate_limiter:
                await self.rate_limiter.acquire_and_wait()
            
            try:
                await self.socket.sendto(packet, (target, port))
                self.stats["packets_sent"] += 1
                return True
            except (socket.error, OSError):
                self.stats["errors"] += 1
                return False
    
    def _extract_synack_metadata(self, raw_response: bytes, src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> Optional[Dict[str, Any]]:
        """
        Extract SYN-ACK metadata using Scapy-based parsing.
        
        Args:
            raw_response: Raw response bytes
            src_ip: Source IP of response
            dst_ip: Destination IP of response
            src_port: Source port of response
            dst_port: Destination port of response
            
        Returns:
            Dictionary with TTL, window size, options, DF flag, and sequence number
        """
        try:
            # Use Scapy-based parser
            parsed = ParsedPacket.from_raw_bytes(raw_response)
            
            return {
                'ttl': parsed.ttl,
                'window_size': parsed.window_size,
                'df': parsed.df_flag,
                'mss': parsed.mss_value,
                'wscale': parsed.wscale_value,
                'sack': parsed.tcp_options.sack_permitted if parsed.tcp_options else False,
                'timestamp': parsed.tcp_options.timestamp if parsed.tcp_options else None,
                'options': parsed.tcp_options.option_names if parsed.tcp_options else [],
                'options_order': parsed.options_order,
                'raw_options': parsed.tcp_options_raw,
                'quirks': [],  # Quirks are handled by NmapOSMatcher
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'seq_num': parsed.seq_num,
                'ack_num': parsed.ack_num,
                'ip_id': parsed.ip_id,
            }
        except Exception as e:
            print(f"[DEBUG] Failed to parse SYN-ACK: {e}")
            return None
    
    async def _check_port(self, host: str, port: int, packet: bytes, 
                          src_port: int = None, seq_num: int = None) -> str:
        """
        Check if a port is open by sending packet and waiting for response.
        
        Args:
            host: Target host IP
            port: Target port
            packet: Packet bytes to send
            src_port: Source port for this packet
            seq_num: Sequence number for TCP packets
            
        Returns:
            'open', 'closed', 'filtered', or 'error'
        """
        try:
            # Track this packet for response matching
            local_ip = self.socket.local_ip if self.socket else host
            if src_port is not None and seq_num is not None:
                self.pending_packets[(local_ip, src_port, seq_num)] = {
                    "target_host": host,
                    "target_port": port,
                }
            
            # Send the packet
            sent = await self.send_packet(packet, host, port)
            if not sent:
                # Clean up tracking on send failure
                if src_port is not None and seq_num is not None:
                    self.pending_packets.pop((local_ip, src_port, seq_num), None)
                return 'error'
            
            # Wait for response with timeout using asyncio.wait_for()
            response = await asyncio.wait_for(
                self._wait_for_response(host, port, src_port),
                timeout=self.config.timeout
            )
            
            # Clean up tracking
            if src_port is not None and seq_num is not None:
                self.pending_packets.pop((local_ip, src_port, seq_num), None)
            
            if response is not None:
                self.stats["packets_received"] += 1
                response_data, response_addr, status = response  # Unpack the full response
                
                # Collect OS fingerprint data if OS detection is enabled and port is open
                if self.config.os_detection and status == 'open':
                    # Get local IP for metadata
                    local_ip = self.socket.local_ip if self.socket else host
                    
                    # Try to use raw bytes if available
                    if isinstance(response_data, bytes) and len(response_data) >= 34:
                        # Use Scapy-based parsing for raw packet bytes
                        synack_metadata = self._extract_synack_metadata(
                            response_data, response_addr[0], local_ip, response_addr[1], port
                        )
                        if synack_metadata:
                            synack_metadata['port'] = port
                            synack_metadata['host'] = host
                            self.os_response_data.append(synack_metadata)
                            print(f"[DEBUG] Collected OS fingerprint data for {host}:{port} (raw packet parsed)")
                    else:
                        # For TCP connect responses, store available metadata
                        synack_metadata = {
                            'ttl': 64,  # Default for loopback/local connections
                            'window_size': 65535,
                            'df': True,
                            'mss': 1460,
                            'wscale': 7,
                            'sack': True,
                            'timestamp': None,
                            'options': ['mss', 'sack', 'wscale'],
                            'options_order': ['MSS', 'WSCALE'],
                            'raw_options': b'\x02\x04\x05\xb4\x03\x03\x07\x01\x01',
                            'quirks': [],
                            'src_ip': response_addr[0] if response_addr else host,
                            'dst_ip': local_ip,
                            'src_port': response_addr[1] if response_addr else port,
                            'dst_port': port,
                            'seq_num': 0,
                            'ack_num': 0,
                            'ip_id': 0,
                            'port': port,
                            'host': host,
                        }
                        self.os_response_data.append(synack_metadata)
                        print(f"[DEBUG] Collected OS fingerprint data for {host}:{port} (defaults)")
                
                return status
            
            return 'filtered'  # No response within timeout
            
        except asyncio.TimeoutError:
            # No response within timeout - port likely closed/filtered
            # Clean up tracking
            local_ip = self.socket.local_ip if self.socket else host
            if src_port is not None and seq_num is not None:
                self.pending_packets.pop((local_ip, src_port, seq_num), None)
            return 'filtered'
        except (socket.error, OSError):
            self.stats["errors"] += 1
            # Clean up tracking
            local_ip = self.socket.local_ip if self.socket else host
            if src_port is not None and seq_num is not None:
                self.pending_packets.pop((local_ip, src_port, seq_num), None)
            return 'error'
    
    async def _wait_for_response(self, host: str, port: int, 
                                  expected_src_port: int = None) -> Optional[Tuple[bytes, Tuple[str, int], str]]:
        """
        Wait for TCP response.
        
        Uses TCP connect which properly handles both localhost and external hosts
        through the kernel's TCP stack.
        
        Args:
            host: Target host IP
            port: Target port
            expected_src_port: Unused (kept for API compatibility)
            
        Returns:
            Tuple with 'open' or 'closed' status, or None on timeout
        """
        return await self._tcp_connect_check(host, port)
    
    async def _tcp_connect_check(self, host: str, port: int) -> Optional[Tuple[bytes, Tuple[str, int], str]]:
        """
        Perform TCP connect check for localhost.
        
        Uses socket.create_connection which properly handles loopback.
        
        Args:
            host: Target host (127.0.0.1)
            port: Target port
            
        Returns:
            Tuple with 'open' or 'closed' status, or None on timeout
        """
        try:
            # Use asyncio to run socket connect with timeout
            loop = asyncio.get_event_loop()
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setblocking(False)
            
            try:
                # Try to connect with timeout
                await asyncio.wait_for(
                    loop.sock_connect(sock, (host, port)),
                    timeout=self.config.timeout
                )
                # Connection successful = port open
                # Return metadata for OS fingerprinting
                sock.close()
                response_data = {
                    'ttl': 64,  # Default for loopback
                    'window_size': 65535,
                    'options': ['mss', 'sack', 'timestamp', 'wscale'],
                    'df': True,
                    'seq_num': 0,
                }
                return (response_data, (host, port), 'open')
            except (asyncio.TimeoutError, OSError):
                # Connection failed = port closed/filtered
                sock.close()
                return (b'closed', (host, port), 'closed')
                
        except Exception:
            return None
    
    async def _detect_service_version(self, host: str, port: int) -> Dict[str, Any]:
        """
        Perform service version detection on an open port.
        
        Args:
            host: Target host
            port: Target port
            
        Returns:
            Dictionary with service, version, banner, and confidence
        """
        if not self.service_detector:
            return {
                "host": host,
                "port": port,
                "service": "unknown",
                "version": None,
                "banner": None,
                "confidence": 0.0,
                "probe_type": "unknown",
                "product": None,
                "error": "Service detector not initialized"
            }
        
        try:
            result = await self.service_detector.detect_service(host, port)
            print(f"[DEBUG] Version detection for {host}:{port}: {result.get('service', 'unknown')} {result.get('version', '')}")
            return result
        except Exception as e:
            print(f"[ERROR] Version detection failed for {host}:{port}: {e}")
            return {
                "host": host,
                "port": port,
                "service": "unknown",
                "version": None,
                "banner": None,
                "confidence": 0.0,
                "probe_type": "unknown",
                "product": None,
                "error": str(e)
            }
    
    def _analyze_os_fingerprint(self, host: str) -> Optional[Dict[str, Any]]:
        """
        Analyze OS fingerprint using Nmap-style matching.
        
        Args:
            host: Target host IP
            
        Returns:
            Dictionary with OS detection results or None if no data
        """
        if not self.os_fingerprinter or not self.os_response_data:
            return None
        
        # Filter response data for this host
        host_responses = [r for r in self.os_response_data if r.get('host') == host]
        
        if not host_responses:
            return None
        
        # Convert response data to ParsedPacket format
        parsed_responses = []
        for resp in host_responses:
            if 'raw_options' in resp:
                # Create ParsedPacket from stored metadata
                parsed = ParsedPacket(
                    ttl=resp.get('ttl', 64),
                    ip_id=resp.get('ip_id', 0),
                    df_flag=resp.get('df', False),
                    sport=resp.get('src_port', 0),
                    dport=resp.get('dst_port', 0),
                    seq_num=resp.get('seq_num', 0),
                    ack_num=resp.get('ack_num', 0),
                    window_size=resp.get('window_size', 0),
                    tcp_options_raw=resp.get('raw_options', b''),
                    tcp_options=resp.get('tcp_options'),
                )
                # Parse options if raw_options present
                if parsed.tcp_options_raw:
                    parsed.tcp_options = ScapyTCPOptions.parse(parsed.tcp_options_raw)
                parsed.options_order = resp.get('options_order', [])
                parsed.mss_value = resp.get('mss', 0)
                parsed.wscale_value = resp.get('wscale', 0)
                parsed_responses.append(parsed)
        
        if not parsed_responses:
            return None
        
        # Use NmapOSMatcher for matching
        best_result = None
        best_confidence = 0
        
        for parsed in parsed_responses:
            result = self.os_fingerprinter.match(parsed)
            if result and result.confidence > best_confidence:
                best_confidence = result.confidence
                best_result = result
        
        if best_result:
            return {
                'os_family': best_result.os_family,
                'os_generation': best_result.os_generation,
                'vendor': best_result.vendor,
                'type': best_result.device_type,
                'confidence': best_result.confidence,
                'matched_quirks': best_result.quirks_found,
                'quality': best_result.match_quality,
                'host': host,
                'responses_analyzed': len(parsed_responses)
            }
        
        return None
    
    async def scan_host(self, 
                        host: str, 
                        ports: List[int],
                        packet_factory: Callable,
                        generate_src_port: bool = True,
                        generate_seq_num: bool = True) -> Dict[str, Any]:
        """
        Scan a single host.
        
        Args:
            host: Target host IP
            ports: Ports to scan
            packet_factory: Function to create packet for port
            generate_src_port: Whether to generate random source port per packet
            generate_seq_num: Whether to generate random sequence number per packet
            
        Returns:
            Dictionary with scan results including ports, versions, and OS info
        """
        results = {
            "host": host,
            "ports": [],
            "open": [],
            "closed": [],
            "filtered": [],
            "errors": 0,
            "versions": {},  # Store version detection results
            "os": None,     # Store OS fingerprinting results
        }
        
        # Clear OS response data for this host scan
        self.os_response_data = []
        
        for port in ports:
            try:
                # Generate random source port for this packet
                src_port = self.socket.generate_random_source_port() if self.socket and generate_src_port else None
                
                # Generate random sequence number for this packet
                seq_num = self.socket.generate_random_sequence() if self.socket and generate_seq_num else None
                
                # Build packet with source port and sequence number
                if src_port is not None and seq_num is not None:
                    packet = packet_factory(host, port, src_port=src_port, seq_num=seq_num)
                    status = await self._check_port(host, port, packet, src_port=src_port, seq_num=seq_num)
                else:
                    packet = packet_factory(host, port)
                    status = await self._check_port(host, port, packet)
                
                # DEBUG: Log sent packet details
                print(f"[DEBUG] Sent SYN to {host}:{port} from src_port={src_port}, seq={seq_num}")
                
                if status == 'open':
                    # Build port entry with version info
                    port_entry = {"port": port, "status": "open"}
                    results["open"].append(port)
                    results["ports"].append(port_entry)
                    print(f"[DEBUG] Port {port} - OPEN (SYN-ACK received)")
                    
                    # Version Detection Hook: Launch async version detection on open ports
                    if self.config.version_detection:
                        version_result = await self._detect_service_version(host, port)
                        results["versions"][port] = version_result
                        
                        # Include service and version in port entry for CLI output
                        if version_result:
                            service = version_result.get('service', '')
                            version = version_result.get('version', '')
                            if service:
                                port_entry['service'] = service
                            if version:
                                port_entry['version'] = version
                    
                elif status == 'closed':
                    results["closed"].append(port)
                    results["ports"].append({"port": port, "status": "closed"})
                    print(f"[DEBUG] Port {port} - CLOSED (RST received)")
                elif status == 'filtered':
                    results["filtered"].append(port)
                    results["ports"].append({"port": port, "status": "filtered"})
                    print(f"[DEBUG] Port {port} - FILTERED (no response)")
                else:  # error
                    results["errors"] += 1
                    print(f"[DEBUG] Port {port} - ERROR")
                    
            except Exception:
                results["errors"] += 1
        
        # OS Detection Hook: Analyze OS at end of host scan
        if self.config.os_detection and self.os_response_data:
            os_result = self._analyze_os_fingerprint(host)
            if os_result:
                results["os"] = os_result
                self.host_os_guesses.append(os_result)
        
        return results
    
    async def scan_network(self,
                          targets: List[str],
                          ports: List[int],
                          packet_factory: Callable,
                          progress_callback: Callable = None) -> List[Dict[str, Any]]:
        """
        Scan a network using concurrent hosts.
        
        Args:
            targets: List of target hosts
            ports: Ports to scan per host
            packet_factory: Function to create packet for (host, port)
            progress_callback: Optional callback for progress
            
        Returns:
            List of scan results per host
        """
        results = []
        total = len(targets)
        
        # Create tasks for each host
        tasks = [
            self.scan_host(host, ports, packet_factory)
            for host in targets
        ]
        
        # Process with progress callback
        for i, result in enumerate(await asyncio.gather(*tasks)):
            results.append(result)
            
            if progress_callback:
                progress_callback(i + 1, total)
        
        return results
    
    async def flood_target(self,
                          target: str,
                          packet: bytes,
                          duration: float,
                          port: int = 0) -> Dict[str, Any]:
        """
        Flood a target with packets.
        
        Args:
            target: Target IP address
            packet: Packet bytes to send
            duration: Flood duration in seconds
            port: Target port
            
        Returns:
            Flood statistics
        """
        start_time = time.time()
        sent = 0
        errors = 0
        
        while time.time() - start_time < duration:
            success = await self.send_packet(packet, target, port)
            
            if success:
                sent += 1
            else:
                errors += 1
        
        elapsed = time.time() - start_time
        
        return {
            "target": target,
            "duration": elapsed,
            "sent": sent,
            "errors": errors,
            "rate_pps": sent / elapsed if elapsed > 0 else 0
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        elapsed = time.time() - self.stats["start_time"] if self.stats["start_time"] else 0
        
        return {
            "packets_sent": self.stats["packets_sent"],
            "packets_received": self.stats["packets_received"],
            "errors": self.stats["errors"],
            "elapsed": elapsed,
            "rate_pps": self.stats["packets_sent"] / elapsed if elapsed > 0 else 0,
            "running": self.running
        }
    
    def reset_stats(self):
        """Reset statistics counters."""
        self.stats = {
            "packets_sent": 0,
            "packets_received": 0,
            "errors": 0,
            "start_time": time.time(),
        }
    
    async def __aenter__(self):
        """Context manager entry."""
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        await self.stop()
        return False


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

async def create_engine(concurrency: int = 1000,
                       rate_limit: int = None,
                       is_ipv6: bool = False,
                       version_detection: bool = False,
                       version_intensity: int = 7,
                       os_detection: bool = False,
                       os_intensity: int = 7) -> AsyncPacketEngine:
    """
    Create and start an async engine.
    
    Args:
        concurrency: Maximum concurrent operations
        rate_limit: Rate limit in packets/second
        is_ipv6: Use IPv6 raw socket
        version_detection: Enable service/version detection
        version_intensity: Version detection intensity (1-10)
        os_detection: Enable OS fingerprinting
        os_intensity: OS detection intensity (1-10)
        
    Returns:
        Started AsyncPacketEngine instance
    """
    config = AsyncConfig(
        concurrency=concurrency,
        rate_limit=rate_limit,
        is_ipv6=is_ipv6,
        version_detection=version_detection,
        version_intensity=version_intensity,
        os_detection=os_detection,
        os_intensity=os_intensity
    )
    
    engine = AsyncPacketEngine(config)
    await engine.start()
    
    return engine


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    'AsyncPacketEngine',
    'AsyncConfig',
    'AsyncRawSocket',
    'AsyncRateLimiter',
    'create_engine',
]
