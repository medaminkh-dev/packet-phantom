#!/usr/bin/env python3
"""
Interactive Packet Phantom Shell

A  interactive shell for packet crafting with full security features.

Usage:
    python -m packet_phantom.interface.interactive_shell
    
Commands:
    syn <target> <port> [count]    - Send SYN packet(s)
    flood <target> <port> <rate>  - Start flood attack
    udp <target> <port> <data>    - Send UDP packet
    icmp <target> <type> <data>   - Send ICMP packet
    ipv6 <target> <port>          - Send IPv6 SYN
    stats                         - Show statistics
    pcap <filename>               - Start PCAP recording
    evade                         - Show evasion settings
    quit                          - Exit shell
    
SECURITY FEATURES:
- Privilege dropping to 'nobody' user after socket setup
- Resource limits (RLIMIT_AS 100-200MB)
- Rate limiting with TokenBucket
- Input validation for all user inputs
- Memory bounds enforcement
- Thread-safe operations
"""

import cmd
import sys
import socket
import struct
import time
import argparse
import resource
import os
import pwd
import grp
import threading
import logging
import unicodedata
import ipaddress
from pathlib import Path
from typing import Optional, Tuple

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from packet_phantom.core.ipv4_forger import IPv4PacketForger
from packet_phantom.core.ipv6_forger import IPv6PacketForger
from packet_phantom.core.udp_forger import UDPForger
from packet_phantom.core.icmp_forger import ICMPForger
from packet_phantom.evasion.ttl_evasion import TTLEvasion
from packet_phantom.evasion.option_scrambler import OptionScrambler
from packet_phantom.output.console import ConsoleFormatter
from packet_phantom.security.rate_limiter import TokenBucket, MAX_RATE_EDU, MAX_RATE_LIVE, OperationMode


# ==================== SECURITY CONSTANTS ====================
MAX_PACKET_SIZE = 65535  # Maximum packet size (Ethernet MTU + overhead)
MAX_PAYLOAD_SIZE = 1400  # Maximum payload size for testing
MAX_RATE = 100000  # Maximum packets per second
MAX_COUNT = 10000  # Maximum packet count per command
MAX_DURATION = 300  # Maximum flood duration in seconds
MAX_PCAP_SIZE = 100 * 1024 * 1024  # 100MB max PCAP file size
RLIMIT_AS_SOFT = 100 * 1024 * 1024  # 100MB soft limit
RLIMIT_AS_HARD = 200 * 1024 * 1024  # 200MB hard limit

# Rate limits by mode (security: prevent DoS attacks)
MAX_RATE_LIVE = 10000  # 10k pkt/s max for LIVE mode
MAX_RATE_EDU = 100     # 100 pkt/s educational cap

# Setup logging for security events
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
security_logger = logging.getLogger('security')


# ==================== SECURITY UTILITIES ====================
def validate_safe_path(path: str, allowed_base: Optional[str] = None) -> str:
    """
    Comprehensive path validation to prevent path traversal attacks.
    
    SECURITY: Validates paths against:
    - Null bytes (\\x00)
    - Unicode normalization attacks
    - Path traversal (..)
    - Symlink attacks (when allowed_base is specified)
    
    Args:
        path: Path to validate
        allowed_base: Optional base directory to restrict path to
        
    Returns:
        str: Validated absolute path
        
    Raises:
        ValueError: If path contains dangerous patterns
    """
    # Check for null bytes - critical security check
    if '\x00' in path:
        raise ValueError("Null bytes in path detected - potential injection attack")
    
    # Normalize unicode to NFC form to prevent homograph attacks
    path = unicodedata.normalize('NFC', path)
    
    # Remove any null bytes after normalization (in case of clever encoding)
    path = path.replace('\x00', '')
    
    # Check for path traversal patterns BEFORE normalization
    # This catches attempts like ./../etc/passwd that normalize to /etc/passwd
    normalized_input = os.path.normpath(path)
    if '..' in path.replace('\\\\', '/').split('/'):
        raise ValueError("Path traversal detected")
    
    # Resolve to absolute path
    abs_path = os.path.abspath(path)
    
    # Check for path traversal after normalization (defense in depth)
    normalized = os.path.normpath(abs_path)
    if '..' in normalized.split(os.sep):
        raise ValueError("Path traversal detected")
    
    # Prevent writing to sensitive system directories
    sensitive_dirs = ['/etc/', '/root/', '/bin/', '/sbin/', '/usr/bin/', '/boot/', '/var/', '/proc/', '/sys/']
    for sensitive in sensitive_dirs:
        if abs_path.startswith(sensitive) or abs_path == sensitive.rstrip('/'):
            raise ValueError(f"Cannot write to protected system directory: {path}")
    
    if allowed_base:
        # Resolve allowed_base to real path (resolves symlinks)
        real_base = os.path.realpath(allowed_base)
        real_path = os.path.realpath(abs_path)
        
        # Ensure path is within allowed base
        if not real_path.startswith(real_base + os.sep):
            raise ValueError(f"Path outside allowed directory: {path}")
    
    return abs_path


def validate_ip_address(ip: str, is_ipv6: bool = False) -> Tuple[bool, Optional[str]]:
    """
    Validate IP address format using ipaddress module.
    
    SECURITY: Uses ipaddress module for proper validation instead of regex.
    Prevents bypasses through malformed IP addresses.
    
    Args:
        ip: IP address string to validate
        is_ipv6: If True, validate as IPv6 address
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not ip or not isinstance(ip, str):
        return False, "IP address must be a non-empty string"
    
    # Check for null bytes
    if '\x00' in ip:
        return False, "Null byte in IP address"
    
    try:
        if is_ipv6:
            # Use ipaddress module for IPv6 validation
            addr = ipaddress.IPv6Address(ip)
            return True, None
        else:
            # Use ipaddress module for IPv4 validation
            addr = ipaddress.IPv4Address(ip)
            return True, None
    except ipaddress.AddressValueError as e:
        return False, f"Invalid IP address: {e}"
    except Exception as e:
        return False, f"IP validation error: {e}"


def validate_port(port: int) -> Tuple[bool, Optional[str]]:
    """
    Validate port number.
    
    SECURITY: Ensures port is in valid range and is an integer.
    
    Args:
        port: Port number to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(port, int):
        return False, "Port must be an integer"
    if port < 0 or port > 65535:
        return False, f"Port out of range: {port} (0-65535)"
    return True, None


def validate_packet_count(count: int) -> Tuple[bool, Optional[str]]:
    """
    Validate packet count against limits.
    
    SECURITY: Prevents resource exhaustion.
    
    Args:
        count: Number of packets requested
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(count, int):
        return False, "Packet count must be an integer"
    if count < 1 or count > MAX_COUNT:
        return False, f"Packet count out of range: {count} (1-{MAX_COUNT})"
    return True, None


def validate_rate(rate: int, mode: str = 'EDU') -> Tuple[bool, Optional[str], int]:
    """
    Validate rate limit with mode awareness.
    
    SECURITY: Enforces different limits based on mode to prevent DoS.
    
    Args:
        rate: Packets per second requested
        mode: Operation mode ('EDU' or 'LIVE')
        
    Returns:
        Tuple of (is_valid, error_message, enforced_rate)
    """
    if not isinstance(rate, int):
        return False, "Rate must be an integer", MAX_RATE_EDU
    
    max_rate = MAX_RATE_LIVE if mode == 'LIVE' else MAX_RATE_EDU
    
    if rate < 1:
        return False, "Rate must be at least 1", max_rate
    
    if rate > max_rate:
        security_logger.warning(f"Rate {rate} exceeds max {max_rate} for mode {mode}")
        return False, f"Rate capped to {max_rate} pkt/s", max_rate
    
    return True, None, rate


def validate_duration(duration: int) -> Tuple[bool, Optional[str]]:
    """
    Validate flood duration.
    
    SECURITY: Prevents long-running attacks.
    
    Args:
        duration: Duration in seconds
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not isinstance(duration, int):
        return False, "Duration must be an integer"
    if duration < 1 or duration > MAX_DURATION:
        return False, f"Duration out of range: {duration} (1-{MAX_DURATION})"
    return True, None


# ==================== SECURITY UTILITIES ====================
def drop_privileges():
    """
    Drop privileges to 'nobody' user after socket setup.
    
    SECURITY: Uses setuid() for PERMANENT privilege drop.
    This is critical because seteuid() only drops effective UID,
    keeping saved UID as root which can be regained.
    
    Order of operations:
    1. Drop supplementary groups FIRST
    2. Set GID before UID (GID change is irreversible)
    3. Set UID using setuid() (NOT seteuid)
    4. Verify privilege drop by attempting to regain root
    
    Returns:
        True if privileges dropped successfully, False otherwise
    """
    # Only drop if running as root
    if os.getuid() != 0:
        security_logger.info("Not running as root, no privileges to drop")
        return True
    
    try:
        # Get nobody user and group
        nobody_user = pwd.getpwnam('nobody')
        nobody_group = grp.getgrnam('nogroup')
        
        # Drop supplementary groups FIRST (must be done before setuid)
        os.setgroups([])
        
        # Set GID before UID - this is IRREVERSIBLE for non-root
        os.setgid(nobody_group.gr_gid)
        
        # Set UID using setuid() - NOT seteuid()!
        # setuid() sets real, effective, and saved UID all at once
        os.setuid(nobody_user.pw_uid)
        
        # Verify we cannot regain root privileges
        try:
            # Try to set UID back to 0 (root)
            os.setuid(0)
            # If we reach here, privilege drop failed catastrophically
            security_logger.error("CRITICAL: Privilege drop verification failed!")
            os._exit(1)  # Abort immediately
        except PermissionError:
            # Good - we cannot regain root privileges
            security_logger.info(f"Privileges dropped successfully to user: {nobody_user.pw_name}")
            pass
        
        return True
        
    except KeyError:
        # nobody user or group doesn't exist
        security_logger.warning("nobody/nogroup user not found, using fallback")
        try:
            # Try to use current non-root user
            if os.getuid() != 0:
                return True
        except Exception:
            pass
        return False
    except OSError as e:
        security_logger.error(f"Failed to drop privileges: {e}")
        # If we can't drop privileges, ABORT - don't continue as root
        security_logger.critical("Cannot continue without dropping privileges, exiting")
        os._exit(1)


def set_resource_limits():
    """
    Set resource limits to prevent memory exhaustion.
    
    SECURITY: Limits memory usage to prevent DoS.
    """
    try:
        # Set address space limit
        resource.setrlimit(resource.RLIMIT_AS, (RLIMIT_AS_SOFT, RLIMIT_AS_HARD))
        security_logger.info("Resource limits set successfully")
    except (ValueError, OSError) as e:
        security_logger.warning(f"Could not set resource limits: {e}")


# ==================== THREAD-SAFE STATISTICS ====================
class ThreadSafeCounter:
    """
    Thread-safe counter for statistics.
    
    SECURITY: Ensures accurate packet counting under concurrent access.
    """
    
    def __init__(self, initial_value: int = 0):
        self._value = initial_value
        self._lock = threading.Lock()
    
    def increment(self, amount: int = 1) -> int:
        """Increment counter thread-safely."""
        with self._lock:
            self._value += amount
            return self._value
    
    def get(self) -> int:
        """Get current value thread-safely."""
        with self._lock:
            return self._value


# ==================== THREAD-SAFE SOCKET LOCK ====================
class ThreadSafeSocket:
    """
    Thread-safe wrapper for socket operations.
    
    SECURITY: Ensures socket send operations are synchronized.
    """
    
    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._lock = threading.Lock()
    
    def sendto(self, data: bytes, address: Tuple[str, int]) -> int:
        """Send data thread-safely."""
        with self._lock:
            return self._sock.sendto(data, address)
    
    def close(self) -> None:
        """Close socket."""
        with self._lock:
            self._sock.close()
    
    def getsockopt(self, level: int, optname: int) -> int:
        """Get socket option."""
        with self._lock:
            return self._sock.getsockopt(level, optname)
    
    def setsockopt(self, level: int, optname: int, value: int) -> None:
        """Set socket option."""
        with self._lock:
            self._sock.setsockopt(level, optname, value)


# ==================== MAIN SHELL CLASS ====================
class PhantomShell(cmd.Cmd):
    """
    Interactive shell for Packet Phantom God Tier
    
    SECURITY: 
    - All operations require root for raw sockets
    - Privileges dropped to 'nobody' after socket setup
    - Resource limits enforced
    - Input validation for all commands
    - Rate limiting to prevent abuse
    - Thread-safe operations
    """
    
    intro = """
╔══════════════════════════════════════════════════════════════╗
║                    PACKET PHANTOM GOD TIER                   ║
║              Interactive Packet Crafting Shell            pp ║
╠══════════════════════════════════════════════════════════════╣
║  Type 'help' for available commands                          ║
║  Type 'help <command>' for detailed command help             ║
║  Type 'quit' to exit                                         ║
╚══════════════════════════════════════════════════════════════╝
"""
    
    prompt = 'phantom> '
    
    def __init__(self):
        super().__init__()
        
        # Set resource limits first (before any allocations)
        set_resource_limits()
        
        # Initialize forgers
        self.ipv4_forger = IPv4PacketForger()
        self.ipv6_forger = IPv6PacketForger()
        self.udp_forger = UDPForger()
        self.icmp_forger = ICMPForger()
        
        # Evasion utilities
        self.ttl_evasion = TTLEvasion()
        self.option_scrambler = OptionScrambler()
        
        # State
        self.running = False
        self.pcap_writer = None
        self._pcap_original_send = None  # Store original send method
        self.rate_limiter = TokenBucket(rate=1000, capacity=1000)
        self.operation_mode = 'EDU'  # Default to educational mode
        
        # Thread-safe statistics
        self._packets_sent = ThreadSafeCounter(0)
        self._bytes_sent = ThreadSafeCounter(0)
        self.start_time = time.time()
        
        # Socket setup (must be done as root)
        self.socket = None
        self._setup_socket()
        
        # Drop privileges after socket setup
        # SECURITY: This MUST happen after all socket operations are complete
        if not drop_privileges():
            print(ConsoleFormatter.warning("Could not drop privileges - running as current user"))
        else:
            print(ConsoleFormatter.success("Privileges dropped to 'nobody' user"))
    
    def _setup_socket(self):
        """Setup raw socket for sending packets"""
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            raw_sock.setblocking(False)
            # Wrap in thread-safe socket
            self.socket = ThreadSafeSocket(raw_sock)
            print(ConsoleFormatter.success("Raw socket initialized"))
        except PermissionError:
            print(ConsoleFormatter.error("Root privileges required for raw sockets"))
            print(ConsoleFormatter.info("Run with: sudo python -m packet_phantom.interface.interactive_shell"))
            sys.exit(1)
        except Exception as e:
            print(ConsoleFormatter.error(f"Failed to create socket: {e}"))
            sys.exit(1)
    
    def _build_tcp_syn(self, src_port: int, dst_port: int, src_ip: str, dst_ip: str) -> bytes:
        """
        Build TCP SYN packet.
        
        SECURITY: Validates all inputs, bounds-checked operations.
        
        Args:
            src_port: Source port number
            dst_port: Destination port number
            src_ip: Source IP address
            dst_ip: Destination IP address
            
        Returns:
            TCP header bytes
            
        Raises:
            ValueError: If inputs are invalid
        """
        # Validate inputs
        valid, error = validate_port(src_port)
        if not valid:
            raise ValueError(f"Invalid source port: {error}")
        valid, error = validate_port(dst_port)
        if not valid:
            raise ValueError(f"Invalid destination port: {error}")
        
        # TCP header format (20 bytes = 5 words, no options):
        # | Source Port (2) | Dest Port (2) | Seq (4) | Ack (4) | Offset+Flags (2) | Window (2) | Checksum (2) | Urgent (2)
        seq = 0
        ack = 0
        data_offset = 5  # 5 words = 20 bytes
        flags = 0x02  # SYN flag
        window = 65535
        
        # Build the offset+flags field: 4 bits offset, 6 bits reserved, 6 bits flags
        offset_flags = (data_offset << 12) | flags
        
        # Build header without checksum first
        tcp_header_no_checksum = struct.pack('!HHIIHH', 
            src_port, dst_port, seq, ack, offset_flags, window)
        
        # Pseudo header for checksum
        pseudo = struct.pack('!4s4sBBH', 
                            socket.inet_aton(dst_ip),  # Use dst_ip for pseudo header
                            socket.inet_aton(dst_ip),
                            0, 
                            socket.IPPROTO_TCP, 
                            len(tcp_header_no_checksum))
        
        # Calculate checksum
        checksum = self._calc_checksum(pseudo + tcp_header_no_checksum)
        
        # Rebuild with correct checksum (include urgent pointer)
        tcp_header = struct.pack('!HHIIHHHH', 
            src_port, dst_port, seq, ack, offset_flags, window, checksum, 0)
        
        return tcp_header
    
    def _calc_checksum(self, data: bytes) -> int:
        """Calculate ones complement checksum"""
        if len(data) % 2:
            data += b'\x00'
        s = sum(struct.unpack('!%dH' % (len(data) // 2), data))
        s = (s >> 16) + (s & 0xffff)
        s += s >> 16
        return ~s & 0xffff
    
    def _send_packet(self, packet: bytes, target: str) -> bool:
        """
        Send packet with rate limiting.
        
        SECURITY:
        - Rate limited to prevent abuse
        - Packet size checked against limits
        - Thread-safe socket operations
        
        Args:
            packet: Raw packet bytes
            target: Target IP address
            
        Returns:
            True if sent successfully, False otherwise
        """
        # Validate packet size
        if len(packet) > MAX_PACKET_SIZE:
            print(ConsoleFormatter.error(f"Packet too large: {len(packet)} > {MAX_PACKET_SIZE}"))
            return False
        
        # Rate limiting
        if not self.rate_limiter.consume():
            return False
        
        try:
            # Thread-safe socket send
            self.socket.sendto(packet, (target, 0))
            self._packets_sent.increment()
            self._bytes_sent.increment(len(packet))
            return True
        except PermissionError:
            print(ConsoleFormatter.error("Permission denied - may need root privileges"))
            return False
        except OSError as e:
            print(ConsoleFormatter.error(f"Send failed: {e}"))
            return False
    
    # ==================== TCP Commands ====================
    
    def do_syn(self, args):
        """
        Send SYN packet: syn <target> <port> [count]
        
        SECURITY:
        - Validates IP and port inputs
        - Limits packet count
        - Rate limited
        """
        parser = argparse.ArgumentParser(prog='syn')
        parser.add_argument('target', help='Target IP address')
        parser.add_argument('port', type=int, help='Target port (0-65535)')
        parser.add_argument('count', type=int, nargs='?', default=1, 
                          help='Number of packets (1-{})'.format(MAX_COUNT))
        
        try:
            parsed = parser.parse_args(args.split())
        except SystemExit:
            return
        
        # Validate inputs using ipaddress module
        valid, error = validate_ip_address(parsed.target)
        if not valid:
            print(ConsoleFormatter.error(f"Invalid target IP: {error}"))
            return
        valid, error = validate_port(parsed.port)
        if not valid:
            print(ConsoleFormatter.error(f"Invalid port: {error}"))
            return
        valid, error = validate_packet_count(parsed.count)
        if not valid:
            print(ConsoleFormatter.error(f"Invalid packet count: {error}"))
            return
        
        for i in range(parsed.count):
            src_port = 12345 + i  # Use different source port for each packet
            tcp_header = self._build_tcp_syn(src_port, parsed.port, '0.0.0.0', parsed.target)
            packet = self.ipv4_forger.build_ipv4_packet(
                src_addr='0.0.0.0',
                dst_addr=parsed.target,
                protocol=socket.IPPROTO_TCP,
                payload=tcp_header,
                ttl=64
            )
            if self._send_packet(packet, parsed.target):
                if i == 0:
                    print(ConsoleFormatter.packet_sent(parsed.target, parsed.port, len(packet)))
    
    def help_syn(self):
        print("""
Send SYN packet to target

Usage: syn <target> <port> [count]

Examples:
    syn 192.168.1.1 80              # Send 1 SYN packet
    syn 10.0.0.1 443 10             # Send 10 SYN packets
    syn 192.168.1.1 8080 100        # Send 100 SYN packets

Note: Requires root privileges
Security: Rate limited to prevent abuse
""")
    
    def do_flood(self, args):
        """
        Start flood attack: flood <target> <port> <rate> [duration]
        
        SECURITY:
        - Validates all inputs
        - Limits rate and duration
        - Can be interrupted with Ctrl+C
        """
        parser = argparse.ArgumentParser(prog='flood')
        parser.add_argument('target', help='Target IP address')
        parser.add_argument('port', type=int, help='Target port (0-65535)')
        parser.add_argument('rate', type=int, help='Packets per second (1-{})'.format(MAX_RATE))
        parser.add_argument('duration', type=int, nargs='?', default=10, 
                          help='Duration in seconds (1-{})'.format(MAX_DURATION))
        
        try:
            parsed = parser.parse_args(args.split())
        except SystemExit:
            return
        
        # Validate inputs using ipaddress module
        valid, error = validate_ip_address(parsed.target)
        if not valid:
            print(ConsoleFormatter.error(f"Invalid target IP: {error}"))
            return
        valid, error = validate_port(parsed.port)
        if not valid:
            print(ConsoleFormatter.error(f"Invalid port: {error}"))
            return
        valid, error, enforced_rate = validate_rate(parsed.rate, self.operation_mode)
        if not valid:
            print(ConsoleFormatter.warning(f"Rate validation: {error}"))
            parsed.rate = enforced_rate
        valid, error = validate_duration(parsed.duration)
        if not valid:
            print(ConsoleFormatter.error(f"Invalid duration: {error}"))
            return
        
        print(ConsoleFormatter.warning("Starting flood: {}:{} @ {}p/s".format(
            parsed.target, parsed.port, parsed.rate)))
        
        # Update rate limiter
        self.rate_limiter = TokenBucket(rate=parsed.rate, capacity=parsed.rate)
        
        packets = 0
        start = time.time()
        src_port = 12345
        
        try:
            while time.time() - start < parsed.duration:
                tcp_header = self._build_tcp_syn(src_port, parsed.port, '0.0.0.0', parsed.target)
                packet = self.ipv4_forger.build_ipv4_packet(
                    src_addr='0.0.0.0',
                    dst_addr=parsed.target,
                    protocol=socket.IPPROTO_TCP,
                    payload=tcp_header,
                    ttl=64
                )
                if self._send_packet(packet, parsed.target):
                    packets += 1
                src_port = ((src_port + 1) % 65535) + 1
                time.sleep(1.0 / parsed.rate if parsed.rate > 0 else 0)
        except KeyboardInterrupt:
            print(ConsoleFormatter.warning("Flood interrupted"))
        
        elapsed = time.time() - start
        print(ConsoleFormatter.success("Flood complete: {} packets in {:.2f}s".format(packets, elapsed)))
    
    def help_flood(self):
        print("""
Start SYN flood attack

Usage: flood <target> <port> <rate> [duration]

Examples:
    flood 192.168.1.1 80 100        # Flood at 100 p/s for 10s
    flood 10.0.0.1 443 1000 30     # Flood at 1000 p/s for 30s

WARNING: Use only for authorized testing!
Security: Rate and duration limited
""")
    
    # ==================== UDP Commands ====================
    
    def do_udp(self, args):
        """
        Send UDP packet: udp <target> <port> <data>
        
        SECURITY:
        - Validates IP and port
        - Limits payload size
        """
        parser = argparse.ArgumentParser(prog='udp')
        parser.add_argument('target', help='Target IP address')
        parser.add_argument('port', type=int, help='Target port (0-65535)')
        parser.add_argument('data', nargs='?', default='test', help='UDP payload')
        
        try:
            parsed = parser.parse_args(args.split())
        except SystemExit:
            return
        
        # Validate inputs using ipaddress module
        valid, error = validate_ip_address(parsed.target)
        if not valid:
            print(ConsoleFormatter.error(f"Invalid target IP: {error}"))
            return
        valid, error = validate_port(parsed.port)
        if not valid:
            print(ConsoleFormatter.error(f"Invalid port: {error}"))
            return
        
        payload = parsed.data.encode('utf-8')
        
        # Validate payload size
        if len(payload) > MAX_PAYLOAD_SIZE:
            print(ConsoleFormatter.error("Payload too large (max {} bytes)".format(MAX_PAYLOAD_SIZE)))
            return
        
        packet = self.udp_forger.craft_udp_packet_with_ip_header(
            target_ip=parsed.target,
            target_port=parsed.port,
            payload=payload
        )
        
        if self._send_packet(packet, parsed.target):
            print(ConsoleFormatter.packet_sent(parsed.target, parsed.port, len(packet)))
    
    def help_udp(self):
        print("""
Send UDP packet

Usage: udp <target> <port> [data]

Examples:
    udp 192.168.1.1 53 dns_query     # Send DNS query
    udp 10.0.0.1 123 ntp_request     # Send NTP request
    udp 192.168.1.1 5000 hello       # Send custom data

Security: Payload size limited
""")
    
    # ==================== ICMP Commands ====================
    
    def do_icmp(self, args):
        """
        Send ICMP packet: icmp <target> <type> [data]
        
        SECURITY:
        - Validates IP and ICMP type
        - Limits payload size
        """
        parser = argparse.ArgumentParser(prog='icmp')
        parser.add_argument('target', help='Target IP address')
        parser.add_argument('type', type=int, help='ICMP type (0=reply, 8=request, 11=time exceeded)')
        parser.add_argument('data', nargs='?', default='test', help='ICMP payload')
        
        try:
            parsed = parser.parse_args(args.split())
        except SystemExit:
            return
        
        # Validate inputs using ipaddress module
        valid, error = validate_ip_address(parsed.target)
        if not valid:
            print(ConsoleFormatter.error(f"Invalid target IP: {error}"))
            return
        if not 0 <= parsed.type <= 255:
            print(ConsoleFormatter.error("Invalid ICMP type (0-255)"))
            return
        
        payload = parsed.data.encode('utf-8')
        
        # Validate payload size
        if len(payload) > MAX_PAYLOAD_SIZE:
            print(ConsoleFormatter.error("Payload too large (max {} bytes)".format(MAX_PAYLOAD_SIZE)))
            return
        
        packet = self.icmp_forger.craft_icmp_echo(parsed.type, 0, 1, payload)
        
        # Wrap in IP header
        ip_packet = self.ipv4_forger.build_ipv4_packet(
            src_addr='0.0.0.0',
            dst_addr=parsed.target,
            protocol=socket.IPPROTO_ICMP,
            payload=packet,
            ttl=64
        )
        
        if self._send_packet(ip_packet, parsed.target):
            print(ConsoleFormatter.packet_sent(parsed.target, parsed.type, len(ip_packet)))
    
    def help_icmp(self):
        print("""
Send ICMP packet

Usage: icmp <target> <type> [data]

ICMP Types:
    0  - Echo Reply
    8  - Echo Request (ping)
    11 - Time Exceeded
    3  - Destination Unreachable

Examples:
    icmp 192.168.1.1 8                    # Ping request
    icmp 10.0.0.1 0                      # Echo reply
    icmp 192.168.1.1 11                  # Time exceeded

Security: Type and payload validated
""")
    
    # ==================== IPv6 Commands ====================
    
    def do_ipv6(self, args):
        """
        Send IPv6 SYN: ipv6 <target> <port>
        
        SECURITY:
        - Validates IPv6 address
        - Validates port number
        - Checks privileges before socket creation
        """
        parser = argparse.ArgumentParser(prog='ipv6')
        parser.add_argument('target', help='Target IPv6 address')
        parser.add_argument('port', type=int, help='Target port (0-65535)')
        
        try:
            parsed = parser.parse_args(args.split())
        except SystemExit:
            return
        
        # Validate IPv6 address
        valid, error = validate_ip_address(parsed.target, is_ipv6=True)
        if not valid:
            print(ConsoleFormatter.error(f"Invalid IPv6 address: {error}"))
            return
        valid, error = validate_port(parsed.port)
        if not valid:
            print(ConsoleFormatter.error(f"Invalid port: {error}"))
            return
        
        # Check if we still have privileges (we dropped them earlier)
        # IPv6 raw sockets require privileges, so this will likely fail
        try:
            # Try to create a temporary IPv6 socket
            sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IP_HDRINCL, 1)
            sock.sendto(b'\x00' * 40, (parsed.target, 0, 0, 0))
            sock.close()
        except PermissionError:
            print(ConsoleFormatter.error("Cannot create IPv6 socket - privileges required"))
            print(ConsoleFormatter.info("IPv6 raw sockets require root privileges"))
            return
        except Exception as e:
            print(ConsoleFormatter.error(f"IPv6 socket error: {e}"))
            return
        
        # Parse IPv6 address
        try:
            dst_addr_bytes = IPv6PacketForger.parse_ipv6_address(parsed.target)
        except Exception as e:
            print(ConsoleFormatter.error("Invalid IPv6 address: {}".format(e)))
            return
        
        packet = self.ipv6_forger.build_ipv6_tcp_syn(
            src_addr=b'\x00' * 16,
            dst_addr=dst_addr_bytes,
            src_port=12345,
            dst_port=parsed.port
        )
        
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IP_HDRINCL, 1)
            sock.sendto(packet, (parsed.target, 0, 0, 0))
            self._packets_sent.increment()
            self._bytes_sent.increment(len(packet))
            print(ConsoleFormatter.packet_sent(parsed.target, parsed.port, len(packet)))
            sock.close()
        except Exception as e:
            print(ConsoleFormatter.error("IPv6 send failed: {}".format(e)))
    
    def help_ipv6(self):
        print("""
Send IPv6 SYN packet

Usage: ipv6 <target> <port>

Examples:
    ipv6 2001:db8::1 80              # IPv6 SYN to port 80
    ipv6 fe80::1 443                 # Link-local IPv6

Security: IPv6 address validated
""")
    
    # ==================== Statistics ====================
    
    def do_stats(self, args):
        """Show statistics (thread-safe)"""
        elapsed = time.time() - self.start_time
        packets = self._packets_sent.get()
        bytes_sent = self._bytes_sent.get()
        rate = packets / elapsed if elapsed > 0 else 0
        
        # Get rate limit based on mode
        if self.operation_mode == OperationMode.EDUCATIONAL:
            rate_limit = MAX_RATE_EDU
        else:
            rate_limit = MAX_RATE_LIVE
        
        print("""
╔══════════════════════════════════╗
║ pp     PACKET STATISTICS         ║
╠══════════════════════════════════╣
║ Packets Sent:    {:>10}          ║
║ Bytes Sent:      {:>10}          ║
║ Duration:        {:>10.2f}s      ║
║ Send Rate:       {:>10.2f} p/s   ║
║ Rate Limit:      {:>10} p/s      ║
╚══════════════════════════════════╝
""".format(packets, bytes_sent, elapsed, rate, rate_limit))
    
    def help_stats(self):
        print("Show packet sending statistics")
    
    # ==================== PCAP Recording ====================
    
    def do_pcap(self, args):
        """
        Start PCAP recording: pcap <filename>
        
        SECURITY:
        - Validates filename with realpath
        - Limited file size
        - Prevents path traversal
        """
        if not args.strip():
            if self.pcap_writer:
                print(ConsoleFormatter.warning("PCAP recording to: {}".format(self.pcap_writer.filename)))
            else:
                print(ConsoleFormatter.error("No PCAP recording active"))
            return
        
        # Handle stop command
        if args.strip().lower() == 'stop':
            if self.pcap_writer:
                self.pcap_writer.close()
                print(ConsoleFormatter.success("PCAP recording stopped"))
                # Restore original send method
                if self._pcap_original_send:
                    self._send_packet = self._pcap_original_send
                    self._pcap_original_send = None
            else:
                print(ConsoleFormatter.error("No PCAP recording active"))
            return
        
        from packet_phantom.output.pcap_writer import PCAPWriter
        
        filename = args.strip()
        
        # SECURITY: Use comprehensive path validation
        try:
            validated_path = validate_safe_path(filename, allowed_base=os.getcwd())
        except ValueError as e:
            print(ConsoleFormatter.error(f"Invalid PCAP path: {e}"))
            return
        
        # Check if file already exists and is writable
        if os.path.exists(validated_path):
            if not os.access(validated_path, os.W_OK):
                print(ConsoleFormatter.error("Cannot write to existing file: {}".format(validated_path)))
                return
        
        # Store original send method before wrapping
        self._pcap_original_send = self._send_packet
        
        try:
            self.pcap_writer = PCAPWriter(validated_path)
            print(ConsoleFormatter.success("PCAP recording started: {}".format(validated_path)))
        except (OSError, PermissionError) as e:
            print(ConsoleFormatter.error(f"Failed to create PCAP file: {e}"))
            self._pcap_original_send = None
            return
        
        # Modify send to record
        original_send = self._send_packet
        def recording_send(packet, target):
            if self.pcap_writer:
                # Check file size limit
                try:
                    if os.path.getsize(self.pcap_writer.filename) > MAX_PCAP_SIZE:
                        print(ConsoleFormatter.warning("PCAP file size limit reached, stopping recording"))
                        self.pcap_writer.close()
                        self.pcap_writer = None
                        return original_send(packet, target)
                    self.pcap_writer.write_packet(packet)
                except OSError:
                    pass
            return original_send(packet, target)
        self._send_packet = recording_send
    
    def help_pcap(self):
        print("""
Start/stop PCAP recording

Usage: pcap <filename>   - Start recording to file
       pcap             - Show current recording file
       pcap stop        - Stop recording

Examples:
    pcap capture.pcap          # Start recording
    pcap                      # Show current file
    pcap stop                 - Stop recording

Security: File size limited to 100MB
Path validated against traversal attacks
""")
    
    # ==================== Evasion Commands ====================
    
    def do_evade(self, args):
        """Show evasion status"""
        print("""
╔══════════════════════════════════╗
║        EVASION SETTINGS          ║
╠══════════════════════════════════╣
║ TTL Mode:        Random          ║
║ TCP Options:     Randomized      ║
║ Fragmentation:   Disabled        ║
║ Padding:         Disabled        ║
╚══════════════════════════════════╝
""")
    
    def help_evade(self):
        print("Show current evasion settings")
    
    # ==================== Help System ====================
    
    def help_general(self):
        print("""
Available Commands:
    syn      - Send SYN packet
    flood    - Start SYN flood
    udp      - Send UDP packet
    icmp     - Send ICMP packet
    ipv6     - Send IPv6 packet
    stats    - Show statistics
    pcap     - PCAP recording
    evade    - Show evasion settings
    quit     - Exit shell
    
Type 'help <command>' for detailed help

Security Features:
- Privilege dropping to 'nobody' user
- Resource limits (100-200MB)
- Rate limiting
- Input validation
- Memory bounds enforcement
""")
    
    # ==================== Exit ====================
    
    def do_quit(self, args):
        """Exit the shell"""
        if self.socket:
            self.socket.close()
        
        elapsed = time.time() - self.start_time
        packets = self._packets_sent.get()
        print(ConsoleFormatter.success("Session complete: {} packets in {:.2f}s".format(packets, elapsed)))
        print(ConsoleFormatter.info("Goodbye!"))
        return True
    
    def do_exit(self, args):
        """Exit the shell"""
        return self.do_quit(args)
    
    def _do_EOF(self, args):
        """Handle Ctrl+D (EOF) - hidden from help"""
        print()  # Print newline for clean exit
        return self.do_quit(args)
    
    def get_hidden_commands(self):
        """Return list of commands to hide from help."""
        return ['EOF']
    
    # ==================== Completions ====================
    
    completenames = ['quit', 'exit', 'help', 'stats']
    
    def complete_syn(self, text, line, begidx, endidx):
        return [cmd for cmd in ['help'] if cmd.startswith(text)]
    
    def complete_udp(self, text, line, begidx, endidx):
        return [cmd for cmd in ['help'] if cmd.startswith(text)]


# ==================== MAIN ENTRY POINT ====================
def main():
    """
    Main entry point for interactive shell.
    
    SECURITY:
    - Checks for root privileges
    - Sets up secure environment
    """
    import sys
    
    # Check privileges
    try:
        socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except PermissionError:
        print("ERROR: Root privileges required")
        print("Run with: sudo python -m packet_phantom.interface.interactive_shell")
        sys.exit(1)
    
    # Print security info
    print(ConsoleFormatter.info("Security Features Active:"))
    print("  - Privilege dropping: Enabled (setuid)")
    print("  - Resource limits: {}-{}MB".format(
        RLIMIT_AS_SOFT // (1024*1024), RLIMIT_AS_HARD // (1024*1024)))
    print("  - Max packet size: {} bytes".format(MAX_PACKET_SIZE))
    print("  - Max rate (EDU): {} p/s".format(MAX_RATE_EDU))
    print("  - Max rate (LIVE): {} p/s".format(MAX_RATE_LIVE))
    print()
    
    # Run shell
    shell = PhantomShell()
    try:
        shell.cmdloop()
    except KeyboardInterrupt:
        print("\nInterrupted")
        shell.do_quit(None)


if __name__ == '__main__':
    main()
