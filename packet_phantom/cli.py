#!/usr/bin/env python3
"""
Packet Phantom v2.0 - Professional Network Testing Tool
=======================================================

A professional network testing tool for security researchers.

USAGE:
    pp [command] [options]

COMMANDS:
    scan        Perform port scanning (default)
    flood       Flood attack mode
    discover    Network discovery
    sniff       Sniff packets (requires root)
    os          OS fingerprinting commands
    db          Database management
    api         Start API server
    shell       Start interactive shell

GLOBAL OPTIONS:
    -t, --target <target>     Target IP, CIDR, or range
    -p, --ports <ports>       Ports to scan (default: 80,443)
    -r, --rate <rate>         Packet rate (packets/second)
    -T, --threads <num>       Worker threads
    -o, --output <file>       Output file
    -of, --format <fmt>        Output format
    -v, --verbose              Verbose output
    -s, --silent               Silent mode
    -h, --help                 Show help
    --version                  Show version

EVASION:
    --evasion <type>           ttl|options|fragmentation|padding
    --ttl <value>              TTL value
    --spoof                    Enable IP spoofing

EXAMPLES:
    pp scan -t 10.0.0.0/24 -p 80,443
    pp scan -t 192.168.1.1 -p 1-1000 -o results.json -of json
    pp os quick -t 192.168.1.1
    pp api --port 8080

For detailed help: pp --help
"""

import argparse
import sys
import os
import json
import time
import socket
import struct
import ipaddress
import re

from typing import Optional, List, Dict, Any

# FOR PERFORMANCE : Lazy import heavy modules only when needed
from .core.mode_manager import ModeManager, OperationMode
from .interface.banner import AdaptiveBanner
from .core.batch_sender import BatchSender, BatchConfig
from .core.raw_socket import is_root
from .core.async_engine import AsyncPacketEngine, AsyncConfig
from .core.multi_process_engine import MultiProcessEngine
from .evasion.evasion_suite import EvasionSuite, EvasionConfig
from .output.pcap_writer import PCAPWriter
from .security.rate_limiter import TokenBucket


# =============================================================================
# SECURITY CONSTANTS
# =============================================================================

MAX_DISCOVERY_HOSTS = 1000
MAX_THREADS_FACTOR = 2
MAX_PORT = 65535
MIN_PORT = 1
MAX_RATE_LIVE = 10000
MAX_RATE_EDU = 100
MAX_TTL = 255
MIN_TTL = 1
MAX_TIMEOUT = 300
MAX_RETRY = 10
ALLOWED_OUTPUT_FORMATS = {'json', 'csv', 'html', 'pcap'}
DANGEROUS_CHARS = re.compile(r'[;&|`$(){}[]|><\\\\]')


# =============================================================================
# COLOR CODES
# =============================================================================

class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    SUCCESS = GREEN
    ERROR = RED
    WARNING = YELLOW
    INFO = CYAN


def colored(text: str, color: str) -> str:
    if sys.stdout.isatty():
        return f"{color}{text}{Colors.RESET}"
    return text


def display_banner(mode: str, style: str = "full") -> None:
    # PERFORMANCE FIX: Lazy import AdaptiveBanner only when needed
    from .interface.banner import AdaptiveBanner
    banner = AdaptiveBanner(mode)
    print(banner.generate(style))


# =============================================================================
# PROFESSIONAL ARGUMENT PARSER
# =============================================================================

class ProfessionalParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        super().__init__(
            *args,
            prog="pp",
            description="Packet Phantom - Professional Network Testing Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            **kwargs
        )
    
    def print_usage(self, file=None):
        if file is None:
            file = sys.stdout
        file.write(colored("Usage: pp [options]\n", Colors.CYAN))
        file.write(colored("  -h, --help          Show help\n", Colors.RESET))
        file.write(colored("  -t, --target        Target specification\n", Colors.RESET))
        file.write(colored("  -p, --ports         Ports to scan\n", Colors.RESET))
    
    def print_help(self, file=None):
        if file is None:
            file = sys.stdout
        
        help_text = """
Packet Phantom v2.0 - Professional Network Testing Tool
=======================================================

USAGE:
    pp [command] [options]

COMMANDS:
    scan        Perform port scanning (default)
    flood       Flood attack mode
    discover    Network discovery
    sniff       Sniff packets (requires root)
    os          OS fingerprinting commands
    db          Database management
    api         Start API server
    shell       Start interactive shell

GLOBAL OPTIONS:
    -t, --target <target>     Target IP, CIDR, or range
    -p, --ports <ports>       Ports to scan (default: 80,443)
    -r, --rate <rate>         Packet rate (packets/second)
    -T, --threads <num>       Worker threads (default: 1)
    -o, --output <file>       Output file
    -of, --format <fmt>        Output format: json|csv|html|pcap|console
    -v, --verbose              Verbose output
    -s, --silent               Silent mode
    -b, --banner <style>       Banner style: full|compact|minimal
    --timeout <sec>           Response timeout (default: 5)
    --interface <name>        Network interface
    --ipv6                     Use IPv6 instead of IPv4
    --count <num>              Packets to send (default: 1)

EVASION:
    --evasion <type>           ttl|options|fragmentation|padding
    --ttl <value>              TTL value (1-255)
    --spoof                    Enable IP spoofing
    --payload <file>           Custom payload file

SERVICE & OS DETECTION:
    -sV, --service-detect      Enable service/version detection
    --version-intensity <0-9>  Version detection intensity (default: 7)
    -O, --os                   Enable OS fingerprinting
    --os-intensity <0-9>       OS detection intensity (default: 7)

PERFORMANCE:
    --async                    Use async I/O engine
    --multiprocess             Use multiprocess engine
    --workers <num>            Worker processes (default: 4)

EDUCATIONAL:
    --edu                      Educational mode (default: enabled)
    --no-edu                   Disable educational mode

INFO:
    --list-interfaces          List network interfaces
    --api                       Start API server
    --api-port <port>           API server port (default: 8080)
    --shell                     Start interactive shell

OS FINGERPRINTING:
    --os-quick                  Quick OS detection (5 probes, 2s timeout)
    --os-deep                   Deep OS fingerprinting (20+ probes)
    --os-forensic                Forensic mode (all probes, detailed)
    --os-learn                  Learn mode: create signature from response

DATABASE:
    --os-db-build [TARGET]      Build signature database
    --os-db-list                List all signatures
    --os-db-info                 Show database statistics
    --find-similar <sig>        Find similar signatures

HELP:
    -h, --help                  Show this help
    --version                    Show version
    --cite                       Show citation

EXAMPLES:
    pp scan -t 10.0.0.0/24 -p 80,443
    pp scan -t 192.168.1.1 -p 1-1000 -o results.json -of json
    pp os quick -t 192.168.1.1
    pp api --port 8080

For detailed help: pp <command> --help
"""
        file.write(colored(help_text, Colors.CYAN if sys.stdout.isatty() else None))
    
    def error(self, message):
        self.exit(2, f"{colored('[ERROR]', Colors.ERROR)} {message}\n")


# =============================================================================
# INPUT VALIDATION FUNCTIONS
# =============================================================================

def validate_positive_int(value: str, field_name: str, min_value: int = 1, max_value: Optional[int] = None) -> int:
    try:
        int_value = int(value)
    except (ValueError, TypeError):
        raise argparse.ArgumentTypeError(f"{field_name} must be an integer, got '{value}'")
    
    if int_value < min_value:
        raise argparse.ArgumentTypeError(f"{field_name} must be at least {min_value}, got {int_value}")
    
    if max_value is not None and int_value > max_value:
        raise argparse.ArgumentTypeError(f"{field_name} must be at most {max_value}, got {int_value}")
    
    return int_value


def validate_rate_value(value: str) -> int:
    try:
        rate = int(value)
    except (ValueError, TypeError):
        raise argparse.ArgumentTypeError(f"Rate must be an integer, got '{value}'")
    
    if rate < 1:
        raise argparse.ArgumentTypeError(f"Rate must be at least 1, got {rate}")
    
    return rate


def validate_threads_value(value: str) -> int:
    cpu_count = os.cpu_count() or 1
    max_threads = cpu_count * MAX_THREADS_FACTOR
    
    return validate_positive_int(value, "Threads", min_value=1, max_value=max_threads)


def validate_ttl_value(value: str) -> int:
    return validate_positive_int(value, "TTL", min_value=MIN_TTL, max_value=MAX_TTL)


def validate_timeout_value(value: str) -> int:
    return validate_positive_int(value, "Timeout", min_value=1, max_value=MAX_TIMEOUT)


def validate_retry_value(value: str) -> int:
    return validate_positive_int(value, "Retry", min_value=0, max_value=MAX_RETRY)


def sanitize_target(target: str) -> str:
    if not target or not target.strip():
        raise ValueError("Target cannot be empty")
    
    stripped = target.strip()
    
    if '\x00' in stripped:
        raise ValueError("Null byte in target - potential injection attack")
    
    import unicodedata
    stripped = unicodedata.normalize('NFC', stripped)
    stripped = stripped.replace('\x00', '')
    
    if DANGEROUS_CHARS.search(stripped):
        raise ValueError(f"Target contains invalid characters: {target}")
    
    if '..' in stripped:
        raise ValueError(f"Target contains path traversal attempt: {target}")
    
    # Reject common command strings that are not valid targets
    commands = {'scan', 'flood', 'discover', 'sniff', 'os', 'db', 'api', 'shell', 
                'help', 'version', 'cite', 'list', 'quick', 'deep', 'forensic', 'learn'}
    if stripped.lower() in commands:
        raise ValueError(f"'{stripped}' is a command, not a valid target")
    
    # Try to parse as IPv4
    try:
        ipaddress.IPv4Address(stripped)
        return stripped
    except ipaddress.AddressValueError:
        pass
    
    # Try to parse as IPv6
    try:
        ipaddress.IPv6Address(stripped)
        return stripped
    except ipaddress.AddressValueError:
        pass
    
    # Check for valid CIDR notation
    if '/' in stripped:
        try:
            network = ipaddress.ip_network(stripped, strict=False)
            return stripped
        except ValueError:
            pass
    
    # Check for IP range notation (e.g., 192.168.1.1-192.168.1.10)
    if '-' in stripped and not stripped.startswith('-'):
        parts = stripped.split('-')
        if len(parts) == 2:
            try:
                ipaddress.IPv4Address(parts[0].strip())
                ipaddress.IPv4Address(parts[1].strip())
                return stripped
            except ipaddress.AddressValueError:
                pass
    
    # Allow hostname (alphanumeric with dots/hyphens)
    if re.match(r"^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$", stripped):
        return stripped
    
    raise ValueError(f"Invalid target format: {target}")


def validate_output_path(path: str) -> str:
    if not path or not path.strip():
        raise ValueError("Output path cannot be empty")
    
    stripped = path.strip()
    
    if DANGEROUS_CHARS.search(stripped):
        raise ValueError(f"Output path contains invalid characters: {path}")
    
    if '..' in stripped:
        raise ValueError(f"Output path contains path traversal: {path}")
    
    sensitive_dirs = ['/etc/', '/root/', '/bin/', '/sbin/', '/usr/bin/', '/boot/']
    for sensitive in sensitive_dirs:
        if stripped.startswith(sensitive):
            raise ValueError(f"Cannot write to protected system directory: {path}")
    
    return stripped


def validate_payload_path(path: str) -> str:
    if not path or not path.strip():
        raise ValueError("Payload path cannot be empty")
    
    stripped = path.strip()
    
    if DANGEROUS_CHARS.search(stripped):
        raise ValueError(f"Payload path contains invalid characters: {path}")
    
    if not os.path.exists(stripped):
        raise ValueError(f"Payload file does not exist: {path}")
    
    if not os.path.isfile(stripped):
        raise ValueError(f"Payload path is not a file: {path}")
    
    return stripped


def validate_interface_name(name: str) -> str:
    if not name or not name.strip():
        raise ValueError("Interface name cannot be empty")
    
    stripped = name.strip()
    
    if not re.match(r'^[a-zA-Z0-9_-]+$', stripped):
        raise ValueError(f"Invalid interface name: {name}")
    
    if ';' in stripped or '|' in stripped or '&' in stripped:
        raise ValueError(f"Invalid interface name (command injection attempt): {name}")
    
    return stripped


def validate_port_spec(ports_str: str) -> str:
    if not ports_str or not ports_str.strip():
        raise ValueError("Port specification cannot be empty")
    
    stripped = ports_str.strip()
    
    if DANGEROUS_CHARS.search(stripped):
        raise ValueError(f"Port specification contains invalid characters: {ports_str}")
    
    parts = stripped.split(',')
    ports = set()
    
    for part in parts:
        part = part.strip()
        
        if not part:
            raise ValueError(f"Empty port specification in: {ports_str}")
        
        if '-' in part:
            range_parts = part.split('-')
            if len(range_parts) != 2:
                raise ValueError(f"Invalid port range: {part}")
            
            try:
                start = int(range_parts[0].strip())
                end = int(range_parts[1].strip())
            except ValueError:
                raise ValueError(f"Port range contains non-integer values: {part}")
            
            if start > end:
                raise ValueError(f"Invalid port range: {part} (start {start} > end {end}). Use {end}-{start} instead.")
            
            if start < MIN_PORT or start > MAX_PORT:
                raise ValueError(f"Port {start} out of range ({MIN_PORT}-{MAX_PORT})")
            if end < MIN_PORT or end > MAX_PORT:
                raise ValueError(f"Port {end} out of range ({MIN_PORT}-{MAX_PORT})")
            
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(part)
            except ValueError:
                raise ValueError(f"Invalid port specification: {part}")
            
            if port < MIN_PORT or port > MAX_PORT:
                raise ValueError(f"Port {port} out of range ({MIN_PORT}-{MAX_PORT})")
            
            ports.add(port)
    
    if not ports:
        raise ValueError(f"No valid ports in specification: {ports_str}")
    
    return stripped


# =============================================================================
# MODE MANAGEMENT
# =============================================================================

def detect_mode_from_args(args) -> "OperationMode":
    """Detect operation mode from arguments."""
    # PERFORMANCE FIX: Lazy import to avoid module-level import delay
    from .core.mode_manager import OperationMode
    if getattr(args, 'mode', None) == 'live':
        return OperationMode.LIVE
    else:
        return OperationMode.EDUCATIONAL


def enforce_rate_limit(rate: Optional[int], mode: "OperationMode") -> Optional[int]:
    """Enforce rate limits based on mode."""
    # PERFORMANCE FIX: Lazy import to avoid module-level import delay
    from .core.mode_manager import OperationMode
    
    if rate is None:
        return None
    
    max_rate = MAX_RATE_LIVE if mode == OperationMode.LIVE else MAX_RATE_EDU
    
    if rate > max_rate:
        rate = max_rate
    
    return rate


# =============================================================================
# BANNER DETECTION
# =============================================================================

def detect_service_banner(sock: socket.socket, timeout: float = 5.0) -> Optional[str]:
    """
    Attempt to detect service banner from open socket.
    
    Args:
        sock: Connected socket
        timeout: Read timeout in seconds
    
    Returns:
        Banner string or None
    """
    try:
        sock.settimeout(timeout)
        banner = sock.recv(1024, socket.MSG_PEEK)
        if banner:
            sock.recv(len(banner))  # Consume the data
            return banner.decode('utf-8', errors='ignore').strip()[:200]
    except socket.timeout:
        pass
    except Exception:
        pass
    return None


# =============================================================================
# MODE MANAGEMENT (already imported)
# =============================================================================

def safe_write_file(path: str, content: str) -> None:
    """Safely write to file with proper encoding."""
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)


def build_icmp_packet(dst_ip: str, src_ip: str, icmp_type: int, code: int) -> bytes:
    """Build ICMP packet for ping sweeps."""
    icmp_id = os.getpid() & 0xFFFF
    icmp_seq = 1
    
    # Create ICMP header
    icmp_checksum = 0
    header = struct.pack('!BBHHH', icmp_type, code, icmp_checksum, icmp_id, icmp_seq)
    
    # Create IP header
    ihl = 5
    version = 4
    tos = 0
    total_length = ihl * 4 + len(header) + 56  # ICMP header + 56 bytes data
    identification = os.getpid() & 0xFFFF
    flags = 0
    fragment_offset = 0
    ttl = 64
    protocol = socket.IPPROTO_ICMP
    checksum = 0
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)
    
    ip_header = struct.pack('!BBHHHBBH4s4s', 
                           (version << 4) | ihl, 
                           tos, 
                           total_length, 
                           identification, 
                           (flags << 13) | fragment_offset, 
                           ttl, 
                           protocol, 
                           checksum, 
                           src_addr, 
                           dst_addr)
    
    # Calculate checksums
    def checksum(data):
        s = 0
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                s += (data[i] << 8) + data[i+1]
            else:
                s += data[i] << 8
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF
    
    icmp_checksum = checksum(header + b'\x00' * 56)
    header = struct.pack('!BBHHH', icmp_type, code, icmp_checksum, icmp_id, icmp_seq)
    
    return ip_header + header + b'\x00' * 56


def build_icmpv6_packet(dst_ip: str, src_ip: str, icmp_type: int, code: int) -> bytes:
    """Build ICMPv6 packet."""
    # Simplified ICMPv6 echo request
    icmp_id = os.getpid() & 0xFFFF
    icmp_seq = 1
    
    # ICMPv6 header + data
    icmp_data = struct.pack('!HH', icmp_id, icmp_seq) + b'\x00' * 48
    
    # Pseudo-header for checksum calculation
    src_bytes = socket.inet_pton(socket.AF_INET6, src_ip)
    dst_bytes = socket.inet_pton(socket.AF_INET6, dst_ip)
    length = len(icmp_data) + 4  # +4 for upper layer length (ICMP type+code+checksum)
    zero = 0
    
    pseudo = src_bytes + dst_bytes + struct.pack('!I', length) + struct.pack('!I', zero) + struct.pack('!B', icmp_type) + struct.pack('!B', code) + icmp_data
    
    def checksum(data):
        s = 0
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                s += (data[i] << 8) + data[i+1]
            else:
                s += data[i] << 8
        s = (s >> 16) + (s & 0xFFFF)
        s += s >> 16
        return ~s & 0xFFFF
    
    icmp_checksum = checksum(pseudo)
    icmp_header = struct.pack('!BBHH', icmp_type, code, icmp_checksum, icmp_id) + struct.pack('!H', icmp_seq)
    
    # IPv6 header
    version = 6
    traffic_class = 0
    flow_label = 0
    payload_length = len(icmp_header) + 48
    next_header = socket.IPPROTO_ICMPV6
    hop_limit = 64
    
    ipv6_header = struct.pack('!IHBB', (version << 28) | (traffic_class << 20) | flow_label, 
                              payload_length, next_header, hop_limit) + src_bytes + dst_bytes
    
    return ipv6_header + icmp_header + b'\x00' * 48


def build_udp_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    """Build UDP packet."""
    # UDP header
    udp_length = 8  # header size
    checksum = 0
    udp_header = struct.pack('!HHHH', src_port, dst_port, udp_length, checksum)
    data = b'\x00' * 48  # payload
    
    # Pseudo-header for checksum
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)
    zero = 0
    protocol = socket.IPPROTO_UDP
    
    pseudo_length = 12 + len(udp_header) + len(data)
    pseudo_header = struct.pack('!HHBBH16s16s', 
                               src_port, dst_port, pseudo_length, zero, protocol,
                               src_addr, dst_addr)
    
    # IP header
    ihl = 5
    version = 4
    tos = 0
    total_length = ihl * 4 + len(udp_header) + len(data)
    identification = os.getpid() & 0xFFFF
    flags = 0
    fragment_offset = 0
    ttl = 64
    protocol = socket.IPPROTO_UDP
    checksum = 0
    
    ip_header = struct.pack('!BBHHHBBH4s4s', 
                           (version << 4) | ihl, 
                           tos, 
                           total_length, 
                           identification, 
                           (flags << 13) | fragment_offset, 
                           ttl, 
                           protocol, 
                           checksum, 
                           src_addr, 
                           dst_addr)
    
    return ip_header + udp_header + data


def build_tcp_syn_packet(src_ip: str, dst_ip: str, dst_port: int, ttl: int = 64, 
                        seq_num: int = 1000, src_port: int = 12345, 
                        window_size: int = 14600, 
                        evasion_suite: Optional["EvasionSuite"] = None) -> bytes:
    """Build TCP SYN packet."""
    # TCP header
    data_offset = 5
    reserved = 0
    flags = 0x02  # SYN flag
    urgent_pointer = 0
    checksum = 0
    options = b'\x02\x04\x05\xb4\x01\x03\x03\x08\x01\x01\x04\x02'  # MSS, SACK permitted, TSopt, WS
    
    tcp_header = struct.pack('!HHIIBBHHH', 
                            src_port, 
                            dst_port, 
                            seq_num, 
                            0,  # acknowledgment number
                            (data_offset << 4) | reserved, 
                            flags, 
                            window_size, 
                            checksum, 
                            urgent_pointer) + options
    
    # Pseudo-header for TCP checksum
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)
    zero = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
    
    pseudo_header = struct.pack('!HHBBH4s4s', 
                               src_port, dst_port, tcp_length, zero, protocol,
                               src_addr, dst_addr)
    
    # IP header
    ihl = 5
    version = 4
    tos = 0
    total_length = ihl * 4 + len(tcp_header)
    identification = os.getpid() & 0xFFFF
    flags = 0x02  # Don't fragment
    fragment_offset = 0
    checksum = 0
    
    ip_header = struct.pack('!BBHHHBBH4s4s', 
                           (version << 4) | ihl, 
                           tos, 
                           total_length, 
                           identification, 
                           (flags << 13) | fragment_offset, 
                           ttl, 
                           protocol, 
                           checksum, 
                           src_addr, 
                           dst_addr)
    
    return ip_header + tcp_header


def build_ipv6_tcp_syn_packet(src_ip: str, dst_ip: str, dst_port: int, ttl: int = 64,
                             seq_num: int = 1000, src_port: int = 12345,
                             window_size: int = 5840,
                             evasion_suite: Optional["EvasionSuite"] = None) -> bytes:
    """Build IPv6 TCP SYN packet."""
    src_bytes = socket.inet_pton(socket.AF_INET6, src_ip)
    dst_bytes = socket.inet_pton(socket.AF_INET6, dst_ip)
    
    # TCP header
    data_offset = 5
    reserved = 0
    flags = 0x02  # SYN
    urgent_pointer = 0
    checksum = 0
    options = b'\x02\x04\x05\xb4\x01\x01\x04\x02'  # MSS, SACK permitted
    
    tcp_header = struct.pack('!HHIIBBHHH',
                            src_port,
                            dst_port,
                            seq_num,
                            0,
                            (data_offset << 4) | reserved,
                            flags,
                            window_size,
                            checksum,
                            urgent_pointer) + options
    
    # IPv6 header
    version = 6
    traffic_class = 0
    flow_label = 0
    payload_length = len(tcp_header)
    next_header = socket.IPPROTO_TCP
    hop_limit = ttl
    
    ipv6_header = struct.pack('!IHBB', (version << 28) | (traffic_class << 20) | flow_label,
                              payload_length, next_header, hop_limit) + src_bytes + dst_bytes
    
    return ipv6_header + tcp_header


def send_packet_with_raw_socket(packet: bytes, dst_ip: str, is_ipv6: bool = False) -> bool:
    """Send packet using raw socket."""
    try:
        if is_ipv6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.sendto(packet, (dst_ip, 0))
        sock.close()
        return True
    except (socket.error, OSError) as e:
        print(colored(f"[!] Raw socket error: {e}", Colors.WARNING))
        return False


# =============================================================================
# OS FINGERPRINTING
# =============================================================================

PROBE_SEQUENCES = {
    'quick': {
        'timeout': 2.0,
        'probes': [
            ('TCP', 80, None),  # SYN to HTTP
            ('TCP', 443, None), # SYN to HTTPS
            ('TCP', 22, None),  # SYN to SSH
            ('TCP', 21, None),  # SYN to FTP
            ('TCP', 25, None),  # SYN to SMTP
        ]
    },
    'deep': {
        'timeout': 5.0,
        'probes': [
            ('TCP', 80, None),
            ('TCP', 443, None),
            ('TCP', 22, None),
            ('TCP', 21, None),
            ('TCP', 25, None),
            ('TCP', 53, None),
            ('TCP', 110, None), # POP3
            ('TCP', 143, None), # IMAP
            ('TCP', 3306, None),# MySQL
            ('TCP', 3389, None),# RDP
        ]
    },
    'forensic': {
        'timeout': 10.0,
        'probes': [
            ('TCP', 80, None),
            ('TCP', 443, None),
            ('TCP', 22, None),
            ('TCP', 21, None),
            ('TCP', 25, None),
            ('TCP', 53, None),
            ('TCP', 110, None),
            ('TCP', 143, None),
            ('TCP', 445, None), # SMB
            ('TCP', 3306, None),
            ('TCP', 3389, None),
            ('TCP', 5432, None),# PostgreSQL
            ('TCP', 5900, None),# VNC
        ]
    }
}

# OS Fingerprint signatures (simplified)
OS_SIGNATURES = {
    'Windows': {
        'window_size': 8192,
        'ttl': 128,
        'tcp_options': ['MSS:1460', 'WS:8', 'SACK_PERM', 'TSopt'],
        'flags': 'SAF'
    },
    'Linux': {
        'window_size': 5840,
        'ttl': 64,
        'tcp_options': ['MSS:1460', 'SACK_PERM', 'TSopt', 'EOL'],
        'flags': 'SAF'
    },
    'macOS': {
        'window_size': 65535,
        'ttl': 64,
        'tcp_options': ['MSS:1460', 'SACK_PERM', 'TSopt'],
        'flags': 'SAF'
    },
    'FreeBSD': {
        'window_size': 5840,
        'ttl': 64,
        'tcp_options': ['MSS:1460', 'SACK_PERM', 'WS:8'],
        'flags': 'SAF'
    },
    'Cisco_IOS': {
        'window_size': 4128,
        'ttl': 255,
        'tcp_options': ['MSS:1460'],
        'flags': 'SAF'
    }
}


def send_os_probe(target: str, port: int, timeout: float, probe_type: str = 'TCP') -> Dict[str, Any]:
    """Send OS detection probe and analyze response."""
    result = {
        'port': port,
        'response': False,
        'ttl': 64,
        'window_size': 0,
        'options': [],
        'flags': '',
        'rtt': 0.0
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start_time = time.time()
        
        try:
            result_code = sock.connect_ex((target, port))
            elapsed = time.time() - start_time
            result['rtt'] = elapsed * 1000  # Convert to ms
            
            if result_code == 0:
                # Port is open - analyze socket properties
                result['response'] = True
                result['window_size'] = sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
                
                # Try to get more info from socket
                try:
                    # Get TCP info if available (Linux)
                    pass
                except:
                    pass
                
                sock.close()
                
        except socket.timeout:
            result['response'] = False
        except Exception:
            result['response'] = False
    
    except Exception as e:
        result['error'] = str(e)
    
    return result


def analyze_os_response(probe_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    Comprehensive OS response analysis using multi-factor detection.
    
    Scoring priority:
    1. Window size + TTL combination (best discriminator)
    2. TCP options (MSS, SACK, ECN, Timestamps, WScale)
    3. Port and service signatures
    4. TTL alone (last resort)
    """
    os_match = {
        'os_family': 'Unknown',
        'os_version': 'Unknown',
        'confidence': 0.0,
        'signature_id': None,
        'reasons': [],
        'factors': {},
        'scores': {}
    }
    
    if not probe_result:
        return os_match
    
    # Extract ALL available fields
    ttl = probe_result.get('ttl', 64)
    window_size = probe_result.get('window_size', 0)
    mss = probe_result.get('mss', 0)
    flags = probe_result.get('flags', 0)
    src_port = probe_result.get('src_port', 0)
    dst_port = probe_result.get('dst_port', 0)
    sack_permitted = probe_result.get('sack_permitted', False)
    timestamp = probe_result.get('timestamp', False)
    ecn = probe_result.get('ecn', False)
    wscale = probe_result.get('wscale', None)
    
    # Initialize scoring dictionary
    os_scores = {
        'Windows10_11': 0.0,
        'Windows_Server': 0.0,
        'Windows_Legacy': 0.0,
        'macOS': 0.0,
        'Linux': 0.0,
        'FreeBSD': 0.0,
        'Cisco': 0.0,
        'Juniper': 0.0
    }
    
    # ========== FACTOR 1: WINDOW SIZE (MOST IMPORTANT) ==========
    # Window size is the single best OS discriminator
    
    if window_size == 65535:
        # This is the KEY discriminator between macOS and Linux
        if ttl == 64:
            os_scores['macOS'] += 0.40  # macOS almost always: TTL=64, Window=65535
            os_match['factors']['window_size'] = 'macOS signature (65535)'
        elif ttl == 128:
            os_scores['Windows10_11'] += 0.20  # Windows rare but possible
            os_match['factors']['window_size'] = 'Large window (65535)'
        else:
            os_scores['Linux'] += 0.15  # Some Linux variants
            os_match['factors']['window_size'] = 'Large window (65535)'
            
    elif window_size in [64960, 65535 - 575]:  # Windows adjusted window
        os_scores['Windows10_11'] += 0.35
        os_match['factors']['window_size'] = 'Windows signature (64960)'
        
    elif window_size in [8192, 16384, 32768]:  # Typical Windows
        os_scores['Windows10_11'] += 0.30
        os_scores['Windows_Server'] += 0.25
        os_match['factors']['window_size'] = f'Windows typical ({window_size})'
        
    elif window_size in [5840, 5792]:  # Linux modern
        os_scores['Linux'] += 0.35
        os_match['factors']['window_size'] = f'Linux typical ({window_size})'
        
    elif window_size in [32768, 65535]:  # BSD/Linux
        if ttl == 64:
            os_scores['FreeBSD'] += 0.20
            os_scores['Linux'] += 0.25
            os_match['factors']['window_size'] = 'Linux/BSD typical'
        else:
            os_match['factors']['window_size'] = 'Large window (BSD/Linux)'
        
    elif window_size > 0:
        # Unknown window, use TTL to break tie
        os_match['factors']['window_size'] = f'Uncommon window ({window_size})'
    
    # ========== FACTOR 2: TTL (WITH WINDOW CONTEXT) ==========
    # TTL is important but NOT the primary discriminator
    
    if ttl == 64:
        # Could be Linux, FreeBSD, macOS, Solaris, Android
        os_scores['Linux'] += 0.20
        os_scores['FreeBSD'] += 0.15
        os_scores['macOS'] += 0.15  # Important: macOS also has TTL=64!
        os_match['factors']['ttl'] = 'TTL=64 (Linux/BSD/macOS)'
        
    elif ttl == 128:
        # Almost certainly Windows
        os_scores['Windows10_11'] += 0.25
        os_scores['Windows_Server'] += 0.20
        os_scores['Windows_Legacy'] += 0.15
        os_match['factors']['ttl'] = 'TTL=128 (Windows)'
        
    elif ttl == 255 or ttl >= 250:
        # Network device (Cisco, Juniper, etc.)
        os_scores['Cisco'] += 0.40
        os_scores['Juniper'] += 0.35
        os_match['factors']['ttl'] = 'TTL=255 (Network Device)'
        
    elif ttl in [100, 101, 102, 103, 104]:  # Google style decrement
        os_scores['Linux'] += 0.15
        os_match['factors']['ttl'] = f'TTL={ttl} (Cloud Linux)'
        
    elif 64 < ttl < 128:
        # Decrement from 128 (Windows with intermediate hops)
        os_scores['Windows10_11'] += 0.10
        os_scores['Windows_Legacy'] += 0.08
        os_match['factors']['ttl'] = f'TTL={ttl} (Windows with hops)'
        
    # ========== FACTOR 3: MSS VALUE ==========
    
    if mss == 1460:
        # Ethernet MTU - very common
        os_scores['Linux'] += 0.10
        os_scores['Windows10_11'] += 0.10
        os_scores['macOS'] += 0.08
        os_match['factors']['mss'] = 'MSS=1460 (Ethernet)'
        
    elif mss == 1452:
        # PPPoE
        os_scores['Linux'] += 0.08
        os_match['factors']['mss'] = 'MSS=1452 (PPPoE)'
        
    elif mss == 536:
        # Conservative/old
        os_scores['Windows_Legacy'] += 0.15
        os_match['factors']['mss'] = 'MSS=536 (Conservative)'
        
    # ========== FACTOR 4: TCP OPTIONS ==========
    
    # SACK Permitted
    if sack_permitted:
        os_scores['Linux'] += 0.08
        os_scores['FreeBSD'] += 0.08
        os_scores['macOS'] += 0.06
        os_match['factors']['sack'] = 'SACK Permitted'
    else:
        os_scores['Windows10_11'] += 0.05
        os_match['factors']['sack'] = 'SACK Not Permitted'
    
    # Timestamps
    if timestamp:
        os_scores['Linux'] += 0.08
        os_scores['Windows10_11'] += 0.08
        os_scores['macOS'] += 0.07
        os_match['factors']['timestamp'] = 'Timestamps Present'
    else:
        os_scores['Windows_Legacy'] += 0.10
        os_match['factors']['timestamp'] = 'No Timestamps'
    
    # ECN (Explicit Congestion Notification)
    if ecn:
        os_scores['Linux'] += 0.08
        os_scores['macOS'] += 0.08
        os_match['factors']['ecn'] = 'ECN Capable'
    else:
        os_scores['Windows_Legacy'] += 0.05
        os_match['factors']['ecn'] = 'ECN Not Capable'
    
    # Window Scaling
    if wscale is not None and wscale > 0:
        if wscale >= 7:
            os_scores['Linux'] += 0.08
            os_scores['Windows10_11'] += 0.06
            os_match['factors']['wscale'] = f'WScale={wscale} (Modern)'
        else:
            os_scores['macOS'] += 0.10  # macOS typically uses 5-6
            os_match['factors']['wscale'] = f'WScale={wscale} (Conservative)'
    
    # ========== FACTOR 5: PORT SIGNATURES ==========
    
    if dst_port == 22:  # SSH
        os_scores['Linux'] += 0.15
        os_scores['FreeBSD'] += 0.10
        os_match['factors']['port'] = 'SSH (port 22) - Linux indicator'
        
    elif dst_port == 3389:  # RDP
        os_scores['Windows10_11'] += 0.25
        os_scores['Windows_Server'] += 0.20
        os_match['factors']['port'] = 'RDP (port 3389) - Windows'
        
    elif dst_port == 548:  # AFP
        os_scores['macOS'] += 0.30
        os_match['factors']['port'] = 'AFP (port 548) - macOS'
        
    elif dst_port == 5353:  # Bonjour/mDNS
        os_scores['macOS'] += 0.20
        os_match['factors']['port'] = 'Bonjour (port 5353) - macOS'
    
    # ========== CALCULATE FINAL SCORE ==========
    
    # Find highest score
    best_os = max(os_scores.items(), key=lambda x: x[1])
    best_os_name, best_score = best_os
    
    # Store all scores for debugging
    os_match['scores'] = os_scores
    
    # Map to display name
    os_mapping = {
        'Windows10_11': 'Windows 10/11',
        'Windows_Server': 'Windows Server',
        'Windows_Legacy': 'Windows (Legacy)',
        'macOS': 'macOS',
        'Linux': 'Linux',
        'FreeBSD': 'FreeBSD',
        'Cisco': 'Cisco IOS',
        'Juniper': 'Juniper'
    }
    
    # Normalize confidence (0-1)
    max_possible_score = 2.0  # Approximate maximum
    normalized_confidence = min(100.0, (best_score / max_possible_score) * 100)
    
    os_match['os_family'] = os_mapping.get(best_os_name, best_os_name)
    os_match['confidence'] = normalized_confidence
    
    # Build reasons (take top 3 factors)
    reason_count = 0
    for factor, value in os_match['factors'].items():
        if reason_count < 3:
            os_match['reasons'].append(value)
            reason_count += 1
    
    # Add confidence explanation
    if normalized_confidence >= 80:
        os_match['reasons'].append('Confidence: VERY HIGH (80%+)')
    elif normalized_confidence >= 60:
        os_match['reasons'].append('Confidence: HIGH (60-80%)')
    elif normalized_confidence >= 40:
        os_match['reasons'].append('Confidence: MODERATE (40-60%)')
    else:
        os_match['reasons'].append('Confidence: LOW (<40%)')
    
    return os_match


def perform_os_fingerprinting(target: str, mode: str = 'quick', timeout: float = 2.0) -> Dict[str, Any]:
    """Perform OS fingerprinting on target."""
    probe_config = PROBE_SEQUENCES.get(mode, PROBE_SEQUENCES['quick'])
    timeout = probe_config['timeout']
    
    results = {
        'target': target,
        'mode': mode,
        'probes_sent': 0,
        'responses': [],
        'os_guess': 'Unknown',
        'confidence': 0.0,
        'details': []
    }
    
    for proto, port, _ in probe_config['probes']:
        results['probes_sent'] += 1
        
        probe_result = send_os_probe(target, port, timeout, proto)
        results['responses'].append(probe_result)
        
        if probe_result.get('response'):
            os_analysis = analyze_os_response(probe_result)
            results['details'].append(os_analysis)
    
    # Aggregate results
    if results['details']:
        # Find most common OS family
        os_families = [d['os_family'] for d in results['details'] if d['os_family']]
        if os_families:
            from collections import Counter
            most_common = Counter(os_families).most_common(1)[0]
            results['os_guess'] = most_common[0]
            results['confidence'] = most_common[1] / len(os_families)
    
    return results


# =============================================================================
# DATABASE OPERATIONS
# =============================================================================

def handle_os_fingerprinting(args) -> Dict[str, Any]:
    """Handle OS fingerprinting command."""
    target = args.target
    
    if not target:
        raise ValueError("Target is required for OS fingerprinting")
    
    mode = 'quick'
    if args.os_deep:
        mode = 'deep'
    elif args.os_forensic:
        mode = 'forensic'
    
    timeout = getattr(args, 'timeout', 5)
    
    result = perform_os_fingerprinting(target, mode, timeout)
    
    print(colored(f"\n[+] OS Fingerprinting Results for {target}", Colors.SUCCESS))
    print(colored(f"    Mode: {mode.upper()}", Colors.INFO))
    print(colored(f"    OS Guess: {result['os_guess']}", Colors.INFO))
    print(colored(f"    Confidence: {result['confidence']:.1%}", Colors.INFO))
    
    if result.get('details'):
        print(colored("\n    Probe Details:", Colors.CYAN))
        for detail in result['details']:
            if detail.get('reasons'):
                print(colored(f"      - {', '.join(detail['reasons'][:2])}", Colors.INFO))
    
    return result


def handle_os_db_list() -> None:
    """List OS signatures in database."""
    try:
        from packet_phantom.core.signature_db_v2 import SignatureDatabaseV2
    except ImportError:
        print(colored("  SignatureDatabaseV2 module not found. Database features unavailable.", Colors.ERROR))
        return
    
    try:
        db = SignatureDatabaseV2()
        signatures = db.list_signatures()
        
        print(colored("\n=== OS Signature Database ===\n", Colors.INFO))
        
        if signatures:
            for sig_id in signatures:
                print(colored(f"  • {sig_id}", Colors.CYAN))
        else:
            print(colored("  No signatures found. Use --os-db-build to create signatures.", Colors.WARNING))
    except Exception as e:
        print(colored(f"  Error accessing database: {e}", Colors.ERROR))


def handle_os_db_info() -> Dict[str, Any]:
    """Show database statistics."""
    try:
        from packet_phantom.core.signature_db_v2 import SignatureDatabaseV2
    except ImportError:
        print(colored("  SignatureDatabaseV2 module not found. Database features unavailable.", Colors.ERROR))
        return {'error': 'Module not found'}
    
    try:
        db = SignatureDatabaseV2()
        stats = db.get_stats()
        
        print(colored("\n=== Database Statistics ===\n", Colors.INFO))
        print(colored(f"  Total Signatures: {stats.get('total', 0)}", Colors.CYAN))
        print(colored(f"  Database Size: {stats.get('size', 'Unknown')}", Colors.CYAN))
        
        return stats
    except Exception as e:
        print(colored(f"  Error accessing database: {e}", Colors.ERROR))
        return {'error': str(e)}


def handle_os_db_build(targets: List[str], args) -> Dict[str, Any]:
    """Build signature database from target responses."""
    try:
        from packet_phantom.core.signature_db_v2 import SignatureDatabaseV2
    except ImportError:
        print(colored("  SignatureDatabaseV2 module not found. Database features unavailable.", Colors.ERROR))
        return {'error': 'Module not found', 'targets': targets, 'signatures_created': 0, 'errors': ['Module not found']}
    
    if not targets:
        targets = ['127.0.0.1']
    
    results = {
        'targets': targets,
        'signatures_created': 0,
        'errors': []
    }
    
    try:
        db = SignatureDatabaseV2()
    except Exception as e:
        results['errors'].append(f"Failed to initialize database: {e}")
        return results
    
    for target in targets:
        try:
            print(colored(f"[*] Probing target: {target}", Colors.INFO))
            
            # Perform quick fingerprinting
            fp_result = perform_os_fingerprinting(target, 'quick', 2.0)
            
            if fp_result['os_guess'] != 'Unknown':
                signature_id = f"{fp_result['os_guess']}_{target.replace('.', '_')}"
                
                signature = {
                    'structure': {
                        'metadata': {
                            'target_os': fp_result['os_guess'],
                            'target_ip': target,
                            'confidence': fp_result['confidence'],
                            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                            'version': '2.0'
                        },
                        'probe_responses': {
                            'tcp_syn_ack': {
                                'window_size': fp_result['details'][0].get('window_size', 0) if fp_result['details'] else 0,
                                'ttl': 64,
                                'flags': 'SAF'
                            }
                        }
                    }
                }
                
                db.save(signature_id, signature)
                results['signatures_created'] += 1
                print(colored(f"[+] Created signature: {signature_id}", Colors.SUCCESS))
            else:
                results['errors'].append(f"Could not identify OS for {target}")
        
        except Exception as e:
            results['errors'].append(f"{target}: {str(e)}")
            print(colored(f"[!] Error probing {target}: {e}", Colors.ERROR))
    
    print(colored(f"\n[+] Build complete. Created {results['signatures_created']} signatures.", Colors.SUCCESS))
    
    return results


def handle_os_find_similar(signature_id: str) -> List[Dict[str, Any]]:
    """Find signatures similar to a given signature."""
    try:
        from packet_phantom.core.signature_db_v2 import SignatureDatabaseV2
    except ImportError:
        print(colored(f"[!] SignatureDatabaseV2 module not found. Database features unavailable.", Colors.ERROR))
        return []
    
    try:
        db = SignatureDatabaseV2()
    except Exception as e:
        print(colored(f"[!] Error initializing database: {e}", Colors.ERROR))
        return []
    
    # Load target signature
    target_sig = db.load(signature_id)
    if not target_sig:
        print(colored(f"[!] Signature not found: {signature_id}", Colors.ERROR))
        return []
    
    target_os = target_sig.get('structure', {}).get('metadata', {}).get('target_os', 'Unknown')
    
    print(colored(f"\nFinding signatures similar to: {signature_id}", Colors.INFO))
    print(colored(f"Target OS: {target_os}\n", Colors.INFO))
    
    all_sigs = db.load_all()
    
    def calculate_similarity(sig1: Dict, sig2: Dict) -> float:
        score = 0.0
        factors = 0
        
        os1 = sig1.get('structure', {}).get('metadata', {}).get('target_os', '')
        os2 = sig2.get('structure', {}).get('metadata', {}).get('target_os', '')
        if os1 == os2:
            score += 1.0
        factors += 1
        
        win1 = sig1.get('structure', {}).get('probe_responses', {}).get('tcp_syn_ack', {}).get('window_size', 0)
        win2 = sig2.get('structure', {}).get('probe_responses', {}).get('tcp_syn_ack', {}).get('window_size', 0)
        if win1 == win2:
            score += 0.5
        elif min(win1, win2) > 0:
            diff = abs(win1 - win2) / max(win1, win2)
            score += max(0, 1 - diff)
        factors += 1
        
        ttl1 = sig1.get('structure', {}).get('probe_responses', {}).get('tcp_syn_ack', {}).get('ttl', 64)
        ttl2 = sig2.get('structure', {}).get('probe_responses', {}).get('tcp_syn_ack', {}).get('ttl', 64)
        if ttl1 == ttl2:
            score += 0.5
        else:
            diff = abs(ttl1 - ttl2) / 255
            score += max(0, 1 - diff)
        factors += 1
        
        return score / factors if factors > 0 else 0
    
    similarities = []
    for sig_id, sig in all_sigs.items():
        if sig_id != signature_id:
            score = calculate_similarity(target_sig, sig)
            similarities.append({
                'signature_id': sig_id,
                'similarity': score,
                'os': sig.get('structure', {}).get('metadata', {}).get('target_os', 'Unknown')
            })
    
    similarities.sort(key=lambda x: x['similarity'], reverse=True)
    
    print(colored("Similar Signatures:\n", Colors.CYAN))
    
    for sim in similarities[:10]:
        bar = "█" * int(sim['similarity'] * 20) + "░" * (20 - int(sim['similarity'] * 20))
        print(colored(f"  {bar} {sim['similarity']:.1%}  {sim['signature_id']}", Colors.INFO))
    
    return similarities


def handle_compare_databases(other_db_path: str) -> Dict[str, Any]:
    """Compare current database with another database file."""
    try:
        from packet_phantom.core.signature_db_v2 import SignatureDatabaseV2
    except ImportError:
        print(colored("[!] SignatureDatabaseV2 module not found. Database features unavailable.", Colors.ERROR))
        return {'error': 'Module not found'}
    
    try:
        db = SignatureDatabaseV2()
        current_sigs = db.load_all()
    except Exception as e:
        print(colored(f"[!] Error loading current database: {e}", Colors.ERROR))
        return {'error': str(e)}
    
    # Try to load other database
    try:
        other_db = SignatureDatabaseV2()
        # Load from specified path if it's a file
        if os.path.isfile(other_db_path):
            with open(other_db_path, 'r') as f:
                other_sigs = json.load(f)
        else:
            other_sigs = other_db.load_all()
    except Exception as e:
        print(colored(f"[!] Error loading other database: {e}", Colors.ERROR))
        return {'error': str(e)}
    
    # Compare signatures
    current_ids = set(current_sigs.keys())
    other_ids = set(other_sigs.keys())
    
    comparison = {
        'current_db_count': len(current_ids),
        'other_db_count': len(other_ids),
        'unique_to_current': list(current_ids - other_ids),
        'unique_to_other': list(other_ids - current_ids),
        'common': list(current_ids & other_ids),
        'total_unique': len(current_ids | other_ids),
        'similarity_score': len(current_ids & other_ids) / len(current_ids | other_ids) if (current_ids | other_ids) else 0
    }
    
    print(colored(f"\nDatabase Comparison Report", Colors.INFO))
    print(colored(f"Current DB signatures: {comparison['current_db_count']}", Colors.CYAN))
    print(colored(f"Other DB signatures: {comparison['other_db_count']}", Colors.CYAN))
    print(colored(f"Common signatures: {len(comparison['common'])}", Colors.GREEN))
    print(colored(f"Unique to current: {len(comparison['unique_to_current'])}", Colors.YELLOW))
    print(colored(f"Unique to other: {len(comparison['unique_to_other'])}", Colors.YELLOW))
    print(colored(f"Overall similarity: {comparison['similarity_score']:.1%}", Colors.CYAN))
    
    return comparison


# =============================================================================
# OUTPUT FUNCTIONS
# =============================================================================

def output_result(target: str, port: int, status: str, service_version: str = "") -> None:
    """Print result in ffuf style."""
    symbols = {
        "open": colored("[+]", Colors.SUCCESS),
        "closed": colored("[-]", Colors.ERROR),
        "filtered": colored("[?]", Colors.WARNING),
        "timeout": colored("[T]", Colors.WARNING),
        "error": colored("[!]", Colors.ERROR),
    }
    symbol = symbols.get(status, colored("[*]", Colors.INFO))
    status_str = colored(status.upper(), Colors.SUCCESS if status == "open" else Colors.INFO)
    
    if service_version:
        print(f"{symbol} {target}:{port} {status_str} {service_version}")
    else:
        print(f"{symbol} {target}:{port} {status_str}")


def output_summary(total: int, open_count: int, closed_count: int, filtered_count: int, error_count: int, rate: float) -> None:
    """Print scan summary."""
    print(colored(f"\n{'='*60}", Colors.INFO))
    print(colored("  Scan Complete", Colors.BOLD))
    print(colored(f"{'='*60}", Colors.INFO))
    print(colored(f"  Total:     {total:,}", Colors.INFO))
    print(colored(f"  Open:     {open_count:,}", Colors.SUCCESS))
    print(colored(f"  Closed:   {closed_count:,}", Colors.ERROR))
    print(colored(f"  Filtered: {filtered_count:,}", Colors.WARNING))
    print(colored(f"  Errors:   {error_count:,}", Colors.ERROR))
    print(colored(f"  Rate:     {rate:.1f} pkt/s", Colors.INFO))
    print(colored(f"{'='*60}\n", Colors.INFO))


def output_error(message: str) -> None:
    print(colored(f"[✗] {message}", Colors.ERROR))


def output_warning(message: str) -> None:
    print(colored(f"[⚠] {message}", Colors.WARNING))


def output_info(message: str) -> None:
    print(colored(f"[ℹ] {message}", Colors.INFO))


def output_debug(message: str) -> None:
    print(colored(f"[🔍] {message}", Colors.CYAN))


# =============================================================================
# TARGET PARSING
# =============================================================================

def parse_target(target: str) -> Dict[str, Any]:
    """Parse target string into components with security validation."""
    sanitized = sanitize_target(target)
    
    if '/' in sanitized:
        try:
            network = ipaddress.ip_network(sanitized, strict=True)
            host_count = network.num_addresses - 2 if network.num_addresses > 2 else network.num_addresses
            
            if host_count > MAX_DISCOVERY_HOSTS:
                raise ValueError(
                    f"Network {sanitized} contains {host_count} hosts, "
                    f"which exceeds the maximum of {MAX_DISCOVERY_HOSTS}."
                )
            
            return {
                "type": "cidr",
                "network": str(network.network_address),
                "broadcast": str(network.broadcast_address),
                "mask": network.prefixlen,
                "hosts": [str(h) for h in network.hosts()]
            }
        except ipaddress.NetmaskValueError as e:
            raise ValueError(f"Invalid CIDR netmask: {e}")
        except ValueError as e:
            if "exceeds the maximum" in str(e):
                raise
            pass
    
    if '-' in sanitized:
        parts = sanitized.split('-')
        if len(parts) == 2:
            try:
                start = ipaddress.ip_address(parts[0])
                end = ipaddress.ip_address(parts[1])
                
                host_count = int(end) - int(start) + 1
                if host_count > MAX_DISCOVERY_HOSTS:
                    raise ValueError(
                        f"IP range {sanitized} contains {host_count} hosts, "
                        f"which exceeds the maximum of {MAX_DISCOVERY_HOSTS}."
                    )
                
                return {
                    "type": "range",
                    "start": str(start),
                    "end": str(end),
                    "hosts": [str(ipaddress.ip_address(i)) for i in range(int(start), int(end) + 1)]
                }
            except ipaddress.AddressValueError as e:
                raise ValueError(f"Invalid IP address in range: {e}")
            except ValueError as e:
                if "exceeds the maximum" in str(e):
                    raise
                pass
    
    try:
        ip = ipaddress.ip_address(sanitized)
        return {
            "type": "ip",
            "value": str(ip)
        }
    except ipaddress.AddressValueError:
        pass
    
    try:
        ip = socket.gethostbyname(sanitized)
        return {
            "type": "hostname",
            "hostname": sanitized,
            "resolved": ip
        }
    except socket.gaierror:
        pass
    
    raise ValueError(f"Invalid target specification: {target}")


def parse_ports(ports_str: str) -> List[int]:
    """Parse port specification string."""
    validate_port_spec(ports_str)
    
    ports = set()
    
    for part in ports_str.split(','):
        part = part.strip()
        
        if '-' in part:
            range_parts = part.split('-')
            if len(range_parts) == 2:
                try:
                    start = int(range_parts[0])
                    end = int(range_parts[1])
                    ports.update(range(start, end + 1))
                    continue
                except ValueError:
                    pass
        
        try:
            port = int(part)
            if MIN_PORT <= port <= MAX_PORT:
                ports.add(port)
        except ValueError:
            pass
    
    return sorted(list(ports))


# =============================================================================
# OUTPUT FORMATTERS
# =============================================================================

def format_output_json(results: List[Dict], args) -> str:
    """Format results as JSON."""
    output_data = {
        'target': args.target,
        'ports': args.ports,
        'results': results,
        'summary': {
            'total': len(results),
            'open': sum(1 for r in results if r.get('status') == 'open'),
            'closed': sum(1 for r in results if r.get('status') == 'closed')
        },
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
    }
    return json.dumps(output_data, indent=2)


def format_output_csv(results: List[Dict]) -> str:
    """Format results as CSV."""
    lines = ["target,port,status,info"]
    for r in results:
        lines.append(f"{r.get('target','')},{r.get('port','')},{r.get('status','')},{r.get('info','')}")
    return "\n".join(lines)


def format_output_html(results: List[Dict]) -> str:
    """Format results as HTML with proper entity escaping."""
    import html
    
    def escape_html(value: str) -> str:
        if value is None:
            return ''
        return html.escape(str(value), quote=True)
    
    open_count = sum(1 for r in results if r.get('status') == 'open')
    closed_count = sum(1 for r in results if r.get('status') == 'closed')
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Packet Phantom Results</title>
    <style>
        body {{ font-family: monospace; background: #1a1a1a; color: #e0e0e0; padding: 20px; }}
        h1 {{ color: #00ff00; }}
        .summary {{ background: #333; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .open {{ color: #00ff00; }}
        .closed {{ color: #ff4444; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #444; padding: 8px; text-align: left; }}
        th {{ background: #333; }}
    </style>
</head>
<body>
    <h1>Packet Phantom v2.0.0 - Scan Results</h1>
    <div class="summary">
        <h2>Summary</h2>
        <p>Open Ports: <span class="open">{open_count}</span></p>
        <p>Closed Ports: <span class="closed">{closed_count}</span></p>
        <p>Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    <table>
        <tr><th>Target</th><th>Port</th><th>Status</th><th>Info</th></tr>
"""
    
    for r in results:
        status_class = 'open' if r.get('status') == 'open' else 'closed'
        html_content += f"""        <tr>
            <td>{escape_html(r.get('target', ''))}</td>
            <td>{escape_html(str(r.get('port', '')))}</td>
            <td class="{status_class}">{escape_html(r.get('status', ''))}</td>
            <td>{escape_html(r.get('info', ''))}</td>
        </tr>
"""
    
    html_content += """    </table>
</body>
</html>"""
    
    return html_content


# =============================================================================
# SNIFF MODE
# =============================================================================

def sniff_mode(args) -> None:
    """Sniff packets on network interface."""
    if os.geteuid() != 0:
        output_error("Sniff mode requires root privileges")
        return
    
    # Use socket for sniffing (simplified)
    output_warning("Sniff mode started - press Ctrl+C to stop")
    
    iface = getattr(args, 'interface', None)
    count_limit = getattr(args, 'count', 0)
    
    # Create raw socket
    try:
        if iface:
            output_info(f"Using interface: {iface}")
        
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        if iface:
            sock.bind((iface, 0x0003))
    except (socket.error, OSError) as e:
        output_error(f"Failed to create sniffing socket: {e}")
        return
    
    pcap_writer = None
    if args.output and args.output_format == 'pcap':
        try:
            pcap_writer = PCAPWriter(args.output)
            output_info(f"Writing packets to {args.output}")
        except (OSError, PermissionError) as e:
            output_error(f"Cannot create PCAP file: {e}")
            sys.exit(1)
    
    packet_count = 0
    
    try:
        while True:
            if count_limit > 0 and packet_count >= count_limit:
                output_info(f"Reached packet count limit ({count_limit})")
                break
            
            try:
                sock.settimeout(1.0)
                packet, addr = sock.recvfrom(65535)
                
                iface = addr[0] if len(addr) > 0 else 'unknown'
                
                packet_count += 1
                
                if len(packet) >= 14:
                    eth_type = (packet[12] << 8) | packet[13]
                    
                    if eth_type == 0x0800 and len(packet) >= 20:
                        src_ip = '.'.join(str(b) for b in packet[26:30])
                        dst_ip = '.'.join(str(b) for b in packet[30:34])
                        protocol = packet[9]
                        
                        proto_name = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}.get(protocol, f'Proto-{protocol}')
                        
                        print(colored(f"[+] {iface}: {src_ip} -> {dst_ip} ({proto_name})", Colors.SUCCESS))
                        
                        if pcap_writer:
                            pcap_writer.write_packet(packet)
                    
                    elif eth_type == 0x86dd and len(packet) >= 54:
                        src_ip = ':'.join(f'{packet[22+i*2]:02x}{packet[23+i*2]:02x}' for i in range(8))
                        dst_ip = ':'.join(f'{packet[38+i*2]:02x}{packet[39+i*2]:02x}' for i in range(8))
                        
                        print(colored(f"[+] {iface}: {src_ip} -> {dst_ip} (IPv6)", Colors.SUCCESS))
                        
                        if pcap_writer:
                            pcap_writer.write_packet(packet)
                    else:
                        print(colored(f"[*] {iface}: ETH type 0x{eth_type:04x}", Colors.INFO))
                else:
                    print(colored(f"[*] {iface}: Short packet ({len(packet)} bytes)", Colors.INFO))
                    
            except socket.timeout:
                continue
            except Exception as e:
                if packet_count > 0:
                    output_warning(f"Error capturing packet: {e}")
    
    except KeyboardInterrupt:
        print(colored("\n[✓] Interrupted by user", Colors.SUCCESS))
    
    finally:
        sock.close()
        if pcap_writer:
            pcap_writer.close()
    
    output_info(f"Captured {packet_count} packets")

def main():
    """Main CLI entry point."""
    # Handle command-specific help BEFORE argparse
    if "--help" in sys.argv or "-h" in sys.argv:
        # Check if there's a command before --help
        args = sys.argv[1:]
        if "--help" in args:
            idx = args.index("--help")
        else:
            idx = args.index("-h")

        # Check if there's a command at or before -h/--help
        if idx >= 0:
            cmd = args[idx - 1] if idx > 0 else args[0]
            command_helps = {
                "scan": """
Scan Mode Options:
  -t, --target <target>   Target IP, CIDR, or range (REQUIRED)
  -p, --ports <ports>     Ports to scan (default: 80,443)
  -r, --rate <rate>       Packet rate (packets/second)
  -T, --threads <num>     Worker threads (default: 1)
  --async                 Use async I/O engine
  --multiprocess          Use multiprocess engine
  --workers <num>         Worker processes (default: 4)
  --ipv6                  Use IPv6 instead of IPv4
  --timeout <sec>         Response timeout (default: 5)
  --retry <num>           Number of retries (default: 0)
  -o, --output <file>     Output file
  -of, --format <fmt>     Output format: json|csv|html|pcap
  -v, --verbose           Verbose output
  -s, --silent            Silent mode

Examples:
  pp scan -t 127.0.0.1 -p 80
  pp scan -t 192.168.1.0/24 -p 80,443
  pp scan -t 10.0.0.1 -p 1-1000 -o results.json -of json
""",
                "flood": """
Flood Mode Options:
  -t, --target <target>   Target IP (REQUIRED)
  -p, --ports <ports>     Ports to flood (default: 80)
  -r, --rate <rate>       Packet rate (packets/second)
  --ipv6                  Use IPv6 instead of IPv4
  --count <num>           Number of packets to send
  --timeout <sec>         Timeout (default: 5)
  -o, --output <file>     Output file
  -of, --format <fmt>     Output format: json|csv|html|pcap

Note: Flood mode requires root privileges.
""",
                "discover": """
Discover Mode Options:
  -t, --target <target>   Target network (REQUIRED)
  --ipv6                  Use IPv6 instead of IPv4
  --timeout <sec>         Timeout (default: 5)
  -o, --output <file>     Output file
  -of, --format <fmt>     Output format: json|csv|html|pcap

Examples:
  pp discover -t 192.168.1.0/24
""",
                "sniff": """
Sniff Mode Options:
  --interface <name>      Network interface (REQUIRED)
  --count <num>           Number of packets to capture
  -o, --output <file>     Output file (PCAP format)
  --timeout <sec>         Timeout (default: 5)

Note: Sniff mode requires root privileges.
""",
                "os": """
OS Fingerprinting Options:
  -t, --target <target>   Target IP (REQUIRED)
  --os-quick              Quick OS detection (5 probes, 2s timeout)
  --os-deep               Deep OS fingerprinting (20+ probes)
  --os-forensic           Forensic mode (all probes, detailed)
  --os-learn              Learn mode: create signature from response
  -p, --ports <ports>     Ports to probe (default: 80,443,22)
  --timeout <sec>         Timeout (default: 5)
  -o, --output <file>     Output file
  -of, --format <fmt>     Output format: json|csv|html|pcap

Examples:
  pp os quick -t 192.168.1.1
  pp os deep -t 192.168.1.1
""",
                "db": """
Database Options:
  --os-db-list            List all signatures
  --os-db-info            Show database statistics
  --os-db-build [TARGET]  Build signature database
  --find-similar <sig>    Find similar signatures
  --compare-with <file>   Compare with another database
""",
                "api": """
API Server Options:
  --api-port <port>       API server port (default: 8080)

The API server provides REST endpoints for scan operations.
""",
                "shell": """
Interactive Shell:
  Start an interactive shell for Packet Phantom commands.

Commands in shell:
  help                 Show help
  scan <target> <ports>  Perform port scan
  os <target>           OS fingerprinting
  db                    Database operations
  exit                  Exit the shell
"""
            }
            if cmd in command_helps:
                display_banner('EDU', 'full')
                print(command_helps[cmd])
                return

        # Show global help if no specific command
        display_banner('EDU', 'full')
        create_parser().print_help()

    
        return
    
    if '--cite' in sys.argv:
        print("""
    Packet Phantom - Professional Network Testing Tool
    ====================================================
    Version: 2.0.0
    
    For academic citations, please refer to the GitHub repository:
    https://github.com/packet-phantom/packet-phantom
    """)
        return
    
    parser = create_parser()
    
    # Show help if no arguments provided
    if len(sys.argv) == 1:
        display_banner('EDU', 'full')
        parser.print_help()
        print(colored("\nRun 'pp --help' for full options", Colors.INFO))
        return
    
    args = parser.parse_args()
    
    # FIX: Convert positional command to corresponding flag
    if args.command:
        if args.command == 'scan':
            args.scan = True
        elif args.command == 'flood':
            args.flood = True
        elif args.command == 'discover':
            args.discover = True
        elif args.command == 'sniff':
            args.sniff = True
        elif args.command == 'os':
            # For 'os', the user might follow with quick/deep/forensic/learn
            # This will be handled by checking the next arguments
            args.os_quick = True  # Default to quick unless specified otherwise
        elif args.command == 'db':
            # Database command - will be handled by existing --os-db-* flags
            pass
        elif args.command == 'api':
            args.api = True
        elif args.command == 'shell':
            args.shell = True
    
    # FIX Bug 8: Correct mode detection
    mode = detect_mode_from_args(args)
    # PERFORMANCE FIX: Lazy import ModeManager
    from .core.mode_manager import ModeManager, OperationMode
    ModeManager.set_mode(mode)
    
    # FIX Bug 2: Enforce rate limit in EDU mode
    enforced_rate = enforce_rate_limit(args.rate, mode)
    if enforced_rate != args.rate:
        args.rate = enforced_rate
    
    # Handle sniff mode
    if args.sniff:
        display_banner('LIVE' if mode == OperationMode.LIVE else 'EDU', 'full')
        sniff_mode(args)
        return
    
    # Handle interactive shell mode
    if args.shell:
        from packet_phantom.interface.interactive_shell import PhantomShell as InteractiveShell
        display_banner('LIVE' if mode == OperationMode.LIVE else 'EDU', 'full')
        shell = InteractiveShell()
        shell.cmdloop()
        return
    
    # Handle API server mode
    if args.api:
        from packet_phantom.api.server import start_server
        output_info(f"Starting API server on port {args.api_port}")
        
        try:
            start_server(host="0.0.0.0", port=args.api_port)
        except KeyboardInterrupt:
            output_info("API server stopped by user")
        
        return
    
    # Handle list-interfaces option
    if args.list_interfaces:
        from packet_phantom.core.network_utils import list_network_interfaces
        interfaces = list_network_interfaces()
        print(colored("\nAvailable Network Interfaces:", Colors.INFO))
        print(colored("=" * 40, Colors.INFO))
        for iface in interfaces:
            print(colored(f"  {iface['name']}", Colors.CYAN))
            print(colored(f"    IP: {iface['ip']}", Colors.INFO))
            print(colored(f"    MAC: {iface['mac']}", Colors.INFO))
            print()
        return
    
    # Handle Database Management Commands
    if args.os_db_list:
        display_banner('LIVE' if mode == OperationMode.LIVE else 'EDU', 'full')
        handle_os_db_list()
        return
    
    if args.os_db_info:
        display_banner('LIVE' if mode == OperationMode.LIVE else 'EDU', 'full')
        handle_os_db_info()
        return
    
    if args.os_find_similar:
        display_banner('LIVE' if mode == OperationMode.LIVE else 'EDU', 'full')
        similarities = handle_os_find_similar(args.os_find_similar)
        if args.output:
            try:
                output_data = json.dumps(similarities, indent=2)
                safe_write_file(args.output, output_data)
                output_info(f"Results written to {args.output}")
            except (OSError, PermissionError) as e:
                output_error(f"Failed to write output file: {e}")
        return
    
        display_banner('LIVE' if mode == OperationMode.LIVE else 'EDU', 'full')
    if args.compare_with:
        comparison = handle_compare_databases(args.compare_with)
        if args.output:
            try:
                output_data = json.dumps(comparison, indent=2)
                safe_write_file(args.output, output_data)
                output_info(f"Results written to {args.output}")
            except (OSError, PermissionError) as e:
                output_error(f"Failed to write output file: {e}")
        return
    
    # Parse target (removed positional_target - use only -t flag)
    if args.target is None:
        pass  # Target not provided
    
    # Show banner + help if no target and no special action
    special_modes = ['sniff', 'shell', 'api', 'list_interfaces', 'os_db_list', 'os_db_info']
    special_mode_requested = any(getattr(args, mode, False) for mode in special_modes)
    
    if args.target is None and not special_mode_requested:
        display_banner('LIVE' if mode == OperationMode.LIVE else 'EDU', args.banner)
        parser.print_help()
        print(colored("\nTarget is required. Use -t TARGET or specify target as positional argument.", Colors.INFO))
        return
    
    # Display banner with correct mode before operations (only once)
    display_banner('LIVE' if mode == OperationMode.LIVE else 'EDU', args.banner)
    
    # Show target and ports
    print(colored(f"Target:   {args.target}", Colors.INFO))
    print(colored(f"Ports:    {args.ports}", Colors.INFO))
    print()
    try:
        target_info = parse_target(args.target)
        print(colored(f"Target Type: {target_info['type'].upper()}", Colors.INFO))
        
        if 'hosts' in target_info:
            print(colored(f"Hosts to scan: {len(target_info['hosts'])}", Colors.INFO))
    except ValueError as e:
        output_error(str(e))
        sys.exit(1)
    
    # Parse ports
    try:
        ports = parse_ports(args.ports)
        print(colored(f"Ports to scan: {len(ports)}", Colors.INFO))
        if len(ports) > 100:
            print(colored(f"  Range: {ports[0]}-{ports[-1]}", Colors.WARNING))
        else:
            print(colored(f"  Ports: {', '.join(map(str, ports))}", Colors.INFO))
    except ValueError as e:
        output_error(str(e))
        sys.exit(1)
    
    # Setup evasion if requested
    _evasion_suite = None
    if args.evasion:
        print(colored(f"Evasion:  {', '.join(args.evasion)}", Colors.WARNING))
        evasion_config = EvasionConfig(
            ttl_evasion='ttl' in args.evasion,
            option_scrambling='options' in args.evasion,
            fragmentation='fragmentation' in args.evasion,
            padding='padding' in args.evasion
        )
        _evasion_suite = EvasionSuite(config=evasion_config)
    
    # Print spoof setting
    if args.spoof:
        print(colored("Spoof:    ENABLED", Colors.WARNING))
    
    # Print rate limit
    if args.rate:
        print(colored(f"Rate:     {args.rate} pkt/s", Colors.INFO))
    
    # Print threads
    if args.threads > 1:
        print(colored(f"Threads:  {args.threads}", Colors.INFO))
    
    # Determine output format
    if args.output and args.output_format == 'console':
        args.output_format = 'json'
    
    print()
    
    # Initialize batch sender
    # PERFORMANCE FIX: Get config lazily
    from .core.mode_manager import ModeManager as _MM
    _ = _MM.get_config()
    
    output_info("Starting Packet Phantom...")
    output_info("Press Ctrl+C to stop")
    
    # Setup signal handlers
    import signal
    running = [True]
    
    def signal_handler(signum, frame):
        running[0] = False
        output_info("Stopping...")
    
    if not args.api:
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    # Initialize PCAP writer
    pcap_writer = None
    if args.output_format == 'pcap' and args.output:
        try:
            pcap_writer = PCAPWriter(args.output)
            output_info(f"Writing packets to {args.output}")
        except (OSError, PermissionError) as e:
            output_error(f"Cannot create PCAP file: {e}")
            sys.exit(1)
    
    # Get targets
    if 'hosts' in target_info:
        targets = target_info['hosts']
    elif 'resolved' in target_info:
        targets = [target_info['resolved']]
    elif 'value' in target_info:
        targets = [target_info['value']]
    else:
        targets = [str(target_info)]
    
    try:
        # Flood mode
        if args.flood:
            output_warning("Flood mode requires root privileges")
            if os.geteuid() == 0:
                batch_config = BatchConfig(
                    batch_size=64,
                    socket_buffer_size=4 * 1024 * 1024,
                    use_sendmmsg=True
                )
                batch_sender = BatchSender(config=batch_config)
                
                target_ip = target_info.get('value', targets[0])
                result = batch_sender.flood(b'\x00' * 64, target_ip, 5.0, args.rate)
                output_info(f"Flood complete: {result}")
                batch_sender.close()
            else:
                output_error("Run with sudo for flood mode")
        
        elif args.discover:
            # Network discovery
            output_info("Starting network discovery...")
            results = []
            for host in targets:
                output_info(f"Discovering host: {host}")
                host_str = str(host)
                
                try:
                    hostname, _, _ = socket.gethostbyaddr(host_str)
                    output_info(f"  Hostname: {hostname}")
                except socket.herror:
                    pass
                except TypeError as e:
                    output_warning(f"Cannot resolve hostname for {host}: {e}")
                
                for port in [21, 22, 23, 25, 53, 80, 443, 3389]:
                    try:
                        if args.ipv6:
                            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                        else:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(1)
                        result = sock.connect_ex((host_str, port))
                        sock.close()
                        
                        if result == 0:
                            results.append({'target': host_str, 'port': port, 'status': 'open', 'info': 'discover'})
                            output_result(host_str, port, 'open', 'discover')
                    except (socket.error, OSError) as e:
                        output_warning(f"Error connecting to {host_str}:{port}: {e}")
                    except Exception as e:
                        output_warning(f"Unexpected error: {e}")
            
            discover_open = sum(1 for r in results if r.get('status') == 'open')
            discover_closed = sum(1 for r in results if r.get('status') == 'closed')
            output_summary(len(results), discover_open, discover_closed, 0, 0, 0)
        
        # OS Fingerprinting Modes
        elif args.os_quick or args.os_deep or args.os_forensic or args.os_learn:
            output_info("Starting OS fingerprinting...")
            result = handle_os_fingerprinting(args)
            if result:
                from packet_phantom.output.os_output_formatter import get_os_formatter
                formatter = get_os_formatter(args.output_format)
                output = formatter.format(result)
                print(output)
                
                if args.output:
                    try:
                        safe_write_file(args.output, output)
                        output_info(f"Results written to {args.output}")
                    except (OSError, PermissionError) as e:
                        output_error(f"Failed to write output file: {e}")
        
        # Database Build Command
        elif args.os_db_build is not None:
            output_info("Building signature database...")
            db_targets = targets if targets else ['127.0.0.1']
            results = handle_os_db_build(db_targets, args)
            
            if args.output:
                try:
                    output_data = json.dumps(results, indent=2)
                    safe_write_file(args.output, output_data)
                    output_info(f"Results written to {args.output}")
                except (OSError, PermissionError) as e:
                    output_error(f"Failed to write output file: {e}")
        
        elif args.scan:
            results = []
            start_time = time.time()
            
            output_debug(f"Starting scan with {len(ports)} ports on {len(targets)} targets")
            
            # PERFORMANCE FIX: Lazy import
            from .core.raw_socket import is_root
            can_use_raw = is_root()
            
            if not can_use_raw:
                output_warning("Running in TCP connect mode (raw sockets require root)")
            
            if args.async_mode:
                output_info("Using async I/O engine for packet sending")
            
            if args.multiprocess:
                output_info(f"Using multiprocess engine with {args.workers} workers")
            
            rate_limiter = None
            if args.rate:
                rate_limiter = TokenBucket(args.rate)
            
            # Multiprocess scan
            if args.multiprocess and can_use_raw:
                output_info("Starting multiprocess scan...")
                engine = MultiProcessEngine(num_workers=args.workers)
                
                tasks = []
                for host in targets:
                    host_str = str(host)
                    for port in ports:
                        tasks.append((host_str, port))
                
                results = engine.run_scan(tasks, args)
            
            # Async scan
            elif args.async_mode and can_use_raw:
                output_info("Starting async scan...")
                
                async def async_scan():
                    config = AsyncConfig(
                        concurrency=args.threads,
                        rate_limit=args.rate,
                        timeout=5.0,
                        is_ipv6=args.ipv6,
                        version_detection=getattr(args, 'version_detection', False),
                        version_intensity=getattr(args, 'version_intensity', 7),
                        os_detection=getattr(args, 'os_detection', False),
                        os_intensity=getattr(args, 'os_intensity', 7)
                    )
                    # PERFORMANCE FIX: Lazy import
                    from .core.async_engine import AsyncPacketEngine
                    engine = AsyncPacketEngine(config)
                    await engine.start()
                    
                    import socket
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s.connect((str(targets[0]), 80))
                        local_ip = s.getsockname()[0]
                        s.close()
                    except:
                        local_ip = "127.0.0.1"
                    
                    def make_packet(host, port, src_port=None, seq_num=None):
                        if src_port is None:
                            src_port = 12345
                        if seq_num is None:
                            seq_num = 1000
                        
                        if args.icmp:
                            if args.ipv6:
                                return build_icmpv6_packet(dst_ip=host, src_ip='::1', icmp_type=128, code=0)
                            else:
                                return build_icmp_packet(dst_ip=host, src_ip='127.0.0.1', icmp_type=8, code=0)
                        elif args.udp:
                            if args.ipv6:
                                return build_udp_packet(src_ip='::1', dst_ip=host, src_port=src_port, dst_port=port)
                            else:
                                return build_udp_packet(src_ip='127.0.0.1', dst_ip=host, src_port=src_port, dst_port=port)
                        else:
                            if args.ipv6:
                                return build_ipv6_tcp_syn_packet(local_ip, host, port, ttl=args.ttl or 64, seq_num=seq_num, src_port=src_port, evasion_suite=_evasion_suite)
                            else:
                                return build_tcp_syn_packet(local_ip, host, port, ttl=args.ttl or 64, seq_num=seq_num, src_port=src_port, evasion_suite=_evasion_suite)
                    
                    all_results = []
                    for host in targets:
                        host_str = str(host)
                        result = await engine.scan_host(host_str, ports, make_packet)
                        all_results.append(result)
                        
                        if pcap_writer:
                            for port in ports:
                                pcap_writer.write_packet(make_packet(host_str, port))
                    
                    await engine.stop()
                    return all_results
                
                import asyncio
                try:
                    async_results = asyncio.run(async_scan())
                    
                    for host_result in async_results:
                        host = host_result.get('host', '')
                        for port_info in host_result.get('ports', []):
                            port = port_info.get('port', 0)
                            status = port_info.get('status', 'unknown')
                            
                            result_entry = {
                                'target': host,
                                'port': port,
                                'status': status,
                                'info': 'async'
                            }
                            
                            results.append(result_entry)
                            output_result(host, port, status)
                    
                    for host_result in async_results:
                        host = host_result.get('host', '')
                        os_result = host_result.get('os', None)
                        if os_result:
                            os_family = os_result.get('os_family', '')
                            os_version = os_result.get('os_version', '')
                            confidence = os_result.get('confidence', 0)
                            if os_family or os_version:
                                os_str = f"{os_family} {os_version}".strip()
                                print(f"OS: {os_str} ({confidence}% confidence)")
                    
                    total = len(results)
                    open_count = sum(1 for r in results if r.get('status') == 'open')
                    closed_count = sum(1 for r in results if r.get('status') == 'closed')
                    filtered_count = sum(1 for r in results if r.get('status') == 'filtered')
                
                except OSError as e:
                    if "Address family for hostname not supported" in str(e):
                        output_error(f"IPv6 not supported: {e}")
                        output_info("Falling back to IPv4.")
                    else:
                        output_warning(f"Async scan error: {e}")
                except Exception as e:
                    output_warning(f"Async scan error: {e}")
            
            # Standard scan
            else:
                for host in targets:
                    host_str = str(host)
                    output_debug(f"Scanning host: {host_str}")
                    for port in ports:
                        try:
                            if rate_limiter:
                                rate_limiter.consume()
                            
                            if args.icmp:
                                if can_use_raw:
                                    try:
                                        if args.ipv6:
                                            packet = build_icmpv6_packet(dst_ip=host_str, src_ip='::1', icmp_type=128, code=0)
                                        else:
                                            packet = build_icmp_packet(dst_ip=host_str, src_ip='127.0.0.1', icmp_type=8, code=0)
                                        
                                        if pcap_writer:
                                            pcap_writer.write_packet(packet)
                                        
                                        if send_packet_with_raw_socket(packet, host_str, is_ipv6=args.ipv6):
                                            results.append({'target': host_str, 'port': 0, 'status': 'probed', 'info': 'ICMP'})
                                            output_result(host_str, 0, 'probed', 'ICMP Echo')
                                    except Exception as e:
                                        output_warning(f"ICMP send error: {e}")
                                else:
                                    output_warning("ICMP requires root privileges")
                            
                            elif args.udp:
                                if can_use_raw:
                                    try:
                                        if args.ipv6:
                                            packet = build_udp_packet(src_ip='::1', dst_ip=host_str, src_port=12345, dst_port=port)
                                        else:
                                            packet = build_udp_packet(src_ip='127.0.0.1', dst_ip=host_str, src_port=12345, dst_port=port)
                                        
                                        if pcap_writer:
                                            pcap_writer.write_packet(packet)
                                        
                                        if send_packet_with_raw_socket(packet, host_str, is_ipv6=args.ipv6):
                                            results.append({'target': host_str, 'port': port, 'status': 'probed', 'info': 'UDP'})
                                            output_result(host_str, port, 'probed')
                                    except Exception as e:
                                        output_warning(f"UDP send error: {e}")
                                else:
                                    output_warning("UDP raw packets require root privileges")
                            
                            else:
                                if args.ipv6:
                                    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                                else:
                                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                sock.settimeout(args.timeout)
                                result = sock.connect_ex((host_str, port))
                                sock.close()
                                
                                output_debug(f"  Port {port}: connect_ex result = {result}")
                                
                                if result == 0:
                                    results.append({'target': host_str, 'port': port, 'status': 'open', 'info': 'TCP'})
                                    output_result(host_str, port, 'open')
                                    
                                    if pcap_writer or can_use_raw:
                                        try:
                                            if args.ipv6:
                                                packet = build_ipv6_tcp_syn_packet(
                                                    '::1', host_str, port, 
                                                    ttl=args.ttl or 64,
                                                    evasion_suite=_evasion_suite
                                                )
                                            else:
                                                packet = build_tcp_syn_packet(
                                                    '127.0.0.1', host_str, port, 
                                                    ttl=args.ttl or 64,
                                                    evasion_suite=_evasion_suite
                                                )
                                            
                                            if pcap_writer:
                                                pcap_writer.write_packet(packet)
                                            
                                            if can_use_raw:
                                                send_packet_with_raw_socket(packet, host_str, is_ipv6=args.ipv6)
                                                
                                        except Exception as e:
                                            output_warning(f"Error writing/sending packet: {e}")
                                else:
                                    results.append({'target': host_str, 'port': port, 'status': 'closed', 'info': f'conn_fail:{result}'})
                                    output_debug(f"  Port {port}: marked as closed (result={result})")
                        except socket.timeout:
                            results.append({'target': host_str, 'port': port, 'status': 'filtered', 'info': 'timeout'})
                            output_debug(f"  Port {port}: timeout")
                        except Exception as e:
                            results.append({'target': host_str, 'port': port, 'status': 'error', 'info': str(e)})
                            output_warning(f"Error scanning {host_str}:{port}: {e}")
            
            elapsed = time.time() - start_time
            rate = len(results) / elapsed if elapsed > 0 else 0
            
            open_count = sum(1 for r in results if r.get('status') == 'open')
            closed_count = sum(1 for r in results if r.get('status') == 'closed')
            filtered_count = sum(1 for r in results if r.get('status') == 'filtered')
            error_count = sum(1 for r in results if r.get('status') == 'error')
            
            if args.verbose:
                output_debug("Scan Results Summary:")
                output_debug(f"  Total: {len(results)}")
                output_debug(f"  Open: {open_count}")
                output_debug(f"  Closed: {closed_count}")
                output_debug(f"  Filtered: {filtered_count}")
                output_debug(f"  Errors: {error_count}")
            
            if args.output:
                if args.output_format == 'json':
                    output_data = format_output_json(results, args)
                    try:
                        safe_write_file(args.output, output_data)
                        output_info(f"Results written to {args.output}")
                    except (OSError, PermissionError) as e:
                        output_error(f"Failed to write output file: {e}")
                elif args.output_format == 'csv':
                    output_data = format_output_csv(results)
                    try:
                        safe_write_file(args.output, output_data)
                        output_info(f"Results written to {args.output}")
                    except (OSError, PermissionError) as e:
                        output_error(f"Failed to write output file: {e}")
                elif args.output_format == 'html':
                    output_data = format_output_html(results)
                    try:
                        safe_write_file(args.output, output_data)
                        output_info(f"Results written to {args.output}")
                    except (OSError, PermissionError) as e:
                        output_error(f"Failed to write output file: {e}")
                elif args.output_format == 'pcap':
                    pass
            
            output_summary(len(results), open_count, closed_count, filtered_count, error_count, rate)
    
    except KeyboardInterrupt:
        print(colored("\n[✓] Interrupted by user", Colors.SUCCESS))
    
    finally:
        if pcap_writer:
            try:
                pcap_writer.close()
            except Exception:
                pass
    
    output_info("Done!")


# =============================================================================
# PARSER CREATION
# =============================================================================

def create_parser() -> ProfessionalParser:
    """Create the professional argument parser."""
    parser = ProfessionalParser(
        add_help=False
    )
    
    # FIX: Add optional positional command (scan, flood, discover, etc.)
    # This allows: pp scan -t target -p ports
    # Instead of only: pp --scan -t target -p ports
    parser.add_argument('command', 
                        nargs='?',
                        default=None,
                        choices=['scan', 'flood', 'discover', 'sniff', 'os', 'db', 'api', 'shell'],
                        help='Command to execute')
    
    # Target is required for most commands (except api, shell, db, sniff sometimes)
    parser.add_argument('-t', '--target', 
                        type=lambda x: sanitize_target(x),
                        default=None,
                        help='Target IP, CIDR, or range')
    
    # Move --list-interfaces out of mutually exclusive group
    parser.add_argument('--list-interfaces', 
                        action='store_true',
                        help='List network interfaces')
    
    parser.add_argument('-m', '--mode',
                        choices=['live', 'edu'],
                        default='edu',
                        help='Operation mode')
    
    parser.add_argument('-b', '--banner',
                        choices=['full', 'compact', 'minimal'],
                        default='full',
                        help='Banner style')
    
    parser.add_argument('-p', '--ports',
                        default='80,443',
                        type=lambda x: validate_port_spec(x),
                        help='Ports to scan')
    
    parser.add_argument('-r', '--rate',
                        type=validate_rate_value,
                        default=None,
                        help='Packet rate')
    parser.add_argument('-T', '--threads',
                        type=validate_threads_value,
                        default=1,
                        help='Worker threads')
    
    parser.add_argument('-o', '--output',
                        type=lambda x: validate_output_path(x),
                        default=None,
                        help='Output file')
    parser.add_argument('-of', '--output-format',
                        choices=['json', 'csv', 'html', 'pcap'],
                        default='console',
                        help='Output format')
    
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument('-v', '--verbose',
                        action='store_true',
                        help='Verbose')
    verbosity_group.add_argument('-s', '--silent',
                        action='store_true',
                        help='Silent')
    
    evasion_group = parser.add_argument_group('Evasion')
    evasion_group.add_argument('--evasion',
                               nargs='+',
                               choices=['ttl', 'options', 'fragmentation', 'padding'],
                               help='Evasion techniques')
    evasion_group.add_argument('--ttl',
                              type=validate_ttl_value,
                              default=None,
                              help='TTL')
    evasion_group.add_argument('--spoof',
                              action='store_true',
                              help='IP spoofing')
    
    mode_group = parser.add_argument_group('Modes')
    mode_group.add_argument('--scan',
                           action='store_true',
                           help='Port scan')
    mode_group.add_argument('--flood',
                           action='store_true',
                           help='Flood attack')
    mode_group.add_argument('--discover',
                           action='store_true',
                           help='Network discovery')
    mode_group.add_argument('--sniff',
                           action='store_true',
                           help='Sniff mode')
    
    protocol_group = parser.add_argument_group('Protocol')
    protocol_group.add_argument('--ipv6',
                                action='store_true',
                                help='IPv6')
    protocol_group.add_argument('--icmp',
                                action='store_true',
                                help='ICMP')
    protocol_group.add_argument('--udp',
                                action='store_true',
                                help='UDP')
    protocol_group.add_argument('--count',
                                type=int,
                                default=1,
                                help='Packets to send')
    
    performance_group = parser.add_argument_group('Performance')
    performance_group.add_argument('--async',
                                   action='store_true',
                                   dest='async_mode',
                                   help='Async I/O')
    performance_group.add_argument('--multiprocess',
                                   action='store_true',
                                   help='Multiprocess')
    performance_group.add_argument('--workers',
                                   type=lambda x: validate_positive_int(x, "Port", 1, 65535),
                                   default=4,
                                   help='Workers')
    
    advanced_group = parser.add_argument_group('Advanced')
    advanced_group.add_argument('--timeout',
                               type=validate_timeout_value,
                               default=5,
                               help='Timeout')
    advanced_group.add_argument('--retry',
                               type=validate_retry_value,
                               default=0,
                               help='Retries')
    advanced_group.add_argument('--payload',
                               type=lambda x: validate_payload_path(x),
                               default=None,
                               help='Payload')
    advanced_group.add_argument('--interface',
                               type=lambda x: validate_interface_name(x),
                               default=None,
                               help='Interface')
    
    service_detect_group = parser.add_argument_group('Service Detection')
    service_detect_group.add_argument('--service-detect', '-sV',
                                      action='store_true',
                                      dest='version_detection',
                                      help='Service/version detection')
    service_detect_group.add_argument('--version-intensity',
                                      type=int,
                                      choices=range(0, 10),
                                      default=7,
                                      help='Version detection intensity')
    
    os_fingerprint_group = parser.add_argument_group('OS Fingerprinting')
    os_fingerprint_group.add_argument('--os-quick',
                                     action='store_true',
                                     help='Quick OS fingerprinting (5 probes, 2s timeout)')
    os_fingerprint_group.add_argument('--os-deep',
                                     action='store_true',
                                     help='Deep OS fingerprinting (20+ probes)')
    os_fingerprint_group.add_argument('--os-forensic',
                                     action='store_true',
                                     help='Forensic OS fingerprinting (all probes)')
    os_fingerprint_group.add_argument('--os-learn',
                                     action='store_true',
                                     help='Learn mode: create signature from response')
    os_fingerprint_group.add_argument('--os-intensity',
                                     type=int,
                                     choices=range(0, 10),
                                     default=7,
                                     help='OS fingerprinting intensity (0-9)')
    
    db_group = parser.add_argument_group('Database')
    db_group.add_argument('--os-db-build', metavar='TARGET', nargs='*',
                          help='Build database')
    db_group.add_argument('--os-db-list', action='store_true',
                          help='List signatures')
    db_group.add_argument('--os-db-info', action='store_true',
                          help='DB info')
    db_group.add_argument('--os-find-similar', metavar='SIGNATURE_ID',
                          help='Find similar')
    db_group.add_argument('--compare-with', metavar='OTHER_DB',
                          help='Compare DB')
    
    edu_group = parser.add_argument_group('Educational Mode')
    edu_mode_exclusive = edu_group.add_mutually_exclusive_group()
    edu_mode_exclusive.add_argument('--edu',
                           action='store_true',
                           default=True,
                           help='Educational mode (default, safe testing)')
    edu_mode_exclusive.add_argument('--no-edu',
                           action='store_true',
                           dest='no_edu',
                           help='Disable educational mode')
    
    api_group = parser.add_argument_group('API & Shell')
    api_group.add_argument('--api',
                           action='store_true',
                           help='API server')
    api_group.add_argument('--api-port',
                           type=lambda x: validate_positive_int(x, "Port", 1, 65535),
                           default=8080,
                           help='API port')
    api_group.add_argument('--shell',
                            action='store_true',
                            help='Interactive shell')
    
    parser.add_argument('-h', '--help',
                        action='store_true',
                        help='Show help')
    parser.add_argument('--version',
                        action='store_true',
                        help='Version')
    parser.add_argument('--cite',
                        action='store_true',
                        help='Citation')
    
    parser.set_defaults(scan=True)
    
    return parser


if __name__ == "__main__":
    main()
