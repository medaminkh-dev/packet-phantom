"""
Packet Phantom - Professional Evasion Suite
==========================================

Advanced evasion techniques for professional network testing.
Designed for bypassing IDS/IPS and network filtering.

⚠️  WARNING: These techniques are for authorized security research only.

Evasion Techniques:
- TTL Randomization: Mimic different OS TTL values
- TCP Option Scrambling: Randomized but valid TCP options
- IP Fragmentation: Split packets to evade detection
- Padding Generation: Add random payload padding
- Protocol Confusion: Exploit protocol ambiguities

Author: Packet Phantom Team
Version: 2.0.0
"""

import secrets
import struct
import socket
from typing import List, Optional
from dataclasses import dataclass
from enum import Enum


# =============================================================================
# EVASION TYPES
# =============================================================================

class EvasionType(Enum):
    """Types of evasion techniques."""
    TTL = "ttl"
    OPTIONS = "options"
    FRAGMENTATION = "fragmentation"
    PADDING = "padding"
    SOURCE_ROUTING = "source_routing"
    TIMING = "timing"
    PROTOCOL = "protocol"


# =============================================================================
# TTL EVASION ENGINE
# =============================================================================

class TTLEvasionEngine:
    """
    TTL randomization for evasion.
    
    Generates realistic TTL values based on different operating systems
    to mimic legitimate traffic patterns.
    """
    
    # OS-specific TTL ranges
    OS_TTL_RANGES = {
        'windows': (100, 128),
        'linux': (56, 64),
        'macos': (60, 64),
        'unix': (64, 128),
        'router': (50, 64),
        'ios': (255, 255),
        'default': (56, 64),
    }
    
    def __init__(self, default_os: str = 'linux'):
        """
        Initialize TTL evasion engine.
        
        Args:
            default_os: Default OS type for TTL generation
        """
        self.default_os = default_os
        self.last_ttl = None
    
    def get_realistic_ttl(self, os_type: Optional[str] = None) -> int:
        """
        Get realistic TTL value for an OS type.
        
        Args:
            os_type: OS type (windows, linux, macos, unix, router, ios)
            
        Returns:
            Realistic TTL value
        """
        os_type = os_type or self.default_os
        range_info = self.OS_TTL_RANGES.get(os_type.lower(), self.OS_TTL_RANGES['default'])
        
        ttl = secrets.randbelow(range_info[1] - range_info[0] + 1) + range_info[0]
        self.last_ttl = ttl
        return ttl
    
    def get_sequence(self, length: int, os_type: Optional[str] = None) -> List[int]:
        """
        Generate a sequence of TTL values with natural variation.
        
        Args:
            length: Number of TTL values to generate
            os_type: Base OS type
            
        Returns:
            List of TTL values with realistic variation
        """
        os_type = os_type or self.default_os
        range_info = self.OS_TTL_RANGES.get(os_type.lower(), self.OS_TTL_RANGES['default'])
        base_ttl = secrets.randbelow(range_info[1] - range_info[0] + 1) + range_info[0]
        
        sequence = []
        current_ttl = base_ttl
        
        for _ in range(length):
            # 10% chance of a jump (route change simulation)
            if secrets.randbelow(2**32) / 2**32 < 0.1:
                current_ttl = secrets.randbelow(range_info[1] - range_info[0] + 1) + range_info[0]
            else:
                # Small drift (±2)
                drift = secrets.randbelow(5) - 2
                current_ttl = max(range_info[0], min(range_info[1], current_ttl + drift))
                current_ttl = max(range_info[0], min(range_info[1], current_ttl + drift))
            
            sequence.append(current_ttl)
        
        return sequence
    
    def get_path_mimic_ttl(self, hop_count: int) -> int:
        """
        Generate TTL based on hop count from target.
        
        Args:
            hop_count: Estimated hops to target
            
        Returns:
            TTL value accounting for hops
        """
        initial_ttl = self.get_realistic_ttl()
        return max(1, initial_ttl - hop_count)


# =============================================================================
# TCP OPTION SCRAMBLER
# =============================================================================

class TCPOptionScrambler:
    """
    TCP option randomization for evasion.
    
    Generates randomized but valid TCP options to study how
    different implementations handle various option combinations.
    """
    
    # TCP Option Codes
    OPTION_EOL = 0
    OPTION_NOP = 1
    OPTION_MSS = 2
    OPTION_WS = 3
    OPTION_SACK_PERMITTED = 4
    OPTION_SACK = 5
    OPTION_TIMESTAMP = 8
    
    def __init__(self):
        """Initialize option scrambler."""
        self.common_mss_values = [512, 1024, 1400, 1460, 1500, 2048, 4096, 8192]
        self.common_ws_values = list(range(0, 15))
    
    def generate_options(self,
                        include_mss: bool = True,
                        include_ws: bool = True,
                        include_timestamp: bool = False,
                        include_sack: bool = False) -> bytes:
        """
        Generate randomized TCP options.
        
        Args:
            include_mss: Include MSS option
            include_ws: Include window scale option
            include_timestamp: Include timestamp option
            include_sack: Include SACK option
            
        Returns:
            TCP options as bytes
        """
        options = b''
        
        # MSS option
        if include_mss:
            mss = self.common_mss_values[secrets.randbelow(len(self.common_mss_values))]
            options += struct.pack('!BBH', self.OPTION_MSS, 4, mss)
        
        # NOP padding
        options += b'\x01' * (secrets.randbelow(3) + 1)
        
        # Window Scale option
        if include_ws:
            ws = self.common_ws_values[secrets.randbelow(len(self.common_ws_values))]
            options += struct.pack('!BBH', self.OPTION_WS, 3, ws)
        
        # NOP padding
        options += b'\x01' * secrets.randbelow(3)
        
        # Timestamp option
        if include_timestamp:
            ts_val = secrets.randbelow(2**32 - 1) + 1
            ts_echo = secrets.randbelow(2**32 - 1) + 1
            options += struct.pack('!BBII', self.OPTION_TIMESTAMP, 10, ts_val, ts_echo)
        
        # SACK Permitted
        if include_sack:
            options += struct.pack('!BB', self.OPTION_SACK_PERMITTED, 2)
        
        # Pad to 4-byte boundary
        while len(options) % 4 != 0:
            options += b'\x01'
        
        # EOL option
        options += b'\x00'
        
        return options
    
    def generate_minimal_options(self) -> bytes:
        """Generate minimal TCP options (MSS only)."""
        return struct.pack('!BBH', self.OPTION_MSS, 4, 1460) + b'\x00'
    
    def generate_max_options(self) -> bytes:
        """Generate maximum variety of TCP options."""
        return self.generate_options(
            include_mss=True,
            include_ws=True,
            include_timestamp=True,
            include_sack=True
        )


# =============================================================================
# IP FRAGMENTATION ENGINE
# =============================================================================

class FragmentationEngine:
    """
    IP packet fragmentation for evasion.
    
    Splits packets into fragments to evade detection and
    exploit reassembly vulnerabilities.
    """
    
    MTU_SIZES = {
        'ethernet': 1500,
        'wifi': 2304,
        'vpn': 1400,
        'gre': 1476,
        'ipsec': 1400,
        'custom': None,
    }
    
    def __init__(self, mtu: int = 1500, overlap: bool = False):
        """
        Initialize fragmentation engine.
        
        Args:
            mtu: Maximum transmission unit
            overlap: Enable overlapping fragments (teardrop-style)
        """
        self.mtu = mtu
        self.overlap = overlap
    
    def fragment_packet(self, packet: bytes, mtu: Optional[int] = None) -> List[bytes]:
        """
        Fragment IP packet into smaller pieces.
        
        Args:
            packet: Original IP packet
            mtu: MTU for fragmentation (uses default if None)
            
        Returns:
            List of packet fragments
        """
        mtu = mtu or self.mtu
        
        # IP header is typically 20 bytes
        header_len = 20
        payload_max = mtu - header_len
        
        if len(packet) <= payload_max:
            return [packet]
        
        # Extract header and payload
        header = packet[:header_len]
        payload_data = packet[header_len:]
        
        # Parse header to get flags
        _version_ihl = header[0]  # noqa: F841 - extracted for clarity
        flags_offset = struct.unpack('!H', header[6:8])[0]
        flags = (flags_offset >> 13) & 0x7
        offset = flags_offset & 0x1FFF
        
        # Clear DF flag
        new_flags = flags & ~0x2  # Clear DF
        new_offset_word = (new_flags << 13) | offset
        new_header = header[:6] + struct.pack('!H', new_offset_word) + header[8:]
        
        fragments = []
        current_offset = 0
        
        while current_offset < len(payload_data):
            fragment_end = min(current_offset + payload_max, len(payload_data))
            
            # Calculate fragment offset (in 8-byte units)
            fragment_offset = current_offset // 8
            
            # Set MF flag if not last fragment
            is_last = fragment_end >= len(payload_data)
            mf_flag = 0 if is_last else 1
            
            fragment_offset_word = (mf_flag << 13) | fragment_offset
            fragment_header = new_header[:6] + struct.pack('!H', fragment_offset_word) + new_header[:8]
            
            fragment = fragment_header + payload_data[current_offset:fragment_end]
            fragments.append(fragment)
            
            current_offset = fragment_end
        
        return fragments
    
    def create_overlapping_fragments(self, packet: bytes) -> List[bytes]:
        """
        Create overlapping fragments (for teardrop-style evasion).
        
        ⚠️  This may cause issues on some systems.
        
        Args:
            packet: Original packet
            
        Returns:
            List of overlapping fragments
        """
        header_len = 20
        _ = packet[header_len:]  # noqa: F841 - extracted for potential future use
        
        # Create first fragment with more data
        first = packet[:40]  # Extra data in first fragment
        
        # Create second fragment starting at offset 8
        second = packet[:28] + packet[8:]  # Overlapping
        
        return [first, second]


# =============================================================================
# PADDING GENERATOR
# =============================================================================

class PaddingGenerator:
    """
    Random payload padding generator.
    
    Adds random padding to packets to evade size-based detection.
    """
    
    def __init__(self, min_padding: int = 0, max_padding: int = 100):
        """
        Initialize padding generator.
        
        Args:
            min_padding: Minimum padding size
            max_padding: Maximum padding size
        """
        self.min_padding = min_padding
        self.max_padding = max_padding
    
    def generate_padding(self, size: Optional[int] = None) -> bytes:
        """
        Generate random padding bytes.
        
        Args:
            size: Specific padding size (uses random if None)
            
        Returns:
            Random padding bytes
        """
        if size is None:
            size = secrets.randbelow(self.max_padding - self.min_padding + 1) + self.min_padding
        
        return bytes(secrets.randbelow(256) for _ in range(size))
    
    def add_padding(self, packet: bytes, max_size: int = 1500) -> bytes:
        """
        Add random padding to packet.
        
        Args:
            packet: Original packet
            max_size: Maximum packet size
            
        Returns:
            Packet with padding
        """
        current_size = len(packet)
        if current_size >= max_size:
            return packet
        
        padding_size = secrets.randbelow(max_size - current_size + 1)
        padding = self.generate_padding(padding_size)
        
        return packet + padding


# =============================================================================
# MAIN EVASION SUITE
# =============================================================================

@dataclass
class EvasionConfig:
    """Configuration for evasion suite."""
    ttl_evasion: bool = False
    ttl_os_type: str = 'linux'
    option_scrambling: bool = False
    fragmentation: bool = False
    mtu: int = 1500
    padding: bool = False
    max_padding: int = 100
    timestamp_evasion: bool = False


class EvasionSuite:
    """
    Professional evasion suite combining multiple techniques.
    
    Usage:
        suite = EvasionSuite(ttl_evasion=True, fragmentation=True)
        evaded_packets = suite.evade_packet(original_packet)
    """
    
    def __init__(self, config: Optional[EvasionConfig] = None):
        """
        Initialize evasion suite.
        
        Args:
            config: Evasion configuration
        """
        self.config = config or EvasionConfig()
        self.ttl_engine = TTLEvasionEngine()
        self.option_scrambler = TCPOptionScrambler()
        self.fragmentation_engine = FragmentationEngine()
        self.padding_generator = PaddingGenerator()
    
    def get_ttl(self) -> int:
        """Get evasion TTL value."""
        if self.config.ttl_evasion:
            return self.ttl_engine.get_realistic_ttl(self.config.ttl_os_type)
        return 64  # Default TTL
    
    def get_options(self) -> bytes:
        """Get scrambled TCP options."""
        if self.config.option_scrambling:
            return self.option_scrambler.generate_options(
                include_timestamp=self.config.timestamp_evasion
            )
        return b''
    
    def fragment(self, packet: bytes) -> List[bytes]:
        """Fragment packet if enabled."""
        if self.config.fragmentation:
            return self.fragmentation_engine.fragment_packet(packet, self.config.mtu)
        return [packet]
    
    def add_padding(self, packet: bytes) -> bytes:
        """Add padding to packet."""
        if self.config.padding:
            return self.padding_generator.add_padding(packet)
        return packet
    
    def evade_packet(self, packet: bytes) -> List[bytes]:
        """
        Apply all enabled evasion techniques to packet.
        
        Args:
            packet: Original packet
            
        Returns:
            List of evaded packets (usually 1, more if fragmented)
        """
        # Add padding first
        packet = self.add_padding(packet)
        
        # Fragment if needed
        fragments = self.fragment(packet)
        
        return fragments
    
    def create_evaded_syn(self,
                         src_ip: str,
                         dst_ip: str,
                         src_port: int,
                         dst_port: int,
                         seq_num: int = 0) -> List[bytes]:
        """
        Create evaded SYN packet(s).
        
        Args:
            src_ip: Source IP
            dst_ip: Destination IP
            src_port: Source port
            dst_port: Destination port
            seq_num: Sequence number
            
        Returns:
            List of SYN packets (possibly fragmented)
        """
        # Build packet components
        ttl = self.get_ttl()
        options = self.get_options()
        
        # IP Header
        version_ihl = 0x45
        tos = 0
        total_len = 20 + 20 + len(options)  # IP + TCP + options
        identification = secrets.randbelow(65535) + 1
        flags_offset = 0
        protocol = socket.IPPROTO_TCP
        
        ip_header = struct.pack('!BBHHHBBH4s4s',
                               version_ihl, tos, total_len, identification,
                               flags_offset, ttl, protocol, 0,
                               socket.inet_aton(src_ip),
                               socket.inet_aton(dst_ip))
        
        # Calculate IP checksum
        ip_checksum = self._calculate_ip_checksum(ip_header)
        ip_header = ip_header[:10] + struct.pack('H', ip_checksum) + ip_header[12:]
        
        # TCP Header
        offset_reserved = (5 << 4)  # 5 * 4 = 20 bytes
        
        tcp_header = struct.pack('!HHIIBBHHH',
                                src_port, dst_port,
                                seq_num, 0,
                                offset_reserved, 0x02,  # SYN flag
                                5840, 0, 0) + options
        
        # Pseudo header for checksum
        pseudo_header = struct.pack('!4s4sBBH',
                                   socket.inet_aton(src_ip),
                                   socket.inet_aton(dst_ip),
                                   0, socket.IPPROTO_TCP,
                                   len(tcp_header))
        
        tcp_checksum = self._calculate_tcp_checksum(pseudo_header + tcp_header)
        tcp_header = tcp_header[:16] + struct.pack('H', tcp_checksum) + tcp_header[18:]
        
        packet = ip_header + tcp_header
        
        # Apply evasion
        return self.evade_packet(packet)
    
    def _calculate_ip_checksum(self, header: bytes) -> int:
        """Calculate IP header checksum."""
        s = 0
        for i in range(0, len(header), 2):
            if i + 1 < len(header):
                w = (header[i] << 8) + header[i + 1]
            else:
                w = header[i] << 8
            s += w
        
        s = (s >> 16) + (s & 0xFFFF)
        s = ~s & 0xFFFF
        return s
    
    def _calculate_tcp_checksum(self, data: bytes) -> int:
        """Calculate TCP checksum."""
        s = 0
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                w = (data[i] << 8) + data[i + 1]
            else:
                w = data[i] << 8
            s += w
        
        s = (s >> 16) + (s & 0xFFFF)
        s = ~s & 0xFFFF
        return s


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    'EvasionSuite',
    'EvasionConfig',
    'EvasionType',
    'TTLEvasionEngine',
    'TCPOptionScrambler',
    'FragmentationEngine',
    'PaddingGenerator',
]
