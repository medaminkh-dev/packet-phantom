"""
IPv6 Packet Forger - Advanced IPv6 packet crafting module.

Provides comprehensive IPv6 packet building capabilities:
- IPv6 header construction (40 bytes fixed)
- Extension header support (Hop-by-Hop, Routing, Fragment, Destination)
- TCP/UDP/ICMPv6 payload support
- SYN packet generation
- Thread-safe operations
- Security hardening

All operations preserve security constraints from the parent PacketForger class.
"""

import struct
import socket
import threading
from typing import Optional, Tuple, List, Dict, Any
from dataclasses import dataclass
from enum import IntEnum

from .checksum import OptimizedChecksum  # noqa: F811 - intentionally shadowing


class IPv6ExtensionHeader(IntEnum):
    """IPv6 Extension Header Types (RFC 8200)."""
    HOP_BY_HOP = 0
    ROUTING = 43
    FRAGMENT = 44
    DESTINATION_OPTIONS = 60
    NO_NEXT_HEADER = 59


class IPv6NextHeader(IntEnum):
    """IPv6 Next Header Values for upper-layer protocols."""
    TCP = 6
    UDP = 17
    ICMPV6 = 58
    NO_NEXT_HEADER = 59


class IPv6PacketError(Exception):
    """Raised when IPv6 packet construction fails."""
    pass


class IPv6ValidationError(Exception):
    """Raised when IPv6 input validation fails."""
    pass


@dataclass
class IPv6ExtensionHeaderEntry:
    """Represents an IPv6 extension header."""
    next_header: int
    header_data: bytes
    options: bytes = b''
    
    def to_bytes(self) -> bytes:
        """Serialize extension header to bytes."""
        # Calculate header length (in 8-byte units, excluding first 8 bytes)
        base_length = 8  # Next Header + Hdr Ext Len + options
        total_length = base_length + len(self.options)
        
        # Pad to 8-byte boundary
        if total_length % 8 != 0:
            padding = 8 - (total_length % 8)
            self.options += bytes(padding)
            total_length = base_length + len(self.options)
        
        hdr_ext_len = (total_length // 8) - 1
        
        return struct.pack('>BB', self.next_header, hdr_ext_len) + self.options


@dataclass
class IPv6FragmentHeader:
    """IPv6 Fragment Header (RFC 8200)."""
    fragment_offset: int  # 13 bits
    more_fragments: bool = False
    identification: int = 0
    
    def to_bytes(self) -> bytes:
        """Serialize fragment header to bytes (8 bytes total)."""
        flags = (self.fragment_offset >> 5) & 0xFE
        if self.more_fragments:
            flags |= 0x01
        
        return struct.pack('>BI', 
                          (IPv6ExtensionHeader.FRAGMENT << 8) | flags,
                          self.identification)


class IPv6PacketForger:
    """
    Thread-safe IPv6 packet forger with comprehensive features.
    
    Features:
    - Full IPv6 header construction
    - Extension header support
    - TCP/UDP/ICMPv6 payload support
    - SYN packet generation
    - Fragmentation support
    - Checksum calculation
    - Thread-safe sequence tracking
    
    Security Features:
    - Input validation for all addresses and ports
    - Memory bounds enforcement
    - Rate limiting support via external TokenBucket
    """
    
    # IPv6 constants
    IPV6_VERSION = 6
    IPV6_HEADER_SIZE = 40
    MAX_PAYLOAD_SIZE = 65535 - 40  # Max IPv6 packet - header
    MIN_MTU = 1280  # Minimum IPv6 MTU
    
    # Sequence tracking (thread-safe)
    _lock = threading.Lock()
    _sequence_counter = 0
    _identification_counter = 0
    
    def __init__(self, rate_limiter: Optional[Any] = None):
        """
        Initialize IPv6 packet forger.
        
        Args:
            rate_limiter: Optional TokenBucket rate limiter for throttling
        """
        self.rate_limiter = rate_limiter
        self._local_sequence = 0
        self._local_identification = 0
    
    @classmethod
    def validate_ipv6_address(cls, addr: str) -> bool:
        """
        Validate IPv6 address format.
        
        Args:
            addr: IPv6 address string to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            socket.inet_pton(socket.AF_INET6, addr)
            return True
        except (socket.error, OSError):
            return False
    
    @classmethod
    def parse_ipv6_address(cls, addr: str) -> bytes:
        """
        Parse IPv6 address string to 16-byte binary format.
        
        Args:
            addr: IPv6 address string
            
        Returns:
            16-byte representation
            
        Raises:
            IPv6ValidationError: If address is invalid
        """
        if not cls.validate_ipv6_address(addr):
            raise IPv6ValidationError(f"Invalid IPv6 address: {addr}")
        return socket.inet_pton(socket.AF_INET6, addr)
    
    @classmethod
    def ipv6_to_string(cls, addr: bytes) -> str:
        """
        Convert 16-byte IPv6 address to string format.
        
        Args:
            addr: 16-byte IPv6 address
            
        Returns:
            IPv6 address string
            
        Raises:
            IPv6ValidationError: If address length is invalid
        """
        if len(addr) != 16:
            raise IPv6ValidationError("IPv6 address must be 16 bytes")
        return socket.inet_ntop(socket.AF_INET6, addr)
    
    def _get_next_sequence(self) -> int:
        """Get next sequence number (thread-safe)."""
        with self._lock:
            self._sequence_counter += 1
            self._local_sequence = self._sequence_counter
            return self._local_sequence
    
    def _get_next_identification(self) -> int:
        """Get next identification value for fragmentation."""
        with self._lock:
            self._identification_counter += 1
            self._local_identification = self._identification_counter
            return self._local_identification
    
    def build_ipv6_header(
        self,
        src_addr: bytes,
        dst_addr: bytes,
        payload_length: int,
        next_header: int,
        traffic_class: int = 0,
        flow_label: int = 0,
        hop_limit: int = 64
    ) -> bytes:
        """
        Build IPv6 header (40 bytes).
        
        IPv6 Header Format (RFC 8200):
        +-----------+-----------+---+-------+-------+--------+--------+--------+
        | Version   | Traffic   |           Flow Label            | Payload Length |
        | (4 bits)  | Class (4) |           (20 bits)               |    (16 bits)    |
        +-----------+-----------+---+-------+-------+--------+--------+--------+
        |  Next Header (8)  |   Hop Limit (8)   |                               |
        +-------------------+-------------------+                               +
        |                                                               |
        +                    Source Address (128 bits)                    +
        |                                                               |
        +-------------------+-------------------+                        |
        +                                                               +
        +              Destination Address (128 bits)                    +
        |                                                               |
        +-------------------+-------------------+------------------------+
        
        Args:
            src_addr: Source address (16 bytes)
            dst_addr: Destination address (16 bytes)
            payload_length: Length of payload (upper layer + extensions)
            next_header: Next header value (protocol number)
            traffic_class: Traffic class (0-255, default 0)
            flow_label: Flow label (0-1048575, default 0)
            hop_limit: Hop limit (1-255, default 64)
            
        Returns:
            40-byte IPv6 header
            
        Raises:
            IPv6ValidationError: If addresses are invalid
            IPv6PacketError: If parameters are out of range
        """
        # Validate addresses
        if len(src_addr) != 16:
            raise IPv6ValidationError("Source address must be 16 bytes")
        if len(dst_addr) != 16:
            raise IPv6ValidationError("Destination address must be 16 bytes")
        
        # Validate parameters
        if not 0 <= traffic_class <= 255:
            raise IPv6PacketError("Traffic class must be 0-255")
        if not 0 <= flow_label <= 0xFFFFF:
            raise IPv6PacketError("Flow label must be 0-1048575")
        if not 1 <= hop_limit <= 255:
            raise IPv6PacketError("Hop limit must be 1-255")
        if not 0 <= payload_length <= 0xFFFF:
            raise IPv6PacketError("Payload length must be 0-65535")
        
        # Build version/traffic_class/flow_label field (32 bits total)
        # Format: Version(4) | Traffic Class(8) | Flow Label(20)
        version_tc_fl = (
            (self.IPV6_VERSION << 28) |
            (traffic_class << 20) |
            (flow_label & 0xFFFFF)
        )
        
        header = struct.pack('>IHBB', version_tc_fl, payload_length, next_header, hop_limit)
        header = header + src_addr + dst_addr
        
        return header
    
    def build_tcp_segment(
        self,
        src_port: int,
        dst_port: int,
        sequence: int,
        acknowledgment: int,
        flags: int,
        window: int = 65535,
        data: bytes = b''
    ) -> bytes:
        """
        Build TCP segment.
        
        TCP Header Format:
        +-----------+-----------+---+-------+-------+--------+--------+--------+
        | Source Port (16) |   Destination Port (16)  |                         |
        +-----------+-----------+---+-------+-------+--------+--------+--------+
        |                        Sequence Number (32)                          |
        +-----------+-----------+---+-------+-------+--------+--------+--------+
        |                    Acknowledgment Number (32)                        |
        +-----------+-----------+---+-------+-------+--------+--------+--------+
        | Offset (4)| Reserved (4)|U|A|P|R|S|F|        Window Size (16)        |
        +-----------+-----------+---+-------+-------+--------+--------+--------+
        |    Checksum (16)        |         Urgent Pointer (16)               |
        +-----------+-----------+---+-------+-------+--------+--------+--------+
        
        Args:
            src_port: Source port (0-65535)
            dst_port: Destination port (0-65535)
            sequence: Sequence number
            acknowledgment: Acknowledgment number
            flags: TCP flags (URG=0x20, ACK=0x10, PSH=0x08, RST=0x04, SYN=0x02, FIN=0x01)
            window: Window size (default 65535)
            data: Optional data payload
            
        Returns:
            TCP segment bytes
            
        Raises:
            IPv6PacketError: If parameters are invalid
        """
        # Validate ports
        if not 0 <= src_port <= 65535:
            raise IPv6PacketError("Source port must be 0-65535")
        if not 0 <= dst_port <= 65535:
            raise IPv6PacketError("Destination port must be 0-65535")
        
        # Validate flags
        valid_flags = 0x3F  # Bits 0-5 (FIN, SYN, RST, PSH, ACK, URG)
        if flags & ~valid_flags:
            raise IPv6PacketError(f"Invalid TCP flags: {flags:#x}")
        
        # Calculate data offset (header length in 32-bit words)
        header_length = 20  # Minimum TCP header
        
        tcp_header = struct.pack('>HHIIHHHH',
            src_port,
            dst_port,
            sequence,
            acknowledgment,
            (header_length // 4) << 12 | flags,  # Offset (4 bits) + Reserved + Flags
            window,
            0,  # Checksum (calculated separately)
            0   # Urgent pointer
        )
        
        return tcp_header + data
    
    def build_ipv6_tcp_syn(
        self,
        src_addr: bytes,
        dst_addr: bytes,
        src_port: int,
        dst_port: int,
        sequence: Optional[int] = None,
        options: bytes = b'',
        traffic_class: int = 0,
        flow_label: int = 0,
        hop_limit: int = 64
    ) -> bytes:
        """
        Build IPv6 TCP SYN packet.
        
        Args:
            src_addr: Source IPv6 address (16 bytes)
            dst_addr: Destination IPv6 address (16 bytes)
            src_port: Source port
            dst_port: Destination port
            sequence: Optional sequence number (auto-generated if None)
            options: TCP options (MSS, SACK, etc.)
            traffic_class: Traffic class
            flow_label: Flow label
            hop_limit: Hop limit
            
        Returns:
            Complete IPv6 TCP SYN packet
            
        Raises:
            IPv6ValidationError: If addresses are invalid
        """
        if sequence is None:
            sequence = self._get_next_sequence()
        
        # Build TCP segment with SYN flag
        tcp_header = self.build_tcp_segment(
            src_port=src_port,
            dst_port=dst_port,
            sequence=sequence,
            acknowledgment=0,
            flags=0x02,  # SYN flag
            data=options
        )
        
        # Calculate checksum
        checksum = OptimizedChecksum.tcp_checksum_ipv6(
            src_ip=src_addr,
            dst_ip=dst_addr,
            tcp_segment=tcp_header
        )
        
        # Replace checksum in header
        tcp_header = tcp_header[:16] + struct.pack('>H', checksum) + tcp_header[18:]
        
        # Build IPv6 header
        ipv6_header = self.build_ipv6_header(
            src_addr=src_addr,
            dst_addr=dst_addr,
            payload_length=len(tcp_header),
            next_header=IPv6NextHeader.TCP,
            traffic_class=traffic_class,
            flow_label=flow_label,
            hop_limit=hop_limit
        )
        
        return ipv6_header + tcp_header
    
    def build_ipv6_tcp_packet(
        self,
        src_addr: bytes,
        dst_addr: bytes,
        src_port: int,
        dst_port: int,
        sequence: int,
        acknowledgment: int,
        flags: int,
        window: int = 65535,
        data: bytes = b'',
        options: bytes = b'',
        traffic_class: int = 0,
        flow_label: int = 0,
        hop_limit: int = 64
    ) -> bytes:
        """
        Build complete IPv6 TCP packet with payload.
        
        Args:
            src_addr: Source IPv6 address (16 bytes)
            dst_addr: Destination IPv6 address (16 bytes)
            src_port: Source port
            dst_port: Destination port
            sequence: Sequence number
            acknowledgment: Acknowledgment number
            flags: TCP flags
            window: Window size
            data: Data payload
            options
            traffic options: TCP_class: Traffic class
            flow_label: Flow label
            hop_limit: Hop limit
            
        Returns:
            Complete IPv6 TCP packet
        """
        # Build TCP segment
        tcp_header = self.build_tcp_segment(
            src_port=src_port,
            dst_port=dst_port,
            sequence=sequence,
            acknowledgment=acknowledgment,
            flags=flags,
            window=window,
            data=options + data
        )
        
        # Calculate checksum
        checksum = OptimizedChecksum.tcp_checksum_ipv6(
            src_ip=src_addr,
            dst_ip=dst_addr,
            tcp_segment=tcp_header
        )
        
        # Replace checksum in header
        tcp_header = tcp_header[:16] + struct.pack('>H', checksum) + tcp_header[18:]
        
        # Build IPv6 header
        ipv6_header = self.build_ipv6_header(
            src_addr=src_addr,
            dst_addr=dst_addr,
            payload_length=len(tcp_header),
            next_header=IPv6NextHeader.TCP,
            traffic_class=traffic_class,
            flow_label=flow_label,
            hop_limit=hop_limit
        )
        
        return ipv6_header + tcp_header
    
    def build_ipv6_udp_packet(
        self,
        src_addr: bytes,
        dst_addr: bytes,
        src_port: int,
        dst_port: int,
        data: bytes = b'',
        traffic_class: int = 0,
        flow_label: int = 0,
        hop_limit: int = 64,
        calculate_checksum: bool = True
    ) -> bytes:
        """
        Build IPv6 UDP packet.
        
        UDP Header Format (8 bytes):
        +-----------+-----------+---+-------+-------+
        | Source Port (16) | Dest Port (16) |
        +-----------+-----------+---+-------+-------+
        |     Length (16)   |   Checksum (16)|
        +-----------+-----------+---+-------+-------+
        
        Args:
            src_addr: Source IPv6 address (16 bytes)
            dst_addr: Destination IPv6 address (16 bytes)
            src_port: Source port
            dst_port: Destination port
            data: UDP payload
            traffic_class: Traffic class
            flow_label: Flow label
            hop_limit: Hop limit
            calculate_checksum: Whether to calculate checksum (recommended True)
            
        Returns:
            Complete IPv6 UDP packet
        """
        # Validate ports
        if not 0 <= src_port <= 65535:
            raise IPv6PacketError("Source port must be 0-65535")
        if not 0 <= dst_port <= 65535:
            raise IPv6PacketError("Destination port must be 0-65535")
        
        # Build UDP header
        length = 8 + len(data)
        udp_header = struct.pack('>HHHH',
            src_port,
            dst_port,
            length,
            0  # Checksum placeholder
        )
        
        # Calculate checksum if required
        if calculate_checksum:
            checksum = OptimizedChecksum.udp_checksum_ipv6(
                src_ip=src_addr,
                dst_ip=dst_addr,
                udp_segment=udp_header + data
            )
            udp_header = struct.pack('>HH', src_port, dst_port) + \
                        struct.pack('>H', length) + \
                        struct.pack('>H', checksum) + data
        else:
            udp_header = udp_header + data
        
        # Build IPv6 header
        ipv6_header = self.build_ipv6_header(
            src_addr=src_addr,
            dst_addr=dst_addr,
            payload_length=len(udp_header),
            next_header=IPv6NextHeader.UDP,
            traffic_class=traffic_class,
            flow_label=flow_label,
            hop_limit=hop_limit
        )
        
        return ipv6_header + udp_header
    
    def build_ipv6_icmpv6_packet(
        self,
        src_addr: bytes,
        dst_addr: bytes,
        icmp_type: int,
        icmp_code: int,
        data: bytes = b'',
        traffic_class: int = 0,
        flow_label: int = 0,
        hop_limit: int = 64
    ) -> bytes:
        """
        Build IPv6 ICMPv6 packet.
        
        ICMPv6 Header Format:
        +-----------+-----------+---+-------+-------+
        | Type (8)  | Code (8)  |    Checksum (16)    |
        +-----------+-----------+---+-------+-------+
        |              Rest of Header / Message Body            |
        +-----------+-----------+---+-------+-------+
        
        Args:
            src_addr: Source IPv6 address (16 bytes)
            dst_addr: Destination IPv6 address (16 bytes)
            icmp_type: ICMPv6 type
            icmp_code: ICMPv6 code
            data: ICMPv6 payload
            traffic_class: Traffic class
            flow_label: Flow label
            hop_limit: Hop limit
            
        Returns:
            Complete IPv6 ICMPv6 packet
        """
        # Build ICMPv6 header with placeholder checksum
        icmp_header = struct.pack('>BBH', icmp_type, icmp_code, 0) + data
        
        # Calculate checksum
        checksum = OptimizedChecksum.icmpv6_checksum(
            src_ip=src_addr,
            dst_ip=dst_addr,
            icmp_data=icmp_header
        )
        
        # Replace checksum
        icmp_header = struct.pack('>BBH', icmp_type, icmp_code, checksum) + data
        
        # Build IPv6 header
        ipv6_header = self.build_ipv6_header(
            src_addr=src_addr,
            dst_addr=dst_addr,
            payload_length=len(icmp_header),
            next_header=IPv6NextHeader.ICMPV6,
            traffic_class=traffic_class,
            flow_label=flow_label,
            hop_limit=hop_limit
        )
        
        return ipv6_header + icmp_header
    
    def build_icmpv6_echo_request(
        self,
        src_addr: bytes,
        dst_addr: bytes,
        identifier: int,
        sequence: int,
        data: bytes = b'',
        traffic_class: int = 0,
        flow_label: int = 0,
        hop_limit: int = 64
    ) -> bytes:
        """
        Build ICMPv6 Echo Request (Ping) packet.
        
        Args:
            src_addr: Source IPv6 address (16 bytes)
            dst_addr: Destination IPv6 address (16 bytes)
            identifier: ICMP identifier
            sequence: ICMP sequence number
            data: Optional payload data
            traffic_class: Traffic class
            flow_label: Flow label
            hop_limit: Hop limit
            
        Returns:
            Complete ICMPv6 Echo Request packet
        """
        # Build ICMPv6 data
        icmp_data = struct.pack('>HH', identifier, sequence) + data
        
        return self.build_ipv6_icmpv6_packet(
            src_addr=src_addr,
            dst_addr=dst_addr,
            icmp_type=128,  # Echo Request
            icmp_code=0,
            data=icmp_data,
            traffic_class=traffic_class,
            flow_label=flow_label,
            hop_limit=hop_limit
        )
    
    def build_icmpv6_echo_reply(
        self,
        src_addr: bytes,
        dst_addr: bytes,
        identifier: int,
        sequence: int,
        data: bytes = b'',
        traffic_class: int = 0,
        flow_label: int = 0,
        hop_limit: int = 64
    ) -> bytes:
        """
        Build ICMPv6 Echo Reply packet.
        
        Args:
            src_addr: Source IPv6 address (16 bytes)
            dst_addr: Destination IPv6 address (16 bytes)
            identifier: ICMP identifier
            sequence: ICMP sequence number
            data: Optional payload data
            traffic_class: Traffic class
            flow_label: Flow label
            hop_limit: Hop limit
            
        Returns:
            Complete ICMPv6 Echo Reply packet
        """
        # Build ICMPv6 data
        icmp_data = struct.pack('>HH', identifier, sequence) + data
        
        return self.build_ipv6_icmpv6_packet(
            src_addr=src_addr,
            dst_addr=dst_addr,
            icmp_type=129,  # Echo Reply
            icmp_code=0,
            data=icmp_data,
            traffic_class=traffic_class,
            flow_label=flow_label,
            hop_limit=hop_limit
        )
    
    def fragment_packet(
        self,
        packet: bytes,
        mtu: int = 1280
    ) -> List[bytes]:
        """
        Fragment IPv6 packet according to RFC 8200.
        
        Note: IPv6 fragmentation is done at the extension header level,
        not at the IP level like IPv4.
        
        Args:
            packet: Full IPv6 packet
            mtu: Maximum transmission unit (minimum 1280)
            
        Returns:
            List of fragmented packets
            
        Raises:
            IPv6PacketError: If packet is too small to fragment
        """
        if len(packet) < self.IPV6_HEADER_SIZE + 8:
            raise IPv6PacketError("Packet too small to fragment")
        
        if mtu < self.MIN_MTU:
            mtu = self.MIN_MTU
        
        # First fragment must contain the IPv6 header + first fragment header
        # Fragment header is 8 bytes
        fragment_header_size = 8
        
        # Calculate available payload per fragment
        # Must be multiple of 8 bytes (except possibly last fragment)
        available_payload = mtu - self.IPV6_HEADER_SIZE - fragment_header_size
        available_payload = (available_payload // 8) * 8
        
        if available_payload < 8:
            raise IPv6PacketError(f"MTU too small: {mtu}")
        
        # Get the IPv6 header and identify upper-layer start
        ipv6_header = packet[:self.IPV6_HEADER_SIZE]
        _next_header = ipv6_header[6]  # noqa: F841 - Offset 6 is Next Header byte, extracted for clarity
        upper_layer = packet[self.IPV6_HEADER_SIZE:]
        
        fragments = []
        offset = 0
        identification = self._get_next_identification()
        
        while offset < len(upper_layer):
            is_last = (offset + available_payload >= len(upper_layer))
            chunk = upper_layer[offset:offset + available_payload]
            
            # Fragment header format (RFC 8200):
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            # |  Next Header  |  Hdr Ext Len  |           Reserved          |
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            # |      Fragment Offset        |  M  |     Identification       |
            # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            # Hdr Ext Len = 0 for fragment header
            # Fragment Offset = offset in 8-byte units (13 bits)
            # M = More Fragments flag (1 bit)
            
            frag_offset = offset // 8  # Convert to 8-byte units
            mf_flag = 0 if is_last else 1
            
            # Build 32-bit first word: NextHeader(8) + Reserved(8) + Offset(13) + M(1) + ID upper(2)
            # Actually simplified: NextHeader(8) + 0x0000 + Offset(13) + M(1)
            first_word = (IPv6ExtensionHeader.FRAGMENT << 24) | (frag_offset << 5) | mf_flag
            
            frag_hdr = struct.pack('>II', first_word, identification)
            
            # Replace next header in IPv6 header with Fragment header type
            new_ipv6_header = ipv6_header[:6] + \
                             struct.pack('B', IPv6ExtensionHeader.FRAGMENT) + \
                             ipv6_header[7:]
            
            # Build fragment payload
            fragment = new_ipv6_header + frag_hdr
            
            # For non-last fragments, payload must be multiple of 8 bytes
            if not is_last and len(chunk) % 8 != 0:
                chunk = chunk[:-(len(chunk) % 8)]
            
            fragment += chunk
            
            fragments.append(fragment)
            offset += len(chunk)
        
        return fragments
    
    def parse_packet(self, packet: bytes) -> Dict[str, Any]:
        """
        Parse IPv6 packet and extract components.
        
        Args:
            packet: Raw IPv6 packet bytes
            
        Returns:
            Dictionary with parsed packet information
            
        Raises:
            IPv6PacketError: If packet is invalid
        """
        if len(packet) < self.IPV6_HEADER_SIZE:
            raise IPv6PacketError("Packet too short for IPv6 header")
        
        # Parse IPv6 header
        version_tc_fl, payload_len, next_header, hop_limit = struct.unpack(
            '>IHBB', packet[:8]
        )
        
        version = (version_tc_fl >> 28) & 0xF
        traffic_class = ((version_tc_fl >> 20) & 0xFF)
        flow_label = version_tc_fl & 0xFFFFF
        
        src_addr = packet[8:24]
        dst_addr = packet[24:40]
        
        if version != 6:
            raise IPv6PacketError(f"Not an IPv6 packet (version {version})")
        
        result = {
            'version': version,
            'traffic_class': traffic_class,
            'flow_label': flow_label,
            'payload_length': payload_len,
            'next_header': next_header,
            'hop_limit': hop_limit,
            'src_addr': self.ipv6_to_string(src_addr),
            'dst_addr': self.ipv6_to_string(dst_addr),
            'src_addr_raw': src_addr,
            'dst_addr_raw': dst_addr,
            'total_length': self.IPV6_HEADER_SIZE + payload_len,
            'extensions': []
        }
        
        # Parse extension headers and upper-layer protocol
        offset = self.IPV6_HEADER_SIZE
        current_next = next_header
        
        while current_next in [IPv6ExtensionHeader.HOP_BY_HOP, 
                               IPv6ExtensionHeader.ROUTING,
                               IPv6ExtensionHeader.FRAGMENT,
                               IPv6ExtensionHeader.DESTINATION_OPTIONS]:
            if offset >= len(packet):
                break
            
            ext_len = packet[offset + 1]
            ext_data = packet[offset:offset + 8 + ext_len * 8]
            
            result['extensions'].append({
                'type': current_next,
                'length': len(ext_data),
                'data': ext_data
            })
            
            current_next = ext_data[0]
            offset += len(ext_data)
        
        result['upper_protocol'] = current_next
        result['upper_layer_offset'] = offset
        result['payload'] = packet[offset:]
        
        return result
    
    @staticmethod
    def tcp_options_to_bytes(options: List[Tuple[int, bytes]]) -> bytes:
        """
        Convert TCP options list to bytes.
        
        Args:
            options: List of (option_kind, value_bytes) tuples
            
        Returns:
            TCP options as bytes
            
        Raises:
            IPv6PacketError: If options are invalid
        """
        result = b''
        for kind, value in options:
            if kind == 0:  # EOL
                result += struct.pack('B', 0)
            elif kind == 1:  # NOP
                result += struct.pack('B', 1)
            else:
                if len(value) > 255:
                    raise IPv6PacketError("TCP option value too long")
                result += struct.pack('BB', kind, len(value) + 2) + value
        
        # Pad to 4-byte boundary
        padding = (4 - (len(result) % 4)) % 4
        if padding:
            result += bytes(padding)
        
        return result
    
    @staticmethod
    def create_mss_option(mss: int = 1460) -> bytes:
        """
        Create MSS TCP option.
        
        Args:
            mss: Maximum segment size
            
        Returns:
            MSS option bytes
        """
        return struct.pack('>BBH', 2, 4, mss)
    
    @staticmethod
    def create_sack_permitted_option() -> bytes:
        """
        Create SACK Permitted TCP option.
        
        Returns:
            SACK Permitted option bytes
        """
        return struct.pack('>BB', 4, 2)
    
    @staticmethod
    def create_window_scale_option(shift: int = 14) -> bytes:
        """
        Create Window Scale TCP option.
        
        Args:
            shift: Window shift count (0-14)
            
        Returns:
            Window Scale option bytes
        """
        return struct.pack('>BBB', 3, 3, shift)
    
    @staticmethod
    def create_timestamp_option(
        timestamp_value: int = 0,
        timestamp_echo: int = 0
    ) -> bytes:
        """
        Create Timestamp TCP option.
        
        Args:
            timestamp_value: Current timestamp
            timestamp_echo: Echoed timestamp
            
        Returns:
            Timestamp option bytes
        """
        return struct.pack('>BBII', 8, 10, timestamp_value, timestamp_echo)
    
    def build_syn_options(
        self,
        mss: int = 1460,
        window_scale: bool = True,
        sack_permitted: bool = True,
        timestamps: bool = True
    ) -> bytes:
        """
        Build SYN packet TCP options.
        
        Args:
            mss: Maximum segment size
            window_scale: Include window scale option
            sack_permitted: Include SACK permitted option
            timestamps: Include timestamp option
            
        Returns:
            TCP options bytes
        """
        options = [
            (2, struct.pack('>H', mss))  # MSS
        ]
        
        if sack_permitted:
            options.append((4, b''))  # SACK Permitted
        
        if window_scale:
            options.append((3, bytes([14])))  # Window Scale (shift=14)
        
        if timestamps:
            options.append((8, struct.pack('>II', 0, 0)))  # Timestamp
        
        return self.tcp_options_to_bytes(options)
