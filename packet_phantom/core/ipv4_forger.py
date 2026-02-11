"""
IPv4 Packet Forger - IPv4 packet crafting module.

Provides IPv4 packet building capabilities:
- IPv4 header construction (20+ bytes)
- Protocol support (TCP, UDP, ICMP)
- Fragmentation support
- TCP segment building with proper checksum calculation
- SYN packet generation
- Thread-safe operations
"""

import struct
import socket
import threading
from typing import Optional, Any
from enum import IntEnum

from .checksum import OptimizedChecksum


class IPv4ForgerError(Exception):
    """Raised when IPv4 packet construction fails."""
    pass


class IPv4ValidationError(Exception):
    """Raised when IPv4 input validation fails."""
    pass


class IPv4Protocol(IntEnum):
    """IPv4 Protocol Numbers."""
    ICMP = 1
    TCP = 6
    UDP = 17
    ICMPV6 = 58


class IPv4PacketForger:
    """
    Thread-safe IPv4 packet forger with comprehensive features.
    
    Features:
    - Full IPv4 header construction
    - Fragmentation support
    - TCP/UDP/ICMP payload support
    - TCP segment building with checksum calculation
    - SYN packet generation
    - Thread-safe operations
    
    Security Features:
    - Input validation for all addresses
    - Memory bounds enforcement
    """
    
    IP_VERSION = 4
    MIN_HEADER_SIZE = 20
    MAX_HEADER_SIZE = 60
    MAX_PAYLOAD_SIZE = 65535 - 20
    
    # Thread-safe identification tracking
    _lock = threading.Lock()
    _identification_counter = 0
    _sequence_counter = 0
    
    def __init__(self, rate_limiter: Optional[Any] = None):
        """
        Initialize IPv4 packet forger.
        
        Args:
            rate_limiter: Optional TokenBucket rate limiter for throttling
        """
        self.rate_limiter = rate_limiter
        self._local_identification = 0
        self._local_sequence = 0
    
    @classmethod
    def validate_ipv4_address(cls, addr: str) -> bool:
        """
        Validate IPv4 address format.
        
        Args:
            addr: IPv4 address string to validate
            
        Returns:
            True if valid, False otherwise
        """
        try:
            socket.inet_aton(addr)
            return True
        except socket.error:
            return False
    
    @classmethod
    def parse_ipv4_address(cls, addr: str) -> bytes:
        """
        Parse IPv4 address string to 4-byte binary format.
        
        Args:
            addr: IPv4 address string
            
        Returns:
            4-byte representation
            
        Raises:
            IPv4ValidationError: If address is invalid
        """
        if not cls.validate_ipv4_address(addr):
            raise IPv4ValidationError(f"Invalid IPv4 address: {addr}")
        return socket.inet_aton(addr)
    
    @classmethod
    def ipv4_to_string(cls, addr: bytes) -> str:
        """
        Convert 4-byte IPv4 address to string format.
        
        Args:
            addr: 4-byte IPv4 address
            
        Returns:
            IPv4 address string
            
        Raises:
            IPv4ValidationError: If address length is invalid
        """
        if len(addr) != 4:
            raise IPv4ValidationError("IPv4 address must be 4 bytes")
        return socket.inet_ntoa(addr)
    
    def _get_next_identification(self) -> int:
        """Get next identification value (thread-safe)."""
        with self._lock:
            self._identification_counter += 1
            self._local_identification = self._identification_counter
            return self._local_identification
    
    def _get_next_sequence(self) -> int:
        """Get next TCP sequence number (thread-safe)."""
        with self._lock:
            self._sequence_counter += 1
            self._local_sequence = self._sequence_counter
            return self._local_sequence
    
    def build_ipv4_header(
        self,
        src_addr: str,
        dst_addr: str,
        protocol: int,
        payload_length: int,
        ttl: int = 64,
        id: Optional[int] = None,
        flags: int = 0,
        offset: int = 0,
        tos: int = 0
    ) -> bytes:
        """
        Build IPv4 header.
        
        IPv4 Header Format:
        +-----------+-----------+---+-------+-------+--------+--------+--------+
        | Ver (4)   | IHL (4)   |   TOS/DSCP (8)    |            Total Length (16)          |
        +-----------+-----------+---+-------+-------+--------+--------+--------+
        |         Identification (16)        | Flags (3) |      Fragment Offset (13)           |
        +-----------+-----------+---+-------+-------+--------+--------+--------+
        |    TTL (8) |    Protocol (8)     |         Header Checksum (16)                   |
        +-----------+-----------+---+-------+-------+--------+--------+--------+
        |                                                               |
        +                    Source Address (32 bits)                          +
        |                                                               |
        +-------------------+-------------------+------------------------------+
        +                                                               +
        +              Destination Address (32 bits)                        +
        |                                                               |
        +-------------------+-------------------+---------------------------+
        
        Args:
            src_addr: Source IPv4 address (string or bytes)
            dst_addr: Destination IPv4 address (string or bytes)
            protocol: Protocol number (TCP=6, UDP=17, ICMP=1)
            payload_length: Length of payload
            ttl: Time to live (default 64)
            id: Identification value (auto-generated if None)
            flags: IP flags (DF=0x2, MF=0x1)
            offset: Fragment offset
            tos: Type of service / DSCP / ECN
            
        Returns:
            IPv4 header bytes
            
        Raises:
            IPv4ValidationError: If addresses are invalid
        """
        # Parse addresses
        if isinstance(src_addr, str):
            src_addr_bytes = self.parse_ipv4_address(src_addr)
        else:
            src_addr_bytes = src_addr
        
        if isinstance(dst_addr, str):
            dst_addr_bytes = self.parse_ipv4_address(dst_addr)
        else:
            dst_addr_bytes = dst_addr
        
        # Validate addresses
        if len(src_addr_bytes) != 4:
            raise IPv4ValidationError("Source address must be 4 bytes")
        if len(dst_addr_bytes) != 4:
            raise IPv4ValidationError("Destination address must be 4 bytes")
        
        # Calculate total length
        total_length = self.MIN_HEADER_SIZE + payload_length
        
        # Validate parameters
        if not 0 <= ttl <= 255:
            raise IPv4ValidationError("TTL must be 0-255")
        if not 0 <= total_length <= 0xFFFF:
            raise IPv4ValidationError("Total length out of range")
        if not 0 <= flags <= 0x7:
            raise IPv4ValidationError("Flags out of range")
        if not 0 <= offset <= 0x1FFF:
            raise IPv4ValidationError("Fragment offset out of range")
        
        # Get identification
        if id is None:
            id = self._get_next_identification()
        
        # Build first word: Version (4) + IHL (5 for 20 bytes) + TOS
        version_ihl = (self.IP_VERSION << 4) | (self.MIN_HEADER_SIZE // 4)
        first_word = (version_ihl << 24) | (tos << 16) | total_length
        
        # Build second word: ID + Flags + Offset
        second_word = (id << 16) | (flags << 13) | offset
        
        # Build header
        header = struct.pack('!II', first_word, second_word)
        header += struct.pack('!BBH', ttl, protocol, 0)  # Checksum placeholder
        header += src_addr_bytes + dst_addr_bytes
        
        # Calculate checksum
        checksum = OptimizedChecksum.ipv4_header_checksum(header)
        
        # Replace checksum in header
        header = header[:10] + struct.pack('!H', checksum) + header[12:]
        
        return header
    
    def build_ipv4_packet(
        self,
        src_addr: str,
        dst_addr: str,
        protocol: int,
        payload: bytes = b'',
        ttl: int = 64,
        id: Optional[int] = None,
        flags: int = 0,
        offset: int = 0,
        tos: int = 0
    ) -> bytes:
        """
        Build complete IPv4 packet.
        
        Args:
            src_addr: Source IPv4 address
            dst_addr: Destination IPv4 address
            protocol: Protocol number
            payload: Packet payload
            ttl: Time to live
            id: Identification value
            flags: IP flags
            offset: Fragment offset
            tos: Type of service
            
        Returns:
            Complete IPv4 packet
        """
        header = self.build_ipv4_header(
            src_addr=src_addr,
            dst_addr=dst_addr,
            protocol=protocol,
            payload_length=len(payload),
            ttl=ttl,
            id=id,
            flags=flags,
            offset=offset,
            tos=tos
        )
        
        return header + payload
    
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
            TCP segment bytes with checksum=0
            
        Raises:
            IPv4ForgerError: If parameters are invalid
        """
        # Validate ports
        if not 0 <= src_port <= 65535:
            raise IPv4ForgerError("Source port must be 0-65535")
        if not 0 <= dst_port <= 65535:
            raise IPv4ForgerError("Destination port must be 0-65535")
        
        # Validate flags
        valid_flags = 0x3F  # Bits 0-5 (FIN, SYN, RST, PSH, ACK, URG)
        if flags & ~valid_flags:
            raise IPv4ForgerError(f"Invalid TCP flags: {flags:#x}")
        
        # Calculate data offset (header length in 32-bit words)
        header_length = 20  # Minimum TCP header
        
        tcp_header = struct.pack('!HHIIHHHH',
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
    
    def build_tcp_syn_packet(
        self,
        src_addr: str,
        dst_addr: str,
        src_port: int,
        dst_port: int,
        sequence: Optional[int] = None,
        options: bytes = b'',
        ttl: int = 64,
        tos: int = 0
    ) -> bytes:
        """
        Build IPv4 TCP SYN packet with proper checksum calculation.
        
        The TCP checksum is calculated using the RFC-compliant ones-complement
        algorithm with a pseudo-header containing:
        - Source IP address (4 bytes)
        - Destination IP address (4 bytes)
        - Zero (1 byte)
        - Protocol (1 byte, TCP=6)
        - TCP length (2 bytes, header + data)
        
        Args:
            src_addr: Source IPv4 address (string or bytes)
            dst_addr: Destination IPv4 address (string or bytes)
            src_port: Source port
            dst_port: Destination port
            sequence: Optional sequence number (auto-generated if None)
            options: TCP options (MSS, SACK, etc.)
            ttl: Time to live (default 64)
            tos: Type of service (default 0)
            
        Returns:
            Complete IPv4 TCP SYN packet with valid checksum
            
        Raises:
            IPv4ValidationError: If addresses are invalid
            IPv4ForgerError: If parameters are invalid
        """
        # Auto-generate sequence number if not provided
        if sequence is None:
            sequence = self._get_next_sequence()
        
        # Parse addresses to bytes if they're strings
        if isinstance(src_addr, str):
            src_addr_bytes = self.parse_ipv4_address(src_addr)
        else:
            src_addr_bytes = src_addr
        
        if isinstance(dst_addr, str):
            dst_addr_bytes = self.parse_ipv4_address(dst_addr)
        else:
            dst_addr_bytes = dst_addr
        
        # Validate addresses
        if len(src_addr_bytes) != 4:
            raise IPv4ValidationError("Source address must be 4 bytes")
        if len(dst_addr_bytes) != 4:
            raise IPv4ValidationError("Destination address must be 4 bytes")
        
        # Build TCP segment with SYN flag and checksum=0
        tcp_header = self.build_tcp_segment(
            src_port=src_port,
            dst_port=dst_port,
            sequence=sequence,
            acknowledgment=0,
            flags=0x02,  # SYN flag
            data=options
        )
        
        # Calculate TCP checksum using OptimizedChecksum
        # The tcp_segment already has checksum=0, which is correct for calculation
        checksum = OptimizedChecksum.tcp_checksum_ipv4(
            src_ip=src_addr_bytes,
            dst_ip=dst_addr_bytes,
            tcp_segment=tcp_header
        )
        
        # Insert calculated checksum into TCP header at position 16
        tcp_header = tcp_header[:16] + struct.pack('!H', checksum) + tcp_header[18:]
        
        # Build IPv4 header
        ipv4_header = self.build_ipv4_header(
            src_addr=src_addr_bytes,
            dst_addr=dst_addr_bytes,
            protocol=IPv4Protocol.TCP,
            payload_length=len(tcp_header),
            ttl=ttl,
            tos=tos
        )
        
        return ipv4_header + tcp_header
    
    def build_tcp_packet(
        self,
        src_addr: str,
        dst_addr: str,
        src_port: int,
        dst_port: int,
        sequence: int,
        acknowledgment: int,
        flags: int,
        window: int = 65535,
        data: bytes = b'',
        options: bytes = b'',
        ttl: int = 64,
        tos: int = 0
    ) -> bytes:
        """
        Build complete IPv4 TCP packet with payload.
        
        Args:
            src_addr: Source IPv4 address (string or bytes)
            dst_addr: Destination IPv4 address (string or bytes)
            src_port: Source port
            dst_port: Destination port
            sequence: Sequence number
            acknowledgment: Acknowledgment number
            flags: TCP flags
            window: Window size
            data: Data payload
            options: TCP options
            ttl: Time to live
            tos: Type of service
            
        Returns:
            Complete IPv4 TCP packet with valid checksum
            
        Raises:
            IPv4ValidationError: If addresses are invalid
            IPv4ForgerError: If parameters are invalid
        """
        # Parse addresses to bytes if they're strings
        if isinstance(src_addr, str):
            src_addr_bytes = self.parse_ipv4_address(src_addr)
        else:
            src_addr_bytes = src_addr
        
        if isinstance(dst_addr, str):
            dst_addr_bytes = self.parse_ipv4_address(dst_addr)
        else:
            dst_addr_bytes = dst_addr
        
        # Validate addresses
        if len(src_addr_bytes) != 4:
            raise IPv4ValidationError("Source address must be 4 bytes")
        if len(dst_addr_bytes) != 4:
            raise IPv4ValidationError("Destination address must be 4 bytes")
        
        # Build TCP segment with checksum=0
        tcp_header = self.build_tcp_segment(
            src_port=src_port,
            dst_port=dst_port,
            sequence=sequence,
            acknowledgment=acknowledgment,
            flags=flags,
            window=window,
            data=options + data
        )
        
        # Calculate TCP checksum using OptimizedChecksum
        checksum = OptimizedChecksum.tcp_checksum_ipv4(
            src_ip=src_addr_bytes,
            dst_ip=dst_addr_bytes,
            tcp_segment=tcp_header
        )
        
        # Insert calculated checksum into TCP header at position 16
        tcp_header = tcp_header[:16] + struct.pack('!H', checksum) + tcp_header[18:]
        
        # Build IPv4 header
        ipv4_header = self.build_ipv4_header(
            src_addr=src_addr_bytes,
            dst_addr=dst_addr_bytes,
            protocol=IPv4Protocol.TCP,
            payload_length=len(tcp_header),
            ttl=ttl,
            tos=tos
        )
        
        return ipv4_header + tcp_header


__all__ = [
    'IPv4PacketForger',
    'IPv4ForgerError',
    'IPv4ValidationError',
    'IPv4Protocol',
]
