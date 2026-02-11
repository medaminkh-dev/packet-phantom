"""
ICMP Packet Forger - Advanced ICMP packet crafting module.

Provides comprehensive ICMP packet building capabilities for both IPv4 and IPv6:

ICMPv4 Support:
- Echo Request/Reply (type 8/0)
- Destination Unreachable (type 3)
- Time Exceeded (type 11)
- Source Quench (type 4) - deprecated but implemented

ICMPv6 Support:
- Echo Request/Reply (type 128/129)
- Destination Unreachable (type 1)
- Packet Too Big (type 2)
- Time Exceeded (type 3)
- Parameter Problem (type 4)

Features:
- Checksum calculation (ICMPv4 and ICMPv6)
- Payload generation
- Ping flood capability
- ICMP flood capability

All operations preserve security constraints.
"""

import struct
import socket
import random
import threading
import time
from typing import Optional, Any, List

from .checksum import OptimizedChecksum


class ICMPForgerError(Exception):
    """Raised when ICMP packet construction fails."""
    pass


class ICMPValidationError(Exception):
    """Raised when ICMP input validation fails."""
    pass


class ICMPForger:
    """
    Thread-safe ICMP packet forger with comprehensive features.
    
    Features:
    - Full ICMPv4 packet construction
    - Full ICMPv6 packet construction
    - Echo Request/Reply (ping)
    - Error message support (Destination Unreachable, Time Exceeded)
    - Checksum calculation
    - Flood capability
    - Thread-safe operations
    
    Security Features:
    - Input validation for all parameters
    - Payload size limits enforced
    - Checksum calculation secure
    - Thread-safe operations
    """
    
    # ICMPv4 Type codes
    ICMPV4_ECHO_REPLY = 0
    ICMPV4_DEST_UNREACHABLE = 3
    ICMPV4_SOURCE_QUENCH = 4
    ICMPV4_REDIRECT = 5
    ICMPV4_ECHO_REQUEST = 8
    ICMPV4_TIME_EXCEEDED = 11
    
    # ICMPv4 Destination Unreachable codes
    ICMPV4_NET_UNREACHABLE = 0
    ICMPV4_HOST_UNREACHABLE = 1
    ICMPV4_PROTO_UNREACHABLE = 2
    ICMPV4_PORT_UNREACHABLE = 3
    ICMPV4_FRAGMENTATION_NEEDED = 4
    ICMPV4_SOURCE_ROUTE_FAILED = 5
    
    # ICMPv4 Time Exceeded codes
    ICMPV4_TTL_EXCEEDED_TRANSIT = 0
    ICMPV4_TTL_EXCEEDED_REASSEMBLY = 1
    
    # ICMPv6 Type codes
    ICMPV6_DEST_UNREACHABLE = 1
    ICMPV6_PACKET_TOO_BIG = 2
    ICMPV6_TIME_EXCEEDED = 3
    ICMPV6_PARAMETER_PROBLEM = 4
    ICMPV6_ECHO_REQUEST = 128
    ICMPV6_ECHO_REPLY = 129
    
    # ICMPv6 Destination Unreachable codes
    ICMPV6_NO_ROUTE = 0
    ICMPV6_ADMIN_PROHIBITED = 1
    ICMPV6_BEYOND_SCOPE = 2
    ICMPV6_ADDRESS_UNREACHABLE = 3
    ICMPV6_PORT_UNREACHABLE = 4
    ICMPV6_SOURCE_POLICY_FAILED = 5
    ICMPV6_REJECT_ROUTE = 6
    
    # Constants
    ICMP_HEADER_SIZE = 8  # Common ICMP header size
    MAX_PAYLOAD_SIZE = 1472  # Same as UDP
    
    # Thread-safe sequence tracking
    _lock = threading.Lock()
    _echo_sequence = 0
    _echo6_sequence = 0
    
    def __init__(self, source_ip: Optional[str] = None, rate_limiter: Optional[Any] = None) -> None:
        """
        Initialize ICMP packet forger.
        
        Args:
            source_ip: Optional source IP address for spoofing
            rate_limiter: Optional TokenBucket rate limiter for throttling
        """
        self.source_ip = source_ip or self._get_local_ip()
        self.source_ip_bytes = self.parse_ipv4_address(self.source_ip)
        self.rate_limiter = rate_limiter
        self._local_sequence = 0
        self._local_sequence6 = 0
    
    @staticmethod
    def _get_local_ip() -> str:
        """Get local IP address for default source IP."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip: str = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception:
            return "127.0.0.1"
    
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
            ICMPValidationError: If address is invalid
        """
        if not cls.validate_ipv4_address(addr):
            raise ICMPValidationError(f"Invalid IPv4 address: {addr}")
        return socket.inet_aton(addr)
    
    @staticmethod
    def validate_ipv6_address(addr: str) -> bool:
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
    
    @staticmethod
    def parse_ipv6_address(addr: str) -> bytes:
        """
        Parse IPv6 address string to 16-byte binary format.
        
        Args:
            addr: IPv6 address string
            
        Returns:
            16-byte representation
            
        Raises:
            ICMPValidationError: If address is invalid
        """
        if not ICMPForger.validate_ipv6_address(addr):
            raise ICMPValidationError(f"Invalid IPv6 address: {addr}")
        return socket.inet_pton(socket.AF_INET6, addr)
    
    def _get_next_sequence(self) -> int:
        """Get next ICMPv4 echo sequence number (thread-safe)."""
        with self._lock:
            self._echo_sequence += 1
            self._local_sequence = self._echo_sequence
            return self._local_sequence
    
    def _get_next_sequence6(self) -> int:
        """Get next ICMPv6 echo sequence number (thread-safe)."""
        with self._lock:
            self._echo6_sequence += 1
            self._local_sequence6 = self._echo6_sequence
            return self._local_sequence6
    
    def _get_current_time_ms(self) -> int:
        """Get current time in milliseconds for ICMP timestamp."""
        return int(time.time() * 1000) & 0xFFFFFFFF
    
    def craft_icmp_echo(
        self,
        icmp_type: int,
        identifier: int,
        sequence: int,
        payload: bytes = b''
    ) -> bytes:
        """
        Craft ICMP Echo Request/Reply packet.
        
        ICMP Echo Request/Reply Format:
        +-----------+-----------+---+-------+-------+
        | Type (8)  | Code (8)  |      Checksum (16)     |
        +-----------+-----------+---+-------+-------+
        | Identifier (16) |    Sequence Number (16)  |
        +-----------+-----------+---+-------+-------+
        |                                                   |
        +                   Payload                         +
        |                                                   |
        +---------------------------------------------------+
        
        Args:
            icmp_type: ICMP type (8 for Request, 0 for Reply)
            identifier: ICMP identifier
            sequence: ICMP sequence number
            payload: Optional payload data
            
        Returns:
            Complete ICMP Echo packet
            
        Raises:
            ICMPValidationError: If parameters are invalid
        """
        # Validate parameters
        if not 0 <= identifier <= 0xFFFF:
            raise ICMPValidationError(
                f"Identifier out of range: {identifier}"
            )
        if not 0 <= sequence <= 0xFFFF:
            raise ICMPValidationError(
                f"Sequence number out of range: {sequence}"
            )
        if len(payload) > self.MAX_PAYLOAD_SIZE:
            raise ICMPValidationError(
                f"Payload too large: {len(payload)} bytes. "
                f"Maximum is {self.MAX_PAYLOAD_SIZE} bytes."
            )
        
        # Build ICMP header (type, code, checksum placeholder)
        icmp_header = struct.pack('!BBH', icmp_type, 0, 0)
        
        # Build ICMP body (identifier, sequence, payload)
        icmp_body = struct.pack('!HH', identifier, sequence) + payload
        
        # Calculate checksum
        checksum = OptimizedChecksum.icmp_checksum(icmp_header + icmp_body)
        
        # Build final header with checksum
        final_header = struct.pack('!BBH', icmp_type, 0, checksum)
        
        return final_header + icmp_body
    
    def craft_icmp_echo_request(
        self,
        identifier: Optional[int] = None,
        sequence: Optional[int] = None,
        payload: Optional[bytes] = None,
        target_ip: Optional[str] = None
    ) -> bytes:
        """
        Craft ICMP Echo Request (ping) packet.
        
        Args:
            identifier: ICMP identifier (auto-generated if None)
            sequence: ICMP sequence number (auto-incremented if None)
            payload: Optional payload data
            target_ip: Target IP (for tracking if needed)
            
        Returns:
            ICMP Echo Request packet
        """
        if identifier is None:
            identifier = random.randint(1, 0xFFFF)  # nosec B311 - not cryptographic
        if sequence is None:
            sequence = self._get_next_sequence()
        if payload is None:
            payload = self._generate_ping_payload()
        
        return self.craft_icmp_echo(
            icmp_type=self.ICMPV4_ECHO_REQUEST,
            identifier=identifier,
            sequence=sequence,
            payload=payload
        )
    
    def craft_icmp_echo_reply(
        self,
        identifier: int,
        sequence: int,
        payload: bytes = b''
    ) -> bytes:
        """
        Craft ICMP Echo Reply packet.
        
        Args:
            identifier: ICMP identifier (from request)
            sequence: ICMP sequence number (from request)
            payload: Payload from request
            
        Returns:
            ICMP Echo Reply packet
        """
        return self.craft_icmp_echo(
            icmp_type=self.ICMPV4_ECHO_REPLY,
            identifier=identifier,
            sequence=sequence,
            payload=payload
        )
    
    def craft_icmp_destination_unreachable(
        self,
        code: int,
        original_ip_header: bytes,
        original_icmp_data: bytes,
        src_ip: Optional[str] = None
    ) -> bytes:
        """
        Craft ICMP Destination Unreachable message.
        
        Args:
            code: Unreachable code
            original_ip_header: Original IP header that caused the error
            original_icmp_data: Original ICMP data that caused the error
            src_ip: Source IP for the unreachable message
            
        Returns:
            ICMP Destination Unreachable packet
            
        Raises:
            ICMPValidationError: If parameters are invalid
        """
        if not 0 <= code <= 5:
            raise ICMPValidationError(f"Invalid unreachable code: {code}")
        
        # Build unused field (32 bits of zero)
        unused = b'\x00\x00\x00\x00'
        
        # Build error data (original IP header + 8 bytes of original datagram)
        error_data = original_ip_header[:20] + original_icmp_data[:8]
        if len(error_data) < 28:
            error_data = error_data.ljust(28, b'\x00')
        
        # Build ICMP header
        icmp_header = struct.pack('!BBH', self.ICMPV4_DEST_UNREACHABLE, code, 0)
        
        # Calculate checksum
        checksum = OptimizedChecksum.icmp_checksum(icmp_header + unused + error_data)
        
        return struct.pack('!BBH', self.ICMPV4_DEST_UNREACHABLE, code, checksum) + unused + error_data
    
    def craft_icmp_time_exceeded(
        self,
        code: int = 0,
        original_ip_header: Optional[bytes] = None,
        original_data: Optional[bytes] = None
    ) -> bytes:
        """
        Craft ICMP Time Exceeded message.
        
        Args:
            code: Time exceeded code (0 = TTL, 1 = fragment reassembly)
            original_ip_header: Original IP header
            original_data: Original data
            
        Returns:
            ICMP Time Exceeded packet
        """
        if not 0 <= code <= 1:
            raise ICMPValidationError(f"Invalid time exceeded code: {code}")
        
        unused = b'\x00\x00\x00\x00'
        
        if original_ip_header is None:
            error_data = b'\x00' * 28
        else:
            error_data = original_ip_header[:20] + (original_data or b'')[:8]
            if len(error_data) < 28:
                error_data = error_data.ljust(28, b'\x00')
        
        icmp_header = struct.pack('!BBH', self.ICMPV4_TIME_EXCEEDED, code, 0)
        checksum = OptimizedChecksum.icmp_checksum(icmp_header + unused + error_data)
        
        return struct.pack('!BBH', self.ICMPV4_TIME_EXCEEDED, code, checksum) + unused + error_data
    
    def craft_icmp_packet(
        self,
        icmp_type: int,
        code: int,
        payload: bytes = b'',
        identifier: int = 0,
        sequence: int = 0
    ) -> bytes:
        """
        Generic ICMP packet crafting.
        
        Args:
            icmp_type: ICMP type
            code: ICMP code
            payload: ICMP payload
            identifier: ICMP identifier (for echo)
            sequence: ICMP sequence (for echo)
            
        Returns:
            Complete ICMP packet
        """
        # Build ICMP header
        if icmp_type in (self.ICMPV4_ECHO_REQUEST, self.ICMPV4_ECHO_REPLY):
            icmp_header = struct.pack('!BBH', icmp_type, code, 0)
            body = struct.pack('!HH', identifier, sequence) + payload
        else:
            icmp_header = struct.pack('!BBH', icmp_type, code, 0)
            body = payload
        
        # Calculate checksum
        checksum = OptimizedChecksum.icmp_checksum(icmp_header + body)
        
        return struct.pack('!BBH', icmp_type, code, checksum) + body
    
    # ICMPv6 Methods
    
    def craft_icmpv6_echo(
        self,
        icmp_type: int,
        identifier: int,
        sequence: int,
        payload: bytes = b'',
        src_ip: Optional[bytes] = None,
        dst_ip: Optional[bytes] = None
    ) -> bytes:
        """
        Craft ICMPv6 Echo Request/Reply packet.
        
        Args:
            icmp_type: ICMPv6 type (128 = Request, 129 = Reply)
            identifier: ICMPv6 identifier
            sequence: ICMPv6 sequence number
            payload: Optional payload data
            src_ip: Source IPv6 address (16 bytes)
            dst_ip: Destination IPv6 address (16 bytes)
            
        Returns:
            Complete ICMPv6 Echo packet
            
        Raises:
            ICMPValidationError: If parameters are invalid
        """
        if not 0 <= identifier <= 0xFFFF:
            raise ICMPValidationError(
                f"Identifier out of range: {identifier}"
            )
        if not 0 <= sequence <= 0xFFFF:
            raise ICMPValidationError(
                f"Sequence number out of range: {sequence}"
            )
        if len(payload) > self.MAX_PAYLOAD_SIZE:
            raise ICMPValidationError(
                f"Payload too large: {len(payload)} bytes. "
                f"Maximum is {self.MAX_PAYLOAD_SIZE} bytes."
            )
        
        # Build ICMPv6 header (type, code, checksum placeholder)
        icmp_header = struct.pack('!BBH', icmp_type, 0, 0)
        
        # Build ICMPv6 body
        icmp_body = struct.pack('!HH', identifier, sequence) + payload
        
        # Calculate checksum with pseudo-header if addresses provided
        checksum = 0
        if src_ip is not None and dst_ip is not None:
            checksum = OptimizedChecksum.icmpv6_checksum(
                src_ip=src_ip,
                dst_ip=dst_ip,
                icmp_data=icmp_header + icmp_body
            )
        
        return struct.pack('!BBH', icmp_type, 0, checksum) + icmp_body
    
    def craft_icmpv6_echo_request(
        self,
        identifier: Optional[int] = None,
        sequence: Optional[int] = None,
        payload: Optional[bytes] = None,
        src_ip: Optional[bytes] = None,
        dst_ip: Optional[bytes] = None
    ) -> bytes:
        """
        Craft ICMPv6 Echo Request (ping) packet.
        
        Args:
            identifier: ICMPv6 identifier (auto-generated if None)
            sequence: ICMPv6 sequence number (auto-incremented if None)
            payload: Optional payload data
            src_ip: Source IPv6 address
            dst_ip: Destination IPv6 address
            
        Returns:
            ICMPv6 Echo Request packet
        """
        if identifier is None:
            identifier = random.randint(1, 0xFFFF)  # nosec B311 - not cryptographic
        if sequence is None:
            sequence = self._get_next_sequence6()
        if payload is None:
            payload = self._generate_ping_payload()
        
        return self.craft_icmpv6_echo(
            icmp_type=self.ICMPV6_ECHO_REQUEST,
            identifier=identifier,
            sequence=sequence,
            payload=payload,
            src_ip=src_ip,
            dst_ip=dst_ip
        )
    
    def craft_icmpv6_echo_reply(
        self,
        identifier: int,
        sequence: int,
        payload: bytes = b'',
        src_ip: Optional[bytes] = None,
        dst_ip: Optional[bytes] = None
    ) -> bytes:
        """
        Craft ICMPv6 Echo Reply packet.
        
        Args:
            identifier: ICMPv6 identifier (from request)
            sequence: ICMPv6 sequence number (from request)
            payload: Payload from request
            src_ip: Source IPv6 address
            dst_ip: Destination IPv6 address
            
        Returns:
            ICMPv6 Echo Reply packet
        """
        return self.craft_icmpv6_echo(
            icmp_type=self.ICMPV6_ECHO_REPLY,
            identifier=identifier,
            sequence=sequence,
            payload=payload,
            src_ip=src_ip,
            dst_ip=dst_ip
        )
    
    def craft_icmpv6_packet(
        self,
        icmp_type: int,
        code: int,
        payload: bytes = b'',
        src_ip: Optional[bytes] = None,
        dst_ip: Optional[bytes] = None
    ) -> bytes:
        """
        Generic ICMPv6 packet crafting with pseudo-header checksum.
        
        Args:
            icmp_type: ICMPv6 type
            code: ICMPv6 code
            payload: ICMPv6 payload
            src_ip: Source IPv6 address (16 bytes)
            dst_ip: Destination IPv6 address (16 bytes)
            
        Returns:
            Complete ICMPv6 packet
        """
        # Build ICMPv6 header with checksum placeholder
        icmp_header = struct.pack('!BBH', icmp_type, code, 0)
        
        # Calculate checksum with pseudo-header if addresses provided
        checksum = 0
        if src_ip is not None and dst_ip is not None:
            checksum = OptimizedChecksum.icmpv6_checksum(
                src_ip=src_ip,
                dst_ip=dst_ip,
                icmp_data=icmp_header + payload
            )
        
        return struct.pack('!BBH', icmp_type, code, checksum) + payload
    
    def craft_icmpv6_destination_unreachable(
        self,
        code: int,
        payload: bytes = b'',
        src_ip: Optional[bytes] = None,
        dst_ip: Optional[bytes] = None
    ) -> bytes:
        """
        Craft ICMPv6 Destination Unreachable message.
        
        Args:
            code: Unreachable code
            payload: Additional data (typically includes original packet)
            src_ip: Source IPv6 address
            dst_ip: Destination IPv6 address
            
        Returns:
            ICMPv6 Destination Unreachable packet
        """
        if not 0 <= code <= 6:
            raise ICMPValidationError(f"Invalid ICMPv6 unreachable code: {code}")
        
        return self.craft_icmpv6_packet(
            icmp_type=self.ICMPV6_DEST_UNREACHABLE,
            code=code,
            payload=payload,
            src_ip=src_ip,
            dst_ip=dst_ip
        )
    
    def craft_icmpv6_packet_too_big(
        self,
        mtu: int,
        payload: bytes = b'',
        src_ip: Optional[bytes] = None,
        dst_ip: Optional[bytes] = None
    ) -> bytes:
        """
        Craft ICMPv6 Packet Too Big message.
        
        Args:
            mtu: Maximum Transmission Unit that couldn't be forwarded
            payload: Additional data
            src_ip: Source IPv6 address
            dst_ip: Destination IPv6 address
            
        Returns:
            ICMPv6 Packet Too Big packet
        """
        if not 0 <= mtu <= 0xFFFFFFFF:
            raise ICMPValidationError(f"MTU out of range: {mtu}")
        
        # Build MTU field
        mtu_field = struct.pack('!I', mtu)
        
        return self.craft_icmpv6_packet(
            icmp_type=self.ICMPV6_PACKET_TOO_BIG,
            code=0,
            payload=mtu_field + payload,
            src_ip=src_ip,
            dst_ip=dst_ip
        )
    
    def craft_icmpv6_time_exceeded(
        self,
        code: int = 0,
        payload: bytes = b'',
        src_ip: Optional[bytes] = None,
        dst_ip: Optional[bytes] = None
    ) -> bytes:
        """
        Craft ICMPv6 Time Exceeded message.
        
        Args:
            code: Time exceeded code (0 = hop limit, 1 = fragment reassembly)
            payload: Additional data
            src_ip: Source IPv6 address
            dst_ip: Destination IPv6 address
            
        Returns:
            ICMPv6 Time Exceeded packet
        """
        if not 0 <= code <= 1:
            raise ICMPValidationError(f"Invalid ICMPv6 time exceeded code: {code}")
        
        unused = b'\x00\x00\x00\x00'
        
        return self.craft_icmpv6_packet(
            icmp_type=self.ICMPV6_TIME_EXCEEDED,
            code=code,
            payload=unused + payload,
            src_ip=src_ip,
            dst_ip=dst_ip
        )
    
    def craft_icmpv6_parameter_problem(
        self,
        pointer: int,
        payload: bytes = b'',
        src_ip: bytes = None,
        dst_ip: bytes = None
    ) -> bytes:
        """
        Craft ICMPv6 Parameter Problem message.
        
        Args:
            pointer: Byte offset where the problem was detected
            payload: Additional data
            src_ip: Source IPv6 address
            dst_ip: Destination IPv6 address
            
        Returns:
            ICMPv6 Parameter Problem packet
        """
        # Build pointer field (32 bits)
        pointer_field = struct.pack('!I', pointer)
        
        return self.craft_icmpv6_packet(
            icmp_type=self.ICMPV6_PARAMETER_PROBLEM,
            code=0,
            payload=pointer_field + payload,
            src_ip=src_ip,
            dst_ip=dst_ip
        )
    
    # Flood generation methods
    
    def generate_ping_flood_packets(
        self,
        target_ip: str,
        num_packets: int = 100,
        payload_size: int = 64,
        is_ipv6: bool = False,
        dst_ip_bytes: bytes = None,
        src_ip_bytes: bytes = None
    ) -> List[bytes]:
        """
        Generate ping flood packets.
        
        Args:
            target_ip: Target IP address
            num_packets: Number of packets to generate
            payload_size: Size of each payload
            is_ipv6: True if IPv6
            dst_ip_bytes: Destination IP bytes (for IPv6 checksum)
            src_ip_bytes: Source IP bytes (for IPv6 checksum)
            
        Returns:
            List of ICMP echo request packets
        """
        if num_packets <= 0:
            raise ICMPValidationError("Number of packets must be positive")
        
        packets = []
        for i in range(num_packets):
            payload = self._generate_ping_payload(payload_size)
            if is_ipv6:
                packet = self.craft_icmpv6_echo_request(
                    identifier=random.randint(1, 0xFFFF),  # nosec B311 - not cryptographic
                    sequence=i,
                    payload=payload,
                    src_ip=src_ip_bytes,
                    dst_ip=dst_ip_bytes
                )
            else:
                packet = self.craft_icmp_echo_request(
                    identifier=random.randint(1, 0xFFFF),  # nosec B311 - not cryptographic
                    sequence=i,
                    payload=payload
                )
            packets.append(packet)
        
        return packets
    
    def _generate_ping_payload(self, size: int = 56) -> bytes:
        """
        Generate ping payload with timestamp and random data.
        
        Args:
            size: Size of payload to generate
            
        Returns:
            Ping payload bytes
        """
        # Generate timestamp
        timestamp = struct.pack('!d', time.time())
        
        # Generate random data
        random_data = random_bytes(size - len(timestamp))
        
        return timestamp + random_data
    
    # Parsing methods
    
    def parse_icmp_header(self, icmp_packet: bytes) -> dict:
        """
        Parse ICMP header from packet.
        
        Args:
            icmp_packet: ICMP packet bytes
            
        Returns:
            Dictionary with parsed ICMP header fields
        """
        if len(icmp_packet) < self.ICMP_HEADER_SIZE:
            raise ICMPForgerError(
                f"ICMP packet too short: {len(icmp_packet)} bytes. "
                f"Minimum is {self.ICMP_HEADER_SIZE} bytes."
            )
        
        icmp_type, code, checksum = struct.unpack('!BBH', icmp_packet[:4])
        
        # Parse echo-specific fields first (before setting payload)
        identifier = None
        sequence = None
        echo_payload = b''
        
        if icmp_type in (self.ICMPV4_ECHO_REQUEST, self.ICMPV4_ECHO_REPLY):
            if len(icmp_packet) >= 8:
                identifier, sequence = struct.unpack('!HH', icmp_packet[4:8])
                echo_payload = icmp_packet[8:]
        
        result = {
            'type': icmp_type,
            'code': code,
            'checksum': checksum,
            'payload': echo_payload
        }
        
        if identifier is not None:
            result['identifier'] = identifier
            result['sequence'] = sequence
        
        return result


def random_bytes(size: int) -> bytes:
    """
    Generate random bytes for payload.
    
    Args:
        size: Number of bytes to generate
        
    Returns:
        Random bytes
    """
    return bytes(random.randint(0, 255) for _ in range(size))  # nosec B311 - not cryptographic


__all__ = [
    'ICMPForger',
    'ICMPForgerError',
    'ICMPValidationError',
    'random_bytes',
]
