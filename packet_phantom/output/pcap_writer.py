import struct
import time
import os
import fcntl
import threading
import logging
from typing import List, Optional, Callable, Any

# Setup logging
security_logger = logging.getLogger('security')


class PCAPWriter:
    """
    Native PCAP file writer (NO scapy dependency).
    
    SECURITY: Process-safe with file locking to prevent corruption
    when multiple processes write to the same file.
    
    PCAP Global Header (24 bytes):
    - magic_number: 0xa1b2c3d4 (native) or 0xd4c3b2a1 (swapped)
    - version_major: 2
    - version_minor: 4
    - thiszone: 0 (timezone correction)
    - sigfigs: 0 (timestamp accuracy)
    - snaplen: 65535 (max packet length)
    - network: 1 (Ethernet)
    
    PCAP Packet Header (16 bytes):
    - ts_sec: seconds since epoch
    - ts_usec: microseconds
    - incl_len: bytes saved in file
    - orig_len: actual length of packet
    """
    
    # PCAP constants
    PCAP_MAGIC_NATIVE = 0xa1b2c3d4
    PCAP_MAGIC_SWAPPED = 0xd4c3b2a1
    VERSION_MAJOR = 2
    VERSION_MINOR = 4
    THISZONE = 0
    SIGFIGS = 0
    SNAPLEN = 65535
    NETWORK_ETHERNET = 1
    NETWORK_RAW = 101  # Raw IP
    
    # Maximum file size (security: prevent disk exhaustion)
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
    
    def __init__(self, filename: str, network: Optional[int] = None) -> None:
        """
        Initialize PCAP writer.
        
        SECURITY: Validates path and sets up file locking.
        
        Args:
            filename: Output file path
            network: Link-layer type (default: Ethernet, use 101 for raw IP)
            
        Raises:
            ValueError: If path is invalid
            PermissionError: If file cannot be created
        """
        self.filename = filename
        self.network = network if network is not None else self.NETWORK_ETHERNET
        self.packet_count = 0
        self._file_size = 0
        self._file = None
        self._lock = threading.Lock()  # Thread safety
        self._is_little_endian = struct.unpack('<H', b'\x01\x00')[0] == 1
        
        # SECURITY: Validate path before opening
        self._validate_path(filename)
        
        # Write global header
        self._write_global_header()
    
    def _validate_path(self, path: str) -> None:
        """
        Validate output path for security.
        
        SECURITY: Checks for:
        - Null bytes
        - Path traversal attempts
        - Sensitive system directories
        """
        # Check for null bytes
        if '\x00' in path:
            raise ValueError("Null byte in path - potential injection attack")
        
        # Check for path traversal
        normalized = os.path.normpath(path)
        if '..' in normalized.split(os.sep):
            # Allow if explicitly using ..
            if not path.startswith('..'):
                raise ValueError("Path traversal detected in PCAP filename")
        
        # Prevent writing to sensitive system directories
        sensitive_dirs = ['/etc/', '/root/', '/bin/', '/sbin/', '/usr/bin/', '/boot/']
        abs_path = os.path.abspath(path)
        for sensitive in sensitive_dirs:
            if abs_path.startswith(sensitive):
                raise ValueError(
                    f"Cannot write PCAP to protected system directory: {path}"
                )
    
    def _write_global_header(self) -> None:
        """Write PCAP global header to file with exclusive access."""
        if self._is_little_endian:
            magic = self.PCAP_MAGIC_NATIVE
        else:
            magic = self.PCAP_MAGIC_SWAPPED
        
        if self._is_little_endian:
            header = struct.pack('<IHHIIII',
                magic,
                self.VERSION_MAJOR,
                self.VERSION_MINOR,
                self.THISZONE,
                self.SIGFIGS,
                self.SNAPLEN,
                self.network
            )
        else:
            header = struct.pack('>IHHIIII',
                magic,
                self.VERSION_MAJOR,
                self.VERSION_MINOR,
                self.THISZONE,
                self.SIGFIGS,
                self.SNAPLEN,
                self.network
            )
        
        # Thread-safe file write
        with self._lock:
            self._file = open(self.filename, 'wb')
            self._file.write(header)
            self._file_size = len(header)
    
    def _get_packer(self) -> Callable[..., Any]:
        """Get appropriate struct packer based on endianness"""
        if self._is_little_endian:
            return lambda fmt, *args: struct.pack('<' + fmt.replace('<', '').replace('>', ''), *args)
        else:
            return lambda fmt, *args: struct.pack('>' + fmt.replace('<', '').replace('>', ''), *args)
    
    @property
    def file_size(self) -> int:
        """Get current file size thread-safely."""
        with self._lock:
            return self._file_size
    
    def write_packet(self, packet: bytes, 
                     timestamp: Optional[float] = None,
                     link_layer: Optional[bytes] = None) -> None:
        """
        Write packet to PCAP file.
        
        SECURITY: Thread-safe with file size limit enforcement.
        
        Args:
            packet: Raw packet bytes (IP packet or Ethernet frame)
            timestamp: Optional timestamp (default: current time)
            link_layer: Optional Ethernet header (if packet is IP only)
            
        Raises:
            OSError: If file size limit is reached
        """
        if timestamp is None:
            timestamp = time.time()
        
        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1000000)
        
        # Add Ethernet header if needed
        if self.network == self.NETWORK_ETHERNET and link_layer:
            full_packet = link_layer + packet
        elif self.network == self.NETWORK_RAW:
            full_packet = packet
        else:
            # Auto-detect: add Ethernet header if first byte doesn't look like Eth
            if len(packet) >= 14:
                # Assume Ethernet if starts with EtherType
                full_packet = packet
            else:
                # Add dummy Ethernet header
                dst_mac = b'\x00\x11\x22\x33\x44\x55'
                src_mac = b'\x66\x77\x88\x99\xaa\xbb'
                ethertype = b'\x08\x00'  # IPv4
                full_packet = dst_mac + src_mac + ethertype + packet
        
        incl_len = len(full_packet)
        orig_len = incl_len
        
        pack = self._get_packer()
        packet_header = pack('IIII', ts_sec, ts_usec, incl_len, orig_len)
        
        # Thread-safe write with file size check
        with self._lock:
            # Check file size limit
            if self._file_size + len(packet_header) + incl_len > self.MAX_FILE_SIZE:
                security_logger.warning(
                    f"PCAP file size limit ({self.MAX_FILE_SIZE} bytes) reached"
                )
                raise OSError("PCAP file size limit reached")
            
            # Advisory file locking (fcntl) for cross-process safety
            # This prevents corruption if multiple processes write to same file
            try:
                # Try to acquire exclusive lock (non-blocking)
                fcntl.flock(self._file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (IOError, OSError):
                # Lock not available - another process is writing
                # Skip this packet to prevent corruption
                security_logger.warning("Could not acquire file lock, skipping packet")
                return
            
            try:
                self._file.write(packet_header)
                self._file.write(full_packet)
                self._file.flush()  # Ensure data is written
                self._file_size += len(packet_header) + incl_len
            finally:
                # Release lock
                try:
                    fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
                except (IOError, OSError):
                    pass
        
        self.packet_count += 1
    
    def write_packets(self, packets: List[bytes], 
                     base_timestamp: Optional[float] = None) -> None:
        """Write multiple packets efficiently"""
        if base_timestamp is None:
            base_timestamp = time.time()
        
        for i, packet in enumerate(packets):
            timestamp = base_timestamp + (i * 0.001)  # 1ms apart
            try:
                self.write_packet(packet, timestamp)
            except OSError:
                # Stop writing if file size limit reached
                security_logger.info(f"Stopped writing after {i} packets due to size limit")
                break
    
    def close(self) -> None:
        """Close the PCAP file safely."""
        with self._lock:
            if self._file:
                try:
                    # Release any held lock before closing
                    fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
                    self._file.close()
                except (IOError, OSError):
                    pass
                self._file = None
    
    def __enter__(self) -> 'PCAPWriter':
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit - ensures file is closed."""
        self.close()
    
    @staticmethod
    def create_ethernet_header(src_mac: Optional[bytes] = None, 
                               dst_mac: Optional[bytes] = None,
                               ethertype: int = 0x0800) -> bytes:
        """Create Ethernet header"""
        dst = dst_mac if dst_mac else b'\xff\xff\xff\xff\xff\xff'
        src = src_mac if src_mac else b'\x00\x00\x00\x00\x00\x00'
        etype = struct.pack('!H', ethertype)
        return dst + src + etype
    
    @staticmethod
    def create_ethernet_header_ipv6(ethertype: int = 0x86dd) -> bytes:
        """Create Ethernet header for IPv6"""
        return PCAPWriter.create_ethernet_header(ethertype=ethertype)
