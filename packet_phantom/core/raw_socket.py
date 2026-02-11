"""
Raw Socket Module - Raw socket transmission for Packet Phantom.

Provides raw socket functionality for packet transmission without Scapy dependency.

Features:
- Raw socket creation with IP_HDRINCL=1
- Packet transmission via sendto
- Root privilege detection
- Thread-safe socket operations


Version: 2.0.0
"""

import socket
import struct
import os
import platform
import threading
import logging
from typing import Optional, Union

# Setup logging
security_logger = logging.getLogger('security')


def create_raw_socket(is_ipv6: bool = False) -> socket.socket:
    """
    Create a raw socket with IP_HDRINCL=1.
    
    Args:
        is_ipv6: If True, create IPv6 raw socket
    
    Returns:
        socket.socket: Configured raw socket
        
    Raises:
        PermissionError: If not running as root
        NotImplementedError: If platform doesn't support required socket type
    """
    if is_ipv6:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_RAW)
        # IPv6 doesn't use IP_HDRINCL, the kernel builds the IPv6 header
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return sock


def send_raw_packet(sock: socket.socket, packet_bytes: bytes, dst_ip: str, is_ipv6: bool = False) -> int:
    """
    Send raw packet via socket with thread-safety.
    
    Args:
        sock: Raw socket to use
        packet_bytes: Raw packet bytes to send
        dst_ip: Destination IP address
        is_ipv6: If True, destination is IPv6 address
        
    Returns:
        int: Number of bytes sent
    """
    if is_ipv6:
        # IPv6 raw sockets use scope ID for link-local addresses
        return sock.sendto(packet_bytes, (dst_ip, 0, 0, 0))
    else:
        return sock.sendto(packet_bytes, (dst_ip, 0))


def is_root() -> bool:
    """
    Check if running as root.
    
    Returns:
        bool: True if running with root privileges
    """
    return os.geteuid() == 0


def is_linux() -> bool:
    """
    Check if running on Linux.
    
    SECURITY: AF_PACKET is Linux-specific. Use this to check
    before attempting to create packet sockets.
    
    Returns:
        bool: True if running on Linux
    """
    return platform.system() == 'Linux'


def create_packet_socket(interface: Optional[str] = None) -> socket.socket:
    """
    Create a packet socket for link-layer access.
    
    SECURITY: AF_PACKET is Linux-only. This function validates
    the platform before attempting to create the socket.
    
    Args:
        interface: Network interface name (optional)
        
    Returns:
        socket.socket: Configured packet socket
        
    Raises:
        NotImplementedError: If not running on Linux
        PermissionError: If not running as root
    """
    # Check platform first - AF_PACKET is Linux-specific
    if not is_linux():
        raise NotImplementedError(
            "AF_PACKET is only available on Linux. "
            "Use BPF on BSD/macOS or WinPcap on Windows."
        )
    
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    if interface:
        sock.bind((interface, socket.ntohs(0x0003)))
    return sock


# ==================== THREAD-SAFE SOCKET WRAPPER ====================
class ThreadSafeSocket:
    """
    Thread-safe wrapper for socket operations.
    
    SECURITY: Ensures socket send operations are synchronized
    to prevent race conditions in multi-threaded environments.
    """
    
    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._lock = threading.Lock()
    
    def sendto(self, data: bytes, address: tuple) -> int:
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
    
    def fileno(self) -> int:
        """Get file descriptor (thread-safe)."""
        with self._lock:
            return self._sock.fileno()
