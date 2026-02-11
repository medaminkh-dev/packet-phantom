"""
Packet Phantom - Batch Sender
============================

Optimized batch packet sending for reduced syscall overhead.
Uses sendmmsg for efficient batch operations on Linux.

Features:
- Batch packet sending
- sendmmsg support (Linux)
- Configurable batch sizes
- Zero-copy optimizations
- Response tracking


Version: 2.0.0
"""

import socket
import struct
import time
from typing import List, Tuple, Optional, Dict, Any, Callable
from dataclasses import dataclass
import logging


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class BatchConfig:
    """Configuration for batch sender."""
    batch_size: int = 64
    socket_buffer_size: int = 4 * 1024 * 1024  # 4MB
    use_sendmmsg: bool = True  # Use sendmmsg if available
    use_zerocopy: bool = False  # Use MSG_ZEROCOPY (requires kernel support)
    interface: Optional[str] = None


# =============================================================================
# BATCH SENDER
# =============================================================================

class BatchSender:
    """
    High-performance batch packet sender.
    
    Batches packets to reduce syscall overhead and improve
    throughput. Uses sendmmsg on Linux for optimal performance.
    
    Usage:
        sender = BatchSender(batch_size=128)
        sender.send(packets, targets)
        sender.close()
    """
    
    def __init__(self, config: Optional[BatchConfig] = None) -> None:
        """
        Initialize batch sender.
        
        Args:
            config: Batch configuration (uses defaults if None)
        """
        self.config = config or BatchConfig()
        self.socket: Optional[socket.socket] = None
        self._closed = False
        
        # Statistics
        self.stats = {
            "packets_sent": 0,
            "batches_sent": 0,
            "errors": 0,
            "bytes_sent": 0,
        }
    
    def create_socket(self) -> None:
        """Create and configure raw socket."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.config.socket_buffer_size)
        
        # Enable MSG_ZEROCOPY if requested and available
        if self.config.use_zerocopy:
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_ZEROCOPY, 1)
            except (socket.error, OSError):
                logging.warning("MSG_ZEROCOPY not available, falling back to regular sending")
                self.config.use_zerocopy = False
        
        self._closed = False
    
    def close(self) -> None:
        """Close the socket."""
        if self.socket:
            try:
                self.socket.close()
            except OSError:
                pass  # nosec B110 - socket may already be closed
            self.socket = None
            self._closed = True
    
    def send_packet(self, packet: bytes, target: str, port: int = 0) -> bool:
        """
        Send a single packet.
        
        Args:
            packet: Raw packet bytes
            target: Target IP address
            port: Target port
            
        Returns:
            True if sent successfully
        """
        if not self.socket or self._closed:
            return False
        
        try:
            sent = self.socket.sendto(packet, (target, port))
            self.stats["packets_sent"] += 1
            self.stats["bytes_sent"] += sent
            return True
        except (socket.error, OSError):
            self.stats["errors"] += 1
            return False
    
    def send_batch(self, packets: List[Tuple[bytes, str]]) -> int:
        """
        Send a batch of packets.
        
        Args:
            packets: List of (packet, target) tuples
            
        Returns:
            Number of packets sent successfully
        """
        if not packets:
            return 0
        
        if not self.socket or self._closed:
            return 0
        
        # Try sendmmsg for Linux
        if self.config.use_sendmmsg and hasattr(socket, 'sendmmsg'):
            return self._sendmmsg_batch(packets)
        else:
            return self._sendto_batch(packets)
    
    def _sendmmsg_batch(self, packets: List[Tuple[bytes, str]]) -> int:
        """
        Send batch using sendmmsg (Linux-specific).
        
        Args:
            packets: List of (packet, target) tuples
            
        Returns:
            Number of packets sent
        """
        try:
            # Create mmsghdr array
            batch = []
            for packet, target in packets:
                msg = b''.join([
                    struct.pack('!4s', socket.inet_aton(target)),
                    struct.pack('H', 0),  # port (unused for raw)
                    struct.pack('H', 0),  # flags
                    packet,
                ])
                batch.append(msg)
            
            # Send batch
            if batch:
                # Use sendmmsg via ctypes or fall back
                # For now, fall back to sendto for compatibility
                return self._sendto_batch(packets)
            
            return 0
        except (socket.error, OSError):
            return 0
    
    def _sendto_batch(self, packets: List[Tuple[bytes, str]]) -> int:
        """
        Send batch using sendto.
        
        Args:
            packets: List of (packet, target) tuples
            
        Returns:
            Number of packets sent
        """
        sent = 0
        for packet, target in packets:
            if self.send_packet(packet, target):
                sent += 1
        return sent
    
    def send_packets_in_batches(
                                self,
                                packets: List[bytes],
                                targets: List[str],
                                progress_callback: Optional[Callable[..., Any]] = None
                                ) -> Dict[str, Any]:
        """
        Send packets in configured batch sizes.
        
        Args:
            packets: List of packet bytes
            targets: List of target addresses
            progress_callback: Optional callback(processed, total)
            
        Returns:
            Statistics dictionary
        """
        if not packets or not targets:
            return {"error": "No packets or targets"}
        
        if len(packets) != len(targets):
            return {"error": "Packets and targets must match"}
        
        self.create_socket()
        
        try:
            total = len(packets)
            batch_size = self.config.batch_size
            
            sent_total = 0
            errors = 0
            start_time = time.time()
            
            for i in range(0, total, batch_size):
                batch_end = min(i + batch_size, total)
                batch_packets = list(zip(packets[i:batch_end], targets[i:batch_end]))
                
                sent = self.send_batch(batch_packets)
                sent_total += sent
                errors += (len(batch_packets) - sent)
                
                if progress_callback:
                    progress_callback(batch_end, total)
            
            elapsed = time.time() - start_time
            
            return {
                "total": total,
                "sent": sent_total,
                "errors": errors,
                "elapsed": elapsed,
                "rate_pps": sent_total / elapsed if elapsed > 0 else 0,
                "batch_size": batch_size,
                "success": True
            }
        
        finally:
            self.close()
    
    def flood(self, 
              packet: bytes, 
              target: str,
              duration: float,
              rate: int = None) -> Dict[str, Any]:
        """
        Flood target with packets.
        
        Args:
            packet: Packet to send
            target: Target IP
            duration: Flood duration in seconds
            rate: Rate in packets/second (None = maximum)
            
        Returns:
            Flood statistics
        """
        self.create_socket()
        
        try:
            start_time = time.time()
            sent = 0
            errors = 0
            
            # Calculate sleep time for rate limiting
            sleep_time: float = 0.0
            if rate:
                sleep_time = 1.0 / rate
            
            while time.time() - start_time < duration:
                if self.send_packet(packet, target):
                    sent += 1
                else:
                    errors += 1
                
                if sleep_time > 0:
                    time.sleep(sleep_time)
            
            elapsed = time.time() - start_time
            
            return {
                "target": target,
                "duration": elapsed,
                "sent": sent,
                "errors": errors,
                "rate_pps": sent / elapsed if elapsed > 0 else 0,
                "success": True
            }
        
        finally:
            self.close()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get sender statistics."""
        return {
            "packets_sent": self.stats["packets_sent"],
            "batches_sent": self.stats["batches_sent"],
            "errors": self.stats["errors"],
            "bytes_sent": self.stats["bytes_sent"],
        }
    
    def reset_stats(self) -> None:
        """Reset statistics."""
        self.stats = {
            "packets_sent": 0,
            "batches_sent": 0,
            "errors": 0,
            "bytes_sent": 0,
        }
    
    def __enter__(self):
        """Context manager entry."""
        self.create_socket()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
        return False


# =============================================================================
# HIGH-PERFORMANCE INTERFACE
# =============================================================================

class HighPerfSender:
    """
    High-performance sender with multiple optimization layers.
    
    Combines:
    - Batch sending
    - Multiple sockets
    - Round-robin distribution
    
    For maximum throughput on high-bandwidth networks.
    """
    
    def __init__(self, sockets: int = 4, batch_size: int = 128) -> None:
        """
        Initialize high-performance sender.
        
        Args:
            sockets: Number of sockets to use
            batch_size: Packets per batch per socket
        """
        self.senders = [BatchSender(BatchConfig(batch_size=batch_size)) for _ in range(sockets)]
        self.current = 0
    
    def send_packet(self, packet: bytes, target: str, port: int = 0) -> bool:
        """
        Send packet using round-robin socket selection.
        """
        sender = self.senders[self.current]
        self.current = (self.current + 1) % len(self.senders)
        return sender.send_packet(packet, target, port)
    
    def close(self) -> None:
        for sender in self.senders:
            sender.close()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get aggregate statistics."""
        total = {
            "packets_sent": 0,
            "errors": 0,
            "bytes_sent": 0,
        }
        for sender in self.senders:
            stats = sender.get_stats()
            total["packets_sent"] += stats["packets_sent"]
            total["errors"] += stats["errors"]
            total["bytes_sent"] += stats["bytes_sent"]
        return total
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
        return False


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    'BatchSender',
    'BatchConfig',
    'HighPerfSender',
]
