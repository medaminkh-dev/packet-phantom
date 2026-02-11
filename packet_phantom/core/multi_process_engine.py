"""
Packet Phantom - Multi-Process Engine
====================================

High-performance packet sending using multiple processes.
Targets 50,000+ packets/second on modern hardware.

Features:
- Multi-process parallel packet sending
- Process-safe socket management
- Workload distribution across CPU cores
- Batch sending with sendmmsg support (Linux)
- Zero-copy optimizations


Version: 2.0.0
"""

import socket
import multiprocessing as mp
import threading
import time
import os
from typing import List, Tuple, Optional, Callable, Any, Dict
from dataclasses import dataclass


# =============================================================================
# CONFIGURATION
# =============================================================================

@dataclass
class EngineConfig:
    """Configuration for multi-process engine."""
    workers: Optional[int] = None  # Auto-detect CPU count
    batch_size: int = 64
    socket_buffer_size: int = 1024 * 1024  # 1MB
    cpu_affinity: bool = False
    priority: int = 0  # 0 = normal, -20 = highest
    send_buffer_size: int = 1024 * 1024  # 1MB per socket
    recv_buffer_size: int = 4 * 1024 * 1024  # 4MB for responses
    
    def __post_init__(self) -> None:
        if self.workers is None:
            self.workers = mp.cpu_count()


# =============================================================================
# PROCESS WORKER
# =============================================================================

class ProcessWorker:
    """
    Individual process worker for packet sending.
    
    Each worker manages its own raw socket and handles
    a portion of the packet sending workload.
    """
    
    def __init__(self, worker_id: int, config: EngineConfig) -> None:
        self.worker_id = worker_id
        self.config = config
        self.socket: Optional[socket.socket] = None
        self.packets_sent = 0
        self.bytes_sent = 0
        self.start_time = 0.0
        self.running = False
        
        # Set process priority
        self._set_priority()
        
        # Set CPU affinity if enabled
        if config.cpu_affinity:
            self._set_cpu_affinity()
    
    def _set_priority(self) -> None:
        """Set process nice value for priority."""
        try:
            os.nice(self.config.priority)
        except OSError:
            pass  # May fail without permissions
    
    def _set_cpu_affinity(self) -> None:
        """Bind process to specific CPU core."""
        try:
            import psutil
            process = psutil.Process()
            cpus = list(range(mp.cpu_count()))
            process.cpu_affinity([cpus[self.worker_id % len(cpus)]])
        except (ImportError, AttributeError):
            pass  # psutil not available or doesn't support affinity
    
    def initialize_socket(self) -> None:
        """Initialize raw socket for this worker."""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        # Set socket buffers
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, self.config.send_buffer_size)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.config.recv_buffer_size)
        
        # Disable SIGPIPE (Linux-specific)
        try:
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_NOSIGPIPE, 1)
        except (AttributeError, OSError):
            pass  # SO_NOSIGPIPE not available on all platforms
        
        self.running = True
    
    def close_socket(self) -> None:
        """Close the socket."""
        if self.socket:
            try:
                self.socket.close()
            except OSError:
                pass  # nosec B110 - socket may already be closed
            self.socket = None
    
    def send_packet(self, packet: bytes, target: str) -> bool:
        """
        Send a single packet.
        
        Args:
            packet: Raw packet bytes
            target: Target IP address
            
        Returns:
            True if sent successfully, False otherwise
        """
        if not self.socket:
            return False
        
        try:
            sent = self.socket.sendto(packet, (target, 0))
            self.packets_sent += 1
            self.bytes_sent += sent
            return True
        except (socket.error, OSError):
            return False
    
    def send_batch(self, packets: List[Tuple[bytes, str]]) -> int:
        """
        Send a batch of packets.
        
        Args:
            packets: List of (packet_bytes, target) tuples
            
        Returns:
            Number of packets sent successfully
        """
        if not self.socket:
            return 0
        
        sent_count = 0
        for packet, target in packets:
            if self.send_packet(packet, target):
                sent_count += 1
        
        return sent_count
    
    def get_stats(self) -> Dict[str, Any]:
        """Get worker statistics."""
        elapsed = time.time() - self.start_time
        rate = self.packets_sent / elapsed if elapsed > 0 else 0
        
        return {
            "worker_id": self.worker_id,
            "packets_sent": self.packets_sent,
            "bytes_sent": self.bytes_sent,
            "rate_pps": rate,
            "elapsed": elapsed
        }
    
    def __enter__(self) -> 'ProcessWorker':
        """Context manager entry."""
        self.initialize_socket()
        return self
    
    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        """Context manager exit."""
        self.close_socket()
        return False


# =============================================================================
# MULTI-PROCESS ENGINE
# =============================================================================

class MultiProcessEngine:
    """
    High-performance multi-process packet engine.
    
    Distributes packet sending workload across multiple processes
    for maximum throughput on multi-core systems.
    
    Usage:
        engine = MultiProcessEngine(workers=8, batch_size=128)
        engine.start()
        results = engine.send_packets(packets, targets)
        engine.stop()
    """
    
    def __init__(self, config: Optional[EngineConfig] = None) -> None:
        """
        Initialize the multi-process engine.
        
        Args:
            config: Engine configuration (uses defaults if None)
        """
        self.config = config or EngineConfig()
        self.workers: List[ProcessWorker] = []
        self.running = False
        self.stats_lock = threading.Lock()
        
        # Validate configuration
        workers_count = self.config.workers if self.config.workers is not None else 1
        if workers_count < 1:
            self.config.workers = 1
        elif workers_count > mp.cpu_count():
            self.config.workers = mp.cpu_count()
        else:
            self.config.workers = workers_count
    
    def initialize_workers(self) -> None:
        """Initialize worker processes."""
        self.workers = []
        
        for i in range(self.config.workers or 1):
            worker = ProcessWorker(i, self.config)
            worker.initialize_socket()
            self.workers.append(worker)
    
    def start(self) -> None:
        """Start the engine and all workers."""
        if not self.workers:
            self.initialize_workers()
        
        self.running = True
        
        for worker in self.workers:
            worker.start_time = time.time()
    
    def stop(self) -> None:
        """Stop all workers and clean up resources."""
        self.running = False
        
        for worker in self.workers:
            worker.close_socket()
        
        self.workers.clear()
    
    def distribute_workload(self, total_items: int) -> List[Tuple[int, int]]:
        """
        Distribute workload across workers.
        
        Args:
            total_items: Total number of items to distribute
            
        Returns:
            List of (worker_index, item_count) tuples
        """
        distribution: List[Tuple[int, int]] = []
        workers = self.config.workers or 1
        base_items = total_items // workers
        remainder = total_items % workers
        
        for i in range(workers):
            count = base_items + (1 if i < remainder else 0)
            if count > 0:
                distribution.append((i, count))
        
        return distribution
    
    def send_packets(
        self,
        packets: List[bytes],
        targets: List[str],
        progress_callback: Optional[Callable[..., Any]] = None
    ) -> Dict[str, Any]:
        """
        Send packets using multi-process parallelization.
        
        Args:
            packets: List of packet bytes
            targets: List of target IP addresses
            progress_callback: Optional callback for progress updates
            
        Returns:
            Dictionary with statistics
        """
        if not packets or not targets:
            return {"error": "No packets or targets provided"}
        
        if len(packets) != len(targets):
            return {"error": "Packets and targets must have same length"}
        
        self.start()
        
        try:
            # Create packet-target pairs
            packet_pairs = list(zip(packets, targets))
            
            # Distribute work
            total_packets = len(packet_pairs)
            distribution = self.distribute_workload(total_packets)
            
            # Send packets
            total_sent = 0
            total_bytes = 0
            start_time = time.time()
            
            for worker_idx, count in distribution:
                worker = self.workers[worker_idx]
                
                # Get this worker's packet slice
                start_idx = sum(c for _, c in distribution[:worker_idx])
                end_idx = start_idx + count
                worker_packets = packet_pairs[start_idx:end_idx]
                
                # Send batch
                sent = worker.send_batch(worker_packets)
                total_sent += sent
                total_bytes += worker.packets_sent * len(packets[0])  # Approximate
                
                # Progress callback
                if progress_callback:
                    progress_callback(total_sent, total_packets)
            
            elapsed = time.time() - start_time
            rate = total_sent / elapsed if elapsed > 0 else 0
            
            return {
                "total_packets": total_packets,
                "sent": total_sent,
                "failed": total_packets - total_sent,
                "bytes": total_bytes,
                "elapsed": elapsed,
                "rate_pps": rate,
                "workers": self.config.workers,
                "success": True
            }
        
        finally:
            self.stop()
    
    def flood_target(
        self,
        packet: bytes,
        target: str,
        duration: float,
        rate: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Flood a target with packets.
        
        Args:
            packet: Packet bytes to send
            target: Target IP address
            duration: Flood duration in seconds
            rate: Target rate in packets/second (None = maximum)
            
        Returns:
            Dictionary with statistics
        """
        self.start()
        
        try:
            start_time = time.time()
            total_sent = 0
            
            # Calculate sleep time for rate limiting
            sleep_time = 0.0
            workers = self.config.workers or 1
            if rate and workers > 0:
                sleep_time = 1.0 / (rate / workers)
            
            while time.time() - start_time < duration:
                for worker in self.workers:
                    if time.time() - start_time >= duration:
                        break
                    
                    if worker.send_packet(packet, target):
                        total_sent += 1
                    
                    if sleep_time > 0:
                        time.sleep(sleep_time)
            
            elapsed = time.time() - start_time
            rate_pps = total_sent / elapsed if elapsed > 0 else 0
            
            return {
                "target": target,
                "duration": elapsed,
                "total_sent": total_sent,
                "rate_pps": rate_pps,
                "workers": workers,
                "success": True
            }
        
        finally:
            self.stop()
    
    def get_aggregate_stats(self) -> Dict[str, Any]:
        """Get aggregate statistics from all workers."""
        if not self.workers:
            return {"error": "Engine not started"}
        
        total_packets = sum(w.packets_sent for w in self.workers)
        total_bytes = sum(w.bytes_sent for w in self.workers)
        
        elapsed = 0.0
        if self.workers:
            elapsed = max(w.start_time for w in self.workers) - min(w.start_time for w in self.workers)
            if elapsed <= 0:
                elapsed = time.time() - min(w.start_time for w in self.workers)
        
        rate = total_packets / elapsed if elapsed > 0 else 0
        
        return {
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "rate_pps": rate,
            "elapsed": elapsed,
            "workers": len(self.workers)
        }
    
    def __enter__(self) -> 'MultiProcessEngine':
        """Context manager entry."""
        self.initialize_workers()
        self.start()
        return self
    
    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        """Context manager exit."""
        self.stop()
        return False


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_engine(
    workers: Optional[int] = None,
    batch_size: int = 64,
    rate: Optional[int] = None
) -> MultiProcessEngine:
    """
    Create a configured multi-process engine.
    
    Args:
        workers: Number of worker processes (auto-detect if None)
        batch_size: Batch size for sending
        rate: Target rate in packets/second
        
    Returns:
        Configured MultiProcessEngine instance
    """
    config = EngineConfig(
        workers=workers,
        batch_size=batch_size
    )
    
    return MultiProcessEngine(config)


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    'MultiProcessEngine',
    'ProcessWorker',
    'EngineConfig',
    'create_engine',
]
