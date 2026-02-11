"""
Packet Phantom - Prometheus Metrics
==================================

Prometheus metrics integration for monitoring and observability.

Metrics:
- packet_phantom_packets_sent_total
- packet_phantom_packets_per_second
- packet_phantom_scan_duration_seconds
- packet_phantom_active_scans
- packet_phantom_errors_total

Author: Packet Phantom Team
Version: 2.0.0
"""

import time
from typing import Dict, List, Optional, Any
import threading


# =============================================================================
# METRICS COLLECTOR
# =============================================================================

class MetricsCollector:
    """
    Collects and exports Prometheus metrics.
    
    Usage:
        metrics = MetricsCollector()
        metrics.packets_sent(100)
        metrics.start_http_server(9090)
    """
    
    def __init__(self, namespace: str = "packet_phantom"):
        """
        Initialize metrics collector.
        
        Args:
            namespace: Prometheus namespace for metrics
        """
        self.namespace = namespace
        
        # Counters
        self._packets_sent = 0
        self._packets_received = 0
        self._scans_started = 0
        self._scans_completed = 0
        self._errors = 0
        
        # Gauges
        self._active_scans = 0
        self._active_connections = 0
        
        # Histograms
        self._scan_durations: List[float] = []
        
        # Locks for thread safety
        self._lock = threading.Lock()
        
        # Start time for uptime
        self._start_time = time.time()
    
    # =========================================================================
    # COUNTER METRICS
    # =========================================================================
    
    def packets_sent(self, count: int = 1) -> None:
        """Increment packets sent counter."""
        with self._lock:
            self._packets_sent += count
    
    def packets_received(self, count: int = 1) -> None:
        """Increment packets received counter."""
        with self._lock:
            self._packets_received += count
    
    def scan_started(self) -> None:
        """Increment scans started counter."""
        with self._lock:
            self._scans_started += 1
            self._active_scans += 1
    
    def scan_completed(self, duration: float) -> None:
        """Record a completed scan."""
        with self._lock:
            self._scans_completed += 1
            self._active_scans -= 1
            self._scan_durations.append(duration)
    
    def error(self, count: int = 1) -> None:
        """Increment error counter."""
        with self._lock:
            self._errors += count
    
    def connection_opened(self) -> None:
        """Increment active connections."""
        with self._lock:
            self._active_connections += 1
    
    def connection_closed(self) -> None:
        """Decrement active connections."""
        with self._lock:
            self._active_connections -= 1
    
    # =========================================================================
    # GETTER METHODS
    # =========================================================================
    
    def get_counters(self) -> Dict[str, int]:
        """Get current counter values."""
        with self._lock:
            return {
                f"{self.namespace}_packets_sent_total": self._packets_sent,
                f"{self.namespace}_packets_received_total": self._packets_received,
                f"{self.namespace}_scans_started_total": self._scans_started,
                f"{self.namespace}_scans_completed_total": self._scans_completed,
                f"{self.namespace}_errors_total": self._errors,
            }
    
    def get_gauges(self) -> Dict[str, int]:
        """Get current gauge values."""
        with self._lock:
            return {
                f"{self.namespace}_active_scans": self._active_scans,
                f"{self.namespace}_active_connections": self._active_connections,
            }
    
    def get_histograms(self) -> Dict[str, Dict[str, float]]:
        """Get histogram statistics."""
        with self._lock:
            if not self._scan_durations:
                return {}
            
            durations = sorted(self._scan_durations)
            n = len(durations)
            
            return {
                f"{self.namespace}_scan_duration_seconds": {
                    "count": n,
                    "sum": sum(durations),
                    "min": min(durations),
                    "max": max(durations),
                    "avg": sum(durations) / n,
                    "p50": durations[int(n * 0.50)],
                    "p95": durations[int(n * 0.95)],
                    "p99": durations[int(n * 0.99)],
                }
            }
    
    # =========================================================================
    # PROMETHUS FORMAT EXPORT
    # =========================================================================
    
    def export_prometheus(self) -> str:
        """Export metrics in Prometheus format."""
        lines = []
        
        # Help strings
        lines.append(f"# HELP {self.namespace}_packets_sent_total Total packets sent")
        lines.append(f"# TYPE {self.namespace}_packets_sent_total counter")
        lines.append(f"{self.namespace}_packets_sent_total {self._packets_sent}")
        
        lines.append(f"# HELP {self.namespace}_packets_received_total Total packets received")
        lines.append(f"# TYPE {self.namespace}_packets_received_total counter")
        lines.append(f"{self.namespace}_packets_received_total {self._packets_received}")
        
        lines.append(f"# HELP {self.namespace}_scans_started_total Total scans started")
        lines.append(f"# TYPE {self.namespace}_scans_started_total counter")
        lines.append(f"{self.namespace}_scans_started_total {self._scans_started}")
        
        lines.append(f"# HELP {self.namespace}_scans_completed_total Total scans completed")
        lines.append(f"# TYPE {self.namespace}_scans_completed_total counter")
        lines.append(f"{self.namespace}_scans_completed_total {self._scans_completed}")
        
        lines.append(f"# HELP {self.namespace}_errors_total Total errors")
        lines.append(f"# TYPE {self.namespace}_errors_total counter")
        lines.append(f"{self.namespace}_errors_total {self._errors}")
        
        lines.append(f"# HELP {self.namespace}_active_scans Currently active scans")
        lines.append(f"# TYPE {self.namespace}_active_scans gauge")
        lines.append(f"{self.namespace}_active_scans {self._active_scans}")
        
        lines.append(f"# HELP {self.namespace}_active_connections Currently active connections")
        lines.append(f"# TYPE {self.namespace}_active_connections gauge")
        lines.append(f"{self.namespace}_active_connections {self._active_connections}")
        
        # Uptime
        uptime = time.time() - self._start_time
        lines.append(f"# HELP {self.namespace}_uptime_seconds Uptime in seconds")
        lines.append(f"# TYPE {self.namespace}_uptime_seconds gauge")
        lines.append(f"{self.namespace}_uptime_seconds {uptime}")
        
        return '\n'.join(lines)
    
    def start_http_server(self, port: int = 9090) -> None:
        """
        Start HTTP server for Prometheus scraping.
        
        Args:
            port: Port to listen on
        """
        try:
            from http.server import HTTPServer, BaseHTTPRequestHandler
            import threading
            
            class MetricsHandler(BaseHTTPRequestHandler):
                def do_GET(self):
                    if self.path == '/metrics':
                        self.send_response(200)
                        self.send_header('Content-type', 'text/plain')
                        self.end_headers()
                        self.wfile.write(
                            self.export_prometheus().encode('utf-8')
                        )
                    else:
                        self.send_response(404)
                        self.end_headers()
                
                def log_message(self, format, *args):
                    pass  # Suppress logging
            
            server = HTTPServer(('0.0.0.0', port), MetricsHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            
            print(f"Metrics server started on port {port}")
        
        except ImportError:
            print("Warning: HTTP server not available")


# =============================================================================
# RATE CALCULATOR
# =============================================================================

class RateCalculator:
    """Calculate and track packet rates."""
    
    def __init__(self, window_seconds: float = 5.0):
        """
        Initialize rate calculator.
        
        Args:
            window_seconds: Time window for rate calculation
        """
        self.window_seconds = window_seconds
        self._timestamps: list = []
        self._lock = threading.Lock()
    
    def record(self):
        """Record a packet sent event."""
        with self._lock:
            now = time.time()
            self._timestamps.append(now)
            # Remove old timestamps
            self._timestamps = [t for t in self._timestamps 
                               if now - t <= self.window_seconds]
    
    def get_rate(self) -> float:
        """Get current rate in events per second."""
        with self._lock:
            if len(self._timestamps) < 2:
                return 0.0
            
            now = time.time()
            window = [t for t in self._timestamps if now - t <= self.window_seconds]
            
            if len(window) < 2:
                return 0.0
            
            duration = window[-1] - window[0]
            if duration <= 0:
                return 0.0
            
            return len(window) / duration


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    'MetricsCollector',
    'RateCalculator',
]
