"""
Packet Phantom - Professional Output Manager
===========================================

Multiple output format support for professional network testing.
Supports JSON, CSV, HTML, PCAP, and SIEM integration.

Features:
- JSON/CSV export for automation
- HTML report generation
- PCAP packet capture
- Prometheus metrics
- SIEM integration (ElasticSearch, Splunk)

Author: Packet Phantom Team
Version: 2.0.0
"""

import json
import csv
import os
import threading
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
import logging


# =============================================================================
# OUTPUT FORMATS
# =============================================================================

class OutputFormat(Enum):
    """Supported output formats."""
    CONSOLE = "console"
    JSON = "json"
    CSV = "csv"
    HTML = "html"
    PCAP = "pcap"
    SIEM = "siem"


# =============================================================================
# OUTPUT CONFIGURATION
# =============================================================================

@dataclass
class OutputConfig:
    """Configuration for output manager."""
    format: OutputFormat = OutputFormat.CONSOLE
    output_file: Optional[str] = None
    append: bool = False
    pretty_print: bool = True
    timestamp_format: str = "%Y-%m-%dT%H:%M:%S.%fZ"
    capture_packets: bool = False
    capture_dir: str = "/tmp/packet_phantom"


# =============================================================================
# RESULT DATA CLASS
# =============================================================================

@dataclass
class ScanResult:
    """Represents a single scan result."""
    target: str
    port: int
    status: str  # open, closed, filtered, error
    response_time: Optional[float] = None
    banner: Optional[str] = None
    timestamp: Optional[str] = None
    ttl: Optional[int] = None
    # NEW: Service version and OS detection fields
    service_version: Optional[str] = None  # service name + version (e.g., "ssh OpenSSH_8.9p1")
    os_guess: Optional[str] = None         # OS fingerprint result (e.g., "Linux 5.4 - 5.15")
    os_confidence: Optional[int] = None    # OS confidence score (0-100)
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat() + "Z"
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class FloodResult:
    """Represents flood statistics."""
    target: str
    duration: float
    packets_sent: int
    packets_per_second: float
    bytes_sent: int
    errors: int
    timestamp: Optional[str] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat() + "Z"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


# =============================================================================
# OUTPUT MANAGER
# =============================================================================

class OutputManager:
    """
    Professional output manager with multiple format support.
    
    Usage:
        output = OutputManager(format=OutputFormat.JSON, output_file="results.json")
        output.write_result(result)
        output.close()
    """
    
    def __init__(self, config: Optional[OutputConfig] = None) -> None:
        """
        Initialize output manager.
        
        Args:
            config: Output configuration
        """
        self.config = config or OutputConfig()
        self.results: List[Dict[str, Any]] = []
        self.packet_writer = None
        self.lock = threading.Lock()
        
        # Initialize file handles
        self._init_output()
    
    def _init_output(self) -> None:
        """Initialize output based on format."""
        if self.config.output_file:
            mode = 'a' if self.config.append else 'w'
            
            if self.config.format == OutputFormat.JSON:
                self._init_json_output(mode)
            elif self.config.format == OutputFormat.CSV:
                self._init_csv_output(mode)
            elif self.config.format == OutputFormat.HTML:
                self._init_html_output(mode)
        
        # Initialize packet capture
        if self.config.capture_packets:
            self._init_pcap_writer()
    
    def _init_json_output(self, mode: str) -> None:
        """Initialize JSON output file."""
        self.json_file = open(self.config.output_file, mode, encoding='utf-8')
        if mode == 'w':
            self.json_file.write('[\n')
    
    def _init_csv_output(self, mode: str) -> None:
        """Initialize CSV output file."""
        self.csv_file = open(self.config.output_file, mode, newline='', encoding='utf-8')
        self.csv_writer = None
    
    def _init_html_output(self, mode: str) -> None:
        """Initialize HTML output file."""
        self.html_file = open(self.config.output_file, mode, encoding='utf-8')
        if mode == 'w':
            self.html_file.write(self._get_html_header())
    
    def _init_pcap_writer(self) -> None:
        """Initialize PCAP writer for packet capture."""
        try:
            from packet_phantom.output.pcap_writer import PCAPWriter
            
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = os.path.join(
                self.config.capture_dir, 
                f"packet_phantom_{timestamp}.pcap"
            )
            self.packet_writer = PCAPWriter(filename)
        except ImportError:
            logging.warning("PCAP writer not available")
    
    def write_result(self, result: ScanResult) -> None:
        """
        Write a scan result to output.
        
        Args:
            result: ScanResult to write
        """
        with self.lock:
            result_dict = result.to_dict()
            self.results.append(result_dict)
            
            # Write to format-specific output
            if self.config.format == OutputFormat.CONSOLE:
                self._write_console(result)
            elif self.config.format == OutputFormat.JSON:
                self._write_json(result_dict)
            elif self.config.format == OutputFormat.CSV:
                self._write_csv(result_dict)
            elif self.config.format == OutputFormat.HTML:
                self._write_html(result_dict)
            
            # Capture packet if enabled
            if self.config.capture_packets and hasattr(result, 'packet'):
                self._capture_packet(result.packet)
    
    def write_flood_result(self, result: FloodResult) -> None:
        """Write flood result to output."""
        with self.lock:
            result_dict = result.to_dict()
            
            if self.config.format == OutputFormat.CONSOLE:
                self._write_flood_console(result)
            elif self.config.format == OutputFormat.JSON:
                self._write_json(result_dict)
    
    def write_results_bulk(self, results: List[ScanResult]) -> None:
        """Write multiple results efficiently."""
        for result in results:
            self.write_result(result)
    
    def _write_console(self, result: ScanResult) -> None:
        """
        Write result to console with service version and OS support.
        
        Output format:
            [+] target:port status service_version
            OS: os_guess (os_confidence%)
        """
        status_colors = {
            'open': '\033[92m',   # Green
            'closed': '\033[91m',  # Red
            'filtered': '\033[93m',  # Yellow
            'error': '\033[90m',   # Gray
        }
        
        color = status_colors.get(result.status, '\033[0m')
        status_str = f"{color}{result.status.upper()}\033[0m"
        
        # Format port line with service version
        if result.service_version:
            line = f"[+] {result.target}:{result.port} {status_str} {result.service_version}"
        else:
            line = f"[+] {result.target}:{result.port} {status_str}"
        
        if result.response_time:
            line += f" ({result.response_time:.3f}s)"
        
        print(line)
        
        # At end of host, show OS guess
        if result.os_guess:
            conf_str = f"{result.os_confidence}%" if result.os_confidence else "?"
            print(f"OS: {result.os_guess} ({conf_str} confidence)")
    
    def _write_json(self, result: Dict[str, Any]) -> None:
        """
        Write result to JSON file with new fields.
        
        Includes: service_version, os_guess, os_confidence
        """
        if self.config.pretty_print:
            json_str = json.dumps(result, indent=2)
        else:
            json_str = json.dumps(result)
        
        self.json_file.write(json_str + ',\n')
    
    def _write_csv(self, result: Dict[str, Any]) -> None:
        """Write result to CSV file."""
        if self.csv_writer is None:
            fieldnames = list(result.keys())
            self.csv_writer = csv.DictWriter(self.csv_file, fieldnames=fieldnames)
            if self.config.append and os.path.exists(self.config.output_file):
                pass  # Append to existing
            else:
                self.csv_writer.writeheader()
        
        self.csv_writer.writerow(result)
    
    def _write_html(self, result: Dict[str, Any]) -> None:
        """Write result to HTML table."""
        status_class = {
            'open': 'status-open',
            'closed': 'status-closed',
            'filtered': 'status-filtered',
            'error': 'status-error',
        }.get(result.get('status', ''), '')
        
        row = f"""
        <tr class="{status_class}">
            <td>{result.get('target', '')}</td>
            <td>{result.get('port', '')}</td>
            <td class="status">{result.get('status', '')}</td>
            <td>{result.get('response_time', '-')}</td>
            <td>{result.get('service_version', '-')}</td>
            <td>{result.get('os_guess', '-')}</td>
            <td>{result.get('os_confidence', '-')}</td>
            <td>{result.get('timestamp', '')}</td>
        </tr>
        """
        self.html_file.write(row)
    
    def _write_flood_console(self, result: FloodResult) -> None:
        """Write flood result to console."""
        print(f"\n[✓] Flood complete: {result.target}")
        print(f"    Duration:     {result.duration:.2f}s")
        print(f"    Packets sent: {result.packets_sent:,}")
        print(f"    Rate:         {result.packets_per_second:,.1f} pkt/s")
        print(f"    Errors:       {result.errors:,}")
    
    def _capture_packet(self, packet: bytes) -> None:
        """Capture packet to PCAP."""
        if self.packet_writer:
            try:
                self.packet_writer.write_packet(packet)
            except Exception:
                pass
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of all results."""
        total = len(self.results)
        open_count = sum(1 for r in self.results if r.get('status') == 'open')
        closed_count = sum(1 for r in self.results if r.get('status') == 'closed')
        filtered_count = sum(1 for r in self.results if r.get('status') == 'filtered')
        
        return {
            "total": total,
            "open": open_count,
            "closed": closed_count,
            "filtered": filtered_count,
            "success_rate": (open_count / total * 100) if total > 0 else 0
        }
    
    def export_json(self, filename: Optional[str] = None, pretty: bool = True) -> str:
        """
        Export all results to JSON.
        
        Args:
            filename: Output filename (uses config if None)
            pretty: Pretty print formatting
            
        Returns:
            JSON string
        """
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2 if pretty else None)
            return filename
        
        return json.dumps(self.results, indent=2 if pretty else None)
    
    def export_csv(self, filename: Optional[str] = None) -> str:
        """
        Export all results to CSV.
        
        Args:
            filename: Output filename (uses config if None)
            
        Returns:
            Filename
        """
        if not filename:
            filename = self.config.output_file
        
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            if self.results:
                writer = csv.DictWriter(f, fieldnames=self.results[0].keys())
                writer.writeheader()
                writer.writerows(self.results)
        
        return filename
    
    def generate_html_report(self, filename: str = None, title: str = "Scan Report") -> str:
        """
        Generate HTML report.
        
        Args:
            filename: Output filename
            title: Report title
            
        Returns:
            Filename
        """
        if not filename:
            filename = self.config.output_file
        
        summary = self.get_summary()
        
        html = self._get_html_header(title)
        html += f"""
        <div class="summary">
            <h2>Summary</h2>
            <ul>
                <li>Total: {summary['total']}</li>
                <li class="open">Open: {summary['open']}</li>
                <li class="closed">Closed: {summary['closed']}</li>
                <li class="filtered">Filtered: {summary['filtered']}</li>
            </ul>
        </div>
        <h2>Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Target</th>
                    <th>Port</th>
                    <th>Status</th>
                    <th>Response Time</th>
                    <th>Service Version</th>
                    <th>OS Guess</th>
                    <th>OS Confidence</th>
                    <th>Timestamp</th>
                </tr>
            </thead>
            <tbody>
        """
        
        for result in self.results:
            status_class = result.get('status', '')
            html += f"""
            <tr class="{status_class}">
                <td>{result.get('target', '')}</td>
                <td>{result.get('port', '')}</td>
                <td class="status">{result.get('status', '')}</td>
                <td>{result.get('response_time', '-')}</td>
                <td>{result.get('service_version', '-')}</td>
                <td>{result.get('os_guess', '-')}</td>
                <td>{result.get('os_confidence', '-')}</td>
                <td>{result.get('timestamp', '')}</td>
            </tr>
            """
        
        html += """
            </tbody>
        </table>
        </body>
        </html>
        """
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return filename
    
    def _get_html_header(self, title: str = "Packet Phantom Report") -> str:
        """Get HTML document header."""
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>{title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        tr.open {{ background-color: #dff0d8; }}
        tr.closed {{ background-color: #f2dede; }}
        tr.filtered {{ background-color: #fcf8e3; }}
        .status {{ font-weight: bold; }}
        .summary {{ margin: 20px 0; padding: 10px; background: #f5f5f5; }}
    </style>
</head>
<body>
    <h1>Packet Phantom - {title}</h1>
"""
    
    def close(self):
        """Close output files and cleanup."""
        # Close JSON file
        if hasattr(self, 'json_file'):
            if self.config.output_file:
                self.json_file.write('\n]')
            self.json_file.close()
        
        # Close CSV file
        if hasattr(self, 'csv_file'):
            self.csv_file.close()
        
        # Close HTML file
        if hasattr(self, 'html_file'):
            self.html_file.write('</body></html>')
            self.html_file.close()
        
        # Close PCAP writer
        if self.packet_writer:
            self.packet_writer.close()
    
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
    'OutputManager',
    'OutputConfig',
    'OutputFormat',
    'ScanResult',
    'FloodResult',
]
