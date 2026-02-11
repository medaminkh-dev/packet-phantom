#!/usr/bin/env python3
"""
OS Output Formatter Module
===========================

Output formatting classes for OS fingerprinting results.

This module provides multiple output formats for OS fingerprinting results:
- SimpleOSOutput: Minimal output for scripting
- DetailedOSOutput: Human-readable output with explanations
- JSONOSOutput: Machine-readable JSON output

Also includes:
- Color coding utilities for terminal output
- ProbeProgress: Progress indicator for probe sequences
- EducationalExplainer: Learning content for educational mode

Author: Packet Phantom Team
Version: 2.0.0
"""

import json
import sys
from typing import Dict, Any, Optional


# =============================================================================
# COLOR CODING UTILITIES
# =============================================================================

class OSOutputColors:
    """ANSI color codes for OS output formatting."""
    
    # Basic colors
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BLACK = '\033[30m'
    
    # Style codes
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    ITALIC = '\033[3m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    
    # Background colors
    BG_GREEN = '\033[42m'
    BG_YELLOW = '\033[43m'
    BG_RED = '\033[41m'
    BG_BLUE = '\033[44m'


# Alias for backward compatibility
COLORS = OSOutputColors


def colorize(text: str, color: str) -> str:
    """
    Apply color to text if terminal supports it.
    
    Args:
        text: Text to colorize
        color: Color name from OSOutputColors
        
    Returns:
        Colorized text if terminal supports it, original text otherwise
    """
    if not sys.stdout.isatty():
        return text
    
    color_code = getattr(OSOutputColors, color.upper(), '')
    if not color_code:
        return text
    
    return f"{color_code}{text}{OSOutputColors.ENDC}"


def colorize_os(os_name: str, confidence: int) -> str:
    """
    Colorize OS name based on confidence level.
    
    Args:
        os_name: Operating system name
        confidence: Confidence level (0-100)
        
    Returns:
        Colorized OS name
    """
    if confidence >= 90:
        return colorize(os_name, 'green')
    elif confidence >= 70:
        return colorize(os_name, 'yellow')
    else:
        return colorize(os_name, 'red')


# =============================================================================
# OUTPUT FORMAT CLASSES
# =============================================================================

class SimpleOSOutput:
    """Minimal output format for scripting and integration."""
    
    def format(self, result: Dict[str, Any]) -> str:
        """
        Format OS detection result in simple text.
        
        Args:
            result: OS detection result dictionary
            
        Returns:
            Simple formatted string
        """
        os_name = result.get('os', 'Unknown')
        confidence = result.get('confidence', 0)
        return f"{os_name} ({confidence}%)"
    
    def format_batch(self, results: list) -> str:
        """
        Format multiple OS detection results.
        
        Args:
            results: List of OS detection result dictionaries
            
        Returns:
            Simple formatted string for all results
        """
        return '\n'.join(self.format(r) for r in results)


class DetailedOSOutput:
    """Human-readable output with explanations and educational content."""
    
    def __init__(self, show_educational: bool = True):
        """
        Initialize DetailedOSOutput.
        
        Args:
            show_educational: Whether to include educational explanations
        """
        self.show_educational = show_educational
        self.explainer = EducationalExplainer() if show_educational else None
    
    def format(self, result: Dict[str, Any]) -> str:
        """
        Format OS detection result with detailed information.
        
        Args:
            result: OS detection result dictionary
            
        Returns:
            Detailed formatted string
        """
        lines = []
        
        # Header
        os_name = result.get('os', 'Unknown')
        confidence = result.get('confidence', 0)
        lines.append(colorize("=" * 50, 'cyan'))
        lines.append(colorize("OS Detection Result", 'bold'))
        lines.append(colorize("=" * 50, 'cyan'))
        lines.append("")
        
        # OS and confidence with color
        os_colored = colorize_os(os_name, confidence)
        lines.append(f"OS: {os_colored}")
        lines.append(f"Confidence: {colorize(str(confidence), 'cyan')}%")
        lines.append("")
        
        # Fingerprints section
        lines.append(colorize("Key Fingerprints:", 'bold'))
        fingerprints = result.get('fingerprints', [])
        for fp in fingerprints:
            lines.append(f"  - {fp}")
        
        if not fingerprints:
            lines.append("  (No fingerprints detected)")
        
        lines.append("")
        
        # Detailed analysis
        if 'analysis' in result:
            lines.append(colorize("Detailed Analysis:", 'bold'))
            for key, value in result['analysis'].items():
                lines.append(f"  {key}: {value}")
            lines.append("")
        
        # Educational explanations
        if self.show_educational and self.explainer and fingerprints:
            lines.append(colorize("Educational Explanation:", 'bold'))
            lines.append(colorize("-" * 30, 'dim'))
            for fp in fingerprints:
                explanation = self.explainer.explain_fingerprint({'name': fp})
                if explanation:
                    lines.append(f"  {fp}: {explanation}")
            lines.append("")
        
        return '\n'.join(lines)
    
    def format_batch(self, results: list) -> str:
        """
        Format multiple OS detection results.
        
        Args:
            results: List of OS detection result dictionaries
            
        Returns:
            Detailed formatted string for all results
        """
        return '\n\n'.join(self.format(r) for r in results)


class JSONOSOutput:
    """Machine-readable JSON output format."""
    
    def format(self, result: Dict[str, Any]) -> str:
        """
        Format OS detection result as JSON.
        
        Args:
            result: OS detection result dictionary
            
        Returns:
            JSON formatted string
        """
        return json.dumps(result, indent=2)
    
    def format_batch(self, results: list) -> str:
        """
        Format multiple OS detection results as JSON array.
        
        Args:
            results: List of OS detection result dictionaries
            
        Returns:
            JSON array formatted string
        """
        return json.dumps(results, indent=2)


# =============================================================================
# FORMATTER FACTORY
# =============================================================================

def get_os_formatter(format_type: str = 'detailed', show_educational: bool = True):
    """
    Get the appropriate output formatter.
    
    Args:
        format_type: Output format ('simple', 'detailed', 'json')
        show_educational: Whether to include educational content
        
    Returns:
        Output formatter instance
    """
    formatters = {
        'simple': SimpleOSOutput(),
        'detailed': lambda: DetailedOSOutput(show_educational),
        'json': JSONOSOutput()
    }
    
    formatter_factory = formatters.get(format_type, formatters['detailed'])
    
    if callable(formatter_factory):
        return formatter_factory()
    return formatter_factory


# =============================================================================
# PROGRESS INDICATOR
# =============================================================================

class ProbeProgress:
    """Progress indicator for probe sequences."""
    
    def __init__(self, total: int, description: str = "Probing"):
        """
        Initialize probe progress indicator.
        
        Args:
            total: Total number of probes
            description: Description of the probing process
        """
        self.total = total
        self.current = 0
        self.description = description
        self.start_time = None
    
    def start(self):
        """Start the progress indicator."""
        import time
        self.start_time = time.time()
        self.current = 0
        print(f"{self.description}...")
    
    def update(self, probe_name: str):
        """
        Update progress with current probe.
        
        Args:
            probe_name: Name of the probe being executed
        """
        import time
        
        if self.start_time is None:
            self.start_time = time.time()
        
        self.current += 1
        percent = (self.current / self.total) * 100
        elapsed = time.time() - self.start_time
        
        # Progress bar
        bar_length = 30
        filled = int(bar_length * self.current // self.total)
        bar = '#' * filled + '-' * (bar_length - filled)
        
        # ETA calculation
        if self.current > 0:
            eta = (elapsed / self.current) * (self.total - self.current)
            eta_str = f"{eta:.1f}s"
        else:
            eta_str = "--s"
        
        print(f"\r{self.description}: [{colorize(bar, 'cyan')}] "
              f"{colorize(f'{percent:5.1f}%', 'green')} "
              f"{colorize(f'{self.current}/{self.total}', 'yellow')} "
              f"ETA: {colorize(eta_str, 'dim')}",
              end='', flush=True)
    
    def complete(self):
        """Mark progress as complete."""
        import time
        
        if self.start_time is None:
            elapsed = 0
        else:
            elapsed = time.time() - self.start_time
        
        print()  # New line
        print(colorize("[OK]", 'green') + f" Probing complete in {elapsed:.2f}s")
        
        self.current = 0
        self.start_time = None
    
    def reset(self):
        """Reset the progress indicator."""
        self.current = 0
        self.start_time = None


# =============================================================================
# EDUCATIONAL MODE EXPLAINER
# =============================================================================

class EducationalExplainer:
    """Add learning content to OS fingerprinting output."""
    
    def __init__(self):
        """Initialize the educational explainer."""
        self.probe_explanations = self._init_probe_explanations()
        self.fingerprint_explanations = self._init_fingerprint_explanations()
    
    def _init_probe_explanations(self) -> Dict[str, str]:
        """Initialize probe explanations."""
        return {
            'tcp_syn_80': (
                "Sending TCP SYN packet to port 80 reveals how the target's TCP stack "
                "responds to connection requests. Different operating systems have "
                "distinctive behaviors in their SYN+ACK responses."
            ),
            'tcp_syn_443': (
                "Sending TCP SYN to port 443 (HTTPS) tests the HTTPS stack behavior. "
                "Some systems use different code paths for HTTPS vs HTTP."
            ),
            'tcp_syn_22': (
                "Sending TCP SYN to port 22 (SSH) probes the SSH daemon's TCP stack. "
                "SSH implementations may have OS-specific characteristics."
            ),
            'tcp_syn_3389': (
                "Sending TCP SYN to port 3389 (RDP) tests Windows RDP stack behavior. "
                "This helps identify Windows systems more accurately."
            ),
            'icmp_echo': (
                "ICMP Echo Request (ping) measures the target's response time and "
                "examines ICMP implementation details that vary by OS."
            ),
            'icmp_timestamp': (
                "ICMP Timestamp Request probes the target's timestamp implementation. "
                "Some operating systems include additional timestamp data."
            ),
            'icmp_address': (
                "ICMP Address Mask Request is used by diskless workstations to get "
                "their subnet mask. Not all operating systems respond."
            ),
            'udp_33434': (
                "UDP probe to port 33434 tests closed port behavior. The ICMP "
                "Type/Code combination reveals OS-specific patterns."
            ),
            'tcp_syn_all': (
                "TCP SYN to multiple common ports maps the full TCP response fingerprint "
                "including window sizes, TTL, and TCP options support."
            ),
            'tcp_syn_ack': (
                "TCP SYN+ACK packet tests how the target handles unexpected packets. "
                "Some systems respond with RST, others ignore."
            ),
            'tcp_fin': (
                "TCP FIN packet to a closed port tests RFC 793 compliance. "
                "Many Windows systems don't respond, while Unix-like systems do."
            ),
            'tcp_rst': (
                "TCP RST packet tests how the target handles reset packets. "
                "Different stacks have varying RST behaviors."
            ),
            'tcp_xmas': (
                "TCP FIN+URG+PSH (XMAS) packet tests response to malformed packets. "
                "Some systems respond to all XMAS packets, others to none."
            ),
            'tcp_null': (
                "TCP NULL packet (no flags) tests how the target handles packets "
                "with no flags set. Windows often responds differently than Unix."
            )
        }
    
    def _init_fingerprint_explanations(self) -> Dict[str, Dict[str, str]]:
        """Initialize fingerprint explanations."""
        return {
            'ttl': {
                'name': 'Time To Live',
                'explanation': (
                    "The TTL value in IP packets indicates how many hops the packet "
                    "can take before being discarded. Different OSes use different "
                    "default TTLs (Linux: 64, Windows: 128, Cisco: 255)."
                ),
                'values': {
                    '64': 'Typical Linux/Unix default',
                    '128': 'Typical Windows default',
                    '255': 'Typical network device default'
                }
            },
            'window_size': {
                'name': 'TCP Window Size',
                'explanation': (
                    "The TCP window size in SYN+ACK responses varies by OS and can help "
                    "identify the operating system. Some systems use fixed values, "
                    "others use dynamic values."
                ),
                'values': {
                    '5840': 'Linux kernel 2.4+',
                    '65535': 'Windows with large window scaling',
                    '4128': 'Older Windows versions',
                    '16384': 'FreeBSD',
                    '32120': 'OpenBSD',
                    '14600': 'Cisco IOS'
                }
            },
            'tcp_options': {
                'name': 'TCP Options',
                'explanation': (
                    "The TCP options included in SYN+ACK responses vary by OS implementation. "
                    "Different stacks support different options in different orders."
                ),
                'values': {
                    'MSS': 'Maximum Segment Size - supported by most systems',
                    'WS': 'Window Scaling - indicates support for large windows',
                    'SACK': 'Selective ACK - indicates advanced TCP features',
                    'TS': 'Timestamps - indicates modern TCP implementation'
                }
            },
            'fragmentation': {
                'name': 'IP Fragmentation Handling',
                'explanation': (
                    "How an OS handles IP fragmentation can reveal its identity. "
                    "Some systems fragment more aggressively than others."
                ),
                'values': {
                    'df': "Don't Fragment bit behavior varies by OS",
                    'mf': "More Fragments bit handling differs"
                }
            },
            'icmp_reply': {
                'name': 'ICMP Reply Behavior',
                'explanation': (
                    "ICMP echo reply characteristics like code field and payload "
                    "handling vary between operating systems."
                ),
                'values': {
                    'type_0': 'Standard echo reply',
                    'type_8': 'Echo request (ping)',
                    'code': 'ICMP code field variations by OS'
                }
            }
        }
    
    def explain_probe(self, probe_name: str) -> str:
        """
        Get explanation for a specific probe.
        
        Args:
            probe_name: Name of the probe
            
        Returns:
            Explanation string for the probe
        """
        return self.probe_explanations.get(probe_name, 
            f"Probe '{probe_name}' analyzes target response patterns.")
    
    def explain_fingerprint(self, fingerprint: Dict[str, Any]) -> str:
        """
        Get explanation for a fingerprint.
        
        Args:
            fingerprint: Fingerprint dictionary with 'name' and 'value' keys
            
        Returns:
            Explanation string for the fingerprint
        """
        fp_name = fingerprint.get('name', '')
        fp_value = fingerprint.get('value', '')
        
        # Check for TTL-based fingerprints
        if 'ttl' in fp_name.lower():
            expl = self.fingerprint_explanations.get('ttl', {})
            if fp_value and fp_value in expl.get('values', {}):
                return f"{expl['explanation']} Value {fp_value}: {expl['values'][fp_value]}"
            return expl.get('explanation', '')
        
        # Check for window size fingerprints
        if 'window' in fp_name.lower():
            expl = self.fingerprint_explanations.get('window_size', {})
            if fp_value and str(fp_value) in expl.get('values', {}):
                return f"{expl['explanation']} This window size ({fp_value}) suggests: {expl['values'].get(str(fp_value), 'Unknown OS')}"
            return expl.get('explanation', '')
        
        # Check for TCP options fingerprints
        if 'option' in fp_name.lower() or 'tcp' in fp_name.lower():
            expl = self.fingerprint_explanations.get('tcp_options', {})
            return expl.get('explanation', '')
        
        # Check for ICMP fingerprints
        if 'icmp' in fp_name.lower():
            expl = self.fingerprint_explanations.get('icmp_reply', {})
            return expl.get('explanation', '')
        
        return f"Fingerprint '{fp_name}' helps identify OS characteristics."
    
    def get_probe_sequence_explanation(self, probe_type: str) -> str:
        """
        Get explanation for a complete probe sequence.
        
        Args:
            probe_type: Type of probe sequence ('quick', 'deep', 'forensic')
            
        Returns:
            Explanation string for the probe sequence
        """
        explanations = {
            'quick': (
                "The QUICK probe sequence sends a minimal set of probes (SYN to ports 80, 443 "
                "and ICMP echo) to quickly identify the operating system. "
                "This provides fast results with good accuracy for common systems."
            ),
            'deep': (
                "The DEEP probe sequence sends additional probes including SYN to ports 22, 3389, "
                "ICMP timestamp, and UDP probes. This provides more fingerprints and higher "
                "accuracy for identifying obscure or hardened systems."
            ),
            'forensic': (
                "The FORENSIC probe sequence sends all available probes including TCP FIN, "
                "RST, XMAS, NULL packets, and comprehensive ICMP tests. "
                "This provides the most detailed fingerprint but takes longer."
            )
        }
        
        return explanations.get(probe_type, "Custom probe sequence for OS fingerprinting.")


# =============================================================================
# MODULE EXPORTS
# =============================================================================

__all__ = [
    # Color utilities
    'OSOutputColors',
    'colorize',
    'colorize_os',
    
    # Output formatters
    'SimpleOSOutput',
    'DetailedOSOutput',
    'JSONOSOutput',
    
    # Factory function
    'get_os_formatter',
    
    # Progress indicator
    'ProbeProgress',
    
    # Educational explainer
    'EducationalExplainer'
]
