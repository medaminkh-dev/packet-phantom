"""
Probe Sequencing Engine for OS Fingerprinting
==============================================

This module provides the probe sequencing engine for executing network probes
against target systems and collecting responses for OS fingerprinting.


Version: 2.0.0
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Callable
import time
import logging

logger = logging.getLogger(__name__)

# Import optimizations for extended functionality
try:
    from packet_phantom.core.parallel_engine import (
        ParallelProbeEngine,
        ProbeCache,
        OptimizedProbeEngine,
        create_optimized_engine
    )
    OPTIMIZATIONS_AVAILABLE = True
except ImportError:
    OPTIMIZATIONS_AVAILABLE = False
    logger.warning("Parallel engine optimizations not available")


class ProbeType(Enum):
    """Enumeration of probe types for OS fingerprinting."""
    TCP_SYN = "tcp_syn"
    TCP_SYN_ACK = "tcp_syn_ack"
    TCP_FIN = "tcp_fin"
    TCP_RST = "tcp_rst"
    TCP_PSH = "tcp_psh"
    ICMP_ECHO = "icmp_echo"
    ICMP_TIMESTAMP = "icmp_timestamp"
    ICMP_ADDRESS = "icmp_address"
    UDP_OPEN = "udp_open"
    UDP_CLOSED = "udp_closed"


@dataclass
class Probe:
    """
    Represents a single network probe for OS fingerprinting.
    
    Attributes:
        name: Human-readable name for the probe
        probe_type: Type of probe to execute
        target_port: Target port (0 for ICMP/UDP general probes)
        timeout: Response timeout in seconds
        retry_count: Number of retry attempts
        payload: Optional payload data for the probe
    """
    name: str
    probe_type: ProbeType
    target_port: int
    timeout: float
    retry_count: int
    payload: Optional[bytes] = field(default=None)
    
    def __post_init__(self):
        """Validate and normalize probe parameters."""
        if self.payload is None:
            self.payload = b''
        if self.timeout < 0.1:
            self.timeout = 0.1
        if self.retry_count < 0:
            self.retry_count = 0


# Pre-defined probe sequences for different analysis depths
PROBE_SEQUENCES = {
    'quick': {
        'description': 'Quick OS detection - minimal probe set',
        'timeout': 2.0,
        'max_retries': 1,
        'probes': [
            Probe('TCP_SYN_80', ProbeType.TCP_SYN, 80, 2.0, 1, None),
            Probe('TCP_SYN_443', ProbeType.TCP_SYN, 443, 2.0, 1, None),
            Probe('ICMP_ECHO', ProbeType.ICMP_ECHO, 0, 2.0, 1, b'\x00' * 56),
        ]
    },
    'deep': {
        'description': 'Deep OS fingerprinting - comprehensive probe set',
        'timeout': 5.0,
        'max_retries': 2,
        'probes': [
            Probe('TCP_SYN_80', ProbeType.TCP_SYN, 80, 5.0, 2, None),
            Probe('TCP_SYN_443', ProbeType.TCP_SYN, 443, 5.0, 2, None),
            Probe('TCP_SYN_22', ProbeType.TCP_SYN, 22, 5.0, 2, None),
            Probe('TCP_SYN_3389', ProbeType.TCP_SYN, 3389, 5.0, 2, None),
            Probe('ICMP_ECHO', ProbeType.ICMP_ECHO, 0, 5.0, 2, b'\x00' * 56),
            Probe('ICMP_TIMESTAMP', ProbeType.ICMP_TIMESTAMP, 0, 5.0, 2, None),
            Probe('UDP_33434', ProbeType.UDP_CLOSED, 33434, 5.0, 2, b'TEST' * 10),
        ]
    },
    'forensic': {
        'description': 'Forensic OS analysis - exhaustive probe set with state probes',
        'timeout': 10.0,
        'max_retries': 3,
        'probes': [
            # TCP state probes
            Probe('TCP_SYN_80', ProbeType.TCP_SYN, 80, 10.0, 3, None),
            Probe('TCP_SYN_ACK_80', ProbeType.TCP_SYN_ACK, 80, 10.0, 3, None),
            Probe('TCP_FIN_80', ProbeType.TCP_FIN, 80, 10.0, 3, None),
            Probe('TCP_RST_80', ProbeType.TCP_RST, 80, 10.0, 3, None),
            # ICMP probes
            Probe('ICMP_ECHO', ProbeType.ICMP_ECHO, 0, 10.0, 3, b'\x00' * 56),
            Probe('ICMP_TIMESTAMP', ProbeType.ICMP_TIMESTAMP, 0, 10.0, 3, None),
            Probe('ICMP_ADDRESS', ProbeType.ICMP_ADDRESS, 0, 10.0, 3, None),
            # UDP probes
            Probe('UDP_OPEN_53', ProbeType.UDP_OPEN, 53, 10.0, 3, b'DNS' * 10),
            Probe('UDP_CLOSED_33434', ProbeType.UDP_CLOSED, 33434, 10.0, 3, b'TEST' * 10),
        ]
    }
}


class ProbeTiming:
    """
    Handle probe timing and timeout logic with exponential backoff.
    
    This class manages timing strategies for probe execution including:
    - Base timeout calculation
    - Exponential backoff for retries
    - Retry decision logic
    """
    
    def __init__(self, base_timeout: float, max_retries: int):
        """
        Initialize probe timing controller.
        
        Args:
            base_timeout: Initial timeout value in seconds
            max_retries: Maximum number of retry attempts
        """
        self.base_timeout = base_timeout
        self.max_retries = max_retries
        self.max_timeout = 30.0  # Cap timeout at 30 seconds
    
    def get_timeout(self, retry: int = 0) -> float:
        """
        Calculate timeout for a retry attempt with exponential backoff.
        
        Args:
            retry: Current retry attempt number (0-indexed)
            
        Returns:
            Timeout value in seconds for this attempt
        """
        # Exponential backoff: base_timeout * (2 ^ retry)
        timeout = self.base_timeout * (2 ** retry)
        return min(timeout, self.max_timeout)
    
    def should_retry(self, response: Optional[Dict[str, Any]], retry: int) -> bool:
        """
        Determine if a probe should be retried based on response.
        
        Args:
            response: Response data from the probe attempt
            retry: Current retry attempt number
            
        Returns:
            True if the probe should be retried
        """
        if response is None:
            return retry < self.max_retries
        
        # Check for specific retry conditions
        error = response.get('error')
        if error and 'timeout' in error.lower():
            return retry < self.max_retries
        
        success = response.get('success', False)
        return not success and retry < self.max_retries
    
    def get_total_timeout(self) -> float:
        """
        Calculate maximum total timeout for the entire probe sequence.
        
        Returns:
            Maximum total timeout in seconds
        """
        total = 0
        for retry in range(self.max_retries + 1):
            total += self.get_timeout(retry)
        return min(total, self.max_timeout * (self.max_retries + 1))


class ProbeEngine:
    """
    Main probe sequencing engine for OS fingerprinting.
    
    This class orchestrates the execution of probe sequences against
    target systems, collecting responses for fingerprint analysis.
    
    Attributes:
        target: Target IP address or hostname
        sequence_name: Name of the probe sequence to use
        sequence: Probe sequence configuration
        timing: ProbeTiming instance for timing management
        results: List of probe results
    """
    
    def __init__(
        self,
        target: str,
        sequence: str = 'quick',
        timeout: Optional[float] = None,
        progress_callback: Optional[Callable[[int, int, str], None]] = None
    ):
        """
        Initialize the probe engine.
        
        Args:
            target: Target IP address or hostname
            sequence: Probe sequence name ('quick', 'deep', 'forensic')
            timeout: Override timeout (uses sequence default if None)
            progress_callback: Optional callback for progress updates
        """
        self.target = target
        self.sequence_name = sequence
        self.sequence = PROBE_SEQUENCES.get(sequence, PROBE_SEQUENCES['quick'])
        self.timeout = timeout or self.sequence['timeout']
        self.timing = ProbeTiming(self.timeout, self.sequence['max_retries'])
        self.results: List[Dict[str, Any]] = []
        self.progress_callback = progress_callback
    
    def run_probe(self, probe: Probe) -> Dict[str, Any]:
        """
        Execute a single probe and record the response.
        
        Args:
            probe: Probe configuration to execute
            
        Returns:
            Dictionary containing probe results
        """
        start_time = time.time()
        
        result = {
            'probe_name': probe.name,
            'probe_type': probe.probe_type.value,
            'target': self.target,
            'target_port': probe.target_port,
            'success': False,
            'response_time_ms': 0.0,
            'response_data': None,
            'error': None,
            'retry_count': 0,
            'timestamp': time.time()
        }
        
        # TODO: Implement actual probe sending (TCP SYN, ICMP, UDP, etc.)
        # For now, return mock response for testing
        
        try:
            # Placeholder for actual probe implementation
            # This would use raw sockets to send probes and capture responses
            logger.debug(f"Executing probe: {probe.name} against {self.target}")
            
            # Simulate probe execution for testing
            result['success'] = False
            result['error'] = 'Probe execution not implemented'
            
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"Probe {probe.name} failed: {e}")
        
        finally:
            result['response_time_ms'] = (time.time() - start_time) * 1000
        
        return result
    
    def run_sequence(self) -> List[Dict[str, Any]]:
        """
        Execute the full probe sequence against the target.
        
        Returns:
            List of result dictionaries for each probe
        """
        self.results = []
        total_probes = len(self.sequence['probes'])
        
        logger.info(f"Starting probe sequence '{self.sequence_name}' against {self.target}")
        logger.info(f"Sequence description: {self.sequence['description']}")
        
        for i, probe in enumerate(self.sequence['probes']):
            # Report progress
            if self.progress_callback:
                self.progress_callback(i, total_probes, probe.name)
            
            logger.debug(f"Executing probe {i+1}/{total_probes}: {probe.name}")
            
            # Try probe with retries
            response = None
            for retry in range(self.sequence['max_retries'] + 1):
                timeout = self.timing.get_timeout(retry)
                response = self.run_probe(probe)
                response['retry_count'] = retry
                
                if response['success'] or not self.timing.should_retry(response, retry):
                    break
            
            self.results.append(response)
        
        logger.info(f"Probe sequence complete: {len(self.results)} probes executed")
        return self.results
    
    def get_successful_probes(self) -> List[Dict[str, Any]]:
        """
        Get list of probes that received successful responses.
        
        Returns:
            List of successful probe result dictionaries
        """
        return [r for r in self.results if r.get('success', False)]
    
    def get_failed_probes(self) -> List[Dict[str, Any]]:
        """
        Get list of probes that failed.
        
        Returns:
            List of failed probe result dictionaries
        """
        return [r for r in self.results if not r.get('success', False)]
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about probe execution.
        
        Returns:
            Dictionary containing probe statistics
        """
        successful = self.get_successful_probes()
        failed = self.get_failed_probes()
        
        total_time = sum(r.get('response_time_ms', 0) for r in self.results)
        
        return {
            'target': self.target,
            'sequence_name': self.sequence_name,
            'total_probes': len(self.results),
            'successful_probes': len(successful),
            'failed_probes': len(failed),
            'success_rate': len(successful) / len(self.results) if self.results else 0,
            'total_execution_time_ms': total_time,
            'average_response_time_ms': total_time / len(self.results) if self.results else 0
        }


# Example usage and testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    # Test probe sequences
    print("=== Probe Sequencing Engine Test ===\n")
    
    print("Quick sequence:")
    print(f"  Description: {PROBE_SEQUENCES['quick']['description']}")
    print(f"  Number of probes: {len(PROBE_SEQUENCES['quick']['probes'])}")
    print(f"  Timeout: {PROBE_SEQUENCES['quick']['timeout']}s")
    print(f"  Max retries: {PROBE_SEQUENCES['quick']['max_retries']}")
    
    print("\nDeep sequence:")
    print(f"  Description: {PROBE_SEQUENCES['deep']['description']}")
    print(f"  Number of probes: {len(PROBE_SEQUENCES['deep']['probes'])}")
    print(f"  Timeout: {PROBE_SEQUENCES['deep']['timeout']}s")
    print(f"  Max retries: {PROBE_SEQUENCES['deep']['max_retries']}")
    
    print("\nForensic sequence:")
    print(f"  Description: {PROBE_SEQUENCES['forensic']['description']}")
    print(f"  Number of probes: {len(PROBE_SEQUENCES['forensic']['probes'])}")
    print(f"  Timeout: {PROBE_SEQUENCES['forensic']['timeout']}s")
    print(f"  Max retries: {PROBE_SEQUENCES['forensic']['max_retries']}")
    
    # Test timing
    print("\n=== Probe Timing Test ===")
    timing = ProbeTiming(base_timeout=2.0, max_retries=3)
    print(f"Base timeout: {timing.base_timeout}s")
    print(f"Max retries: {timing.max_retries}")
    for i in range(4):
        print(f"  Retry {i}: timeout = {timing.get_timeout(i):.2f}s")
    
    # Test probe engine
    print("\n=== Probe Engine Test ===")
    engine = ProbeEngine(target="127.0.0.1", sequence="quick")
    print(f"Target: {engine.target}")
    print(f"Sequence: {engine.sequence_name}")
    print(f"Timeout: {engine.timeout}s")
    
    results = engine.run_sequence()
    print(f"\nResults: {len(results)} probes executed")
    stats = engine.get_statistics()
    print(f"Statistics: {stats}")
