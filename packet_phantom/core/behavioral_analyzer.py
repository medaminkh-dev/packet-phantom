"""
Behavioral Analysis Engine for Packet Phantom God OS Fingerprinting.

This module implements the D1-D8 dimension analyzers for comprehensive
behavioral fingerprinting of target systems.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from enum import Enum
import statistics


class Dimension(Enum):
    """Fingerprinting dimensions for behavioral analysis."""
    D1_STATIC_TCP = "D1"      # Static TCP fingerprinting
    D2_TCP_BEHAVIOR = "D2"    # TCP behavior under load
    D3_TEMPORAL = "D3"        # Temporal analysis
    D4_ICMP = "D4"            # ICMP response patterns
    D5_ERROR_HANDLING = "D5"  # Error handling patterns
    D6_UDP = "DD6"             # UDP behavior
    D7_TLS = "D7"              # TLS/SSL handshake
    D8_HARDWARE = "D8"        # Hardware/virtualization detection


@dataclass
class DimensionResult:
    """Result from analyzing a single dimension."""
    dimension: str
    score: float
    details: Dict[str, Any]
    confidence: float


class D1StaticTCPAnalyzer:
    """D1: Static TCP fingerprinting analysis."""
    
    def analyze(self, response: Dict[str, Any]) -> DimensionResult:
        """Analyze TCP SYN-ACK response for static fingerprints."""
        details = {}
        score = 0.0
        
        # Extract TCP fields
        ttl = response.get('ttl', 0)
        window = response.get('window_size', 0)
        options = response.get('options', [])
        df_bit = response.get('df_bit', False)
        mss = response.get('mss')
        
        # Score each component
        if ttl:
            details['ttl'] = ttl
            score += 0.25
        
        if window:
            details['window_size'] = window
            score += 0.25
        
        if options:
            details['options'] = options
            # More options = higher specificity
            score += min(0.25, len(options) * 0.05)
        
        if df_bit is not None:
            details['df_bit'] = df_bit
            score += 0.15
        
        if mss:
            details['mss'] = mss
            score += 0.10
        
        # Calculate dimension confidence
        confidence = min(score * 100 / 0.9, 100.0)  # Normalize
        
        return DimensionResult(
            dimension="D1",
            score=score,
            details=details,
            confidence=confidence
        )


class D2TCPBehaviorAnalyzer:
    """D2: TCP behavior under load."""
    
    def analyze(self, responses: List[Dict[str, Any]]) -> DimensionResult:
        """Analyze TCP behavior patterns across multiple probes."""
        if not responses:
            return DimensionResult("D2", 0.0, {}, 0.0)
        
        details = {
            'response_rate': len(responses) / len(responses),  # Should be 1.0
            'window_variations': [],
            'option_changes': []
        }
        
        # Analyze window size consistency
        windows = [r.get('window_size', 0) for r in responses if r.get('window_size')]
        if len(windows) > 1:
            details['window_variations'] = windows
            variance = statistics.variance(windows) if len(windows) > 1 else 0
            details['window_variance'] = variance
        
        # Analyze option consistency
        options_list = [tuple(r.get('options', [])) for r in responses]
        unique_options = len(set(options_list))
        details['option_consistency'] = 1.0 - (unique_options / len(responses))
        
        score = 0.5 + (details.get('option_consistency', 0) * 0.5)
        
        return DimensionResult(
            dimension="D2",
            score=score,
            details=details,
            confidence=min(score * 100, 100.0)
        )


class D3TemporalAnalyzer:
    """D3: Temporal analysis (jitter, response speed)."""
    
    def analyze(self, response_times: List[float]) -> DimensionResult:
        """Analyze timing patterns."""
        if not response_times:
            return DimensionResult("D3", 0.0, {}, 0.0)
        
        details = {
            'mean_ms': statistics.mean(response_times),
            'min_ms': min(response_times),
            'max_ms': max(response_times),
        }
        
        if len(response_times) > 1:
            details['jitter_ms'] = statistics.stdev(response_times)
            details['jitter_percent'] = (details['jitter_ms'] / details['mean_ms']) * 100
        else:
            details['jitter_ms'] = 0.0
            details['jitter_percent'] = 0.0
        
        # Lower jitter = higher score
        if details['jitter_ms'] < 1.0:
            score = 1.0
        elif details['jitter_ms'] < 5.0:
            score = 0.8
        elif details['jitter_ms'] < 10.0:
            score = 0.6
        else:
            score = 0.4
        
        return DimensionResult(
            dimension="D3",
            score=score,
            details=details,
            confidence=min(score * 100, 100.0)
        )


class D4ICMPAnalyzer:
    """D4: ICMP response patterns."""
    
    def analyze(self, icmp_responses: List[Dict[str, Any]]) -> DimensionResult:
        """Analyze ICMP echo and timestamp responses."""
        if not icmp_responses:
            return DimensionResult("D4", 0.0, {}, 0.0)
        
        details = {
            'echo_responses': 0,
            'timestamp_responses': 0,
            'address_responses': 0,
            'code_values': []
        }
        
        for resp in icmp_responses:
            resp_type = resp.get('type', '')
            if 'echo' in resp_type.lower():
                details['echo_responses'] += 1
            elif 'timestamp' in resp_type.lower():
                details['timestamp_responses'] += 1
            elif 'address' in resp_type.lower():
                details['address_responses'] += 1
            
            code = resp.get('code', 0)
            details['code_values'].append(code)
        
        # Score based on response diversity
        response_types = (
            (1 if details['echo_responses'] > 0 else 0) + 
            (1 if details['timestamp_responses'] > 0 else 0) + 
            (1 if details['address_responses'] > 0 else 0)
        )
        score = min(response_types * 0.3 + 0.4, 1.0)
        
        return DimensionResult(
            dimension="D4",
            score=score,
            details=details,
            confidence=min(score * 100, 100.0)
        )


class D5ErrorHandlingAnalyzer:
    """D5: Error handling patterns."""
    
    def analyze(self, error_responses: List[Dict[str, Any]]) -> DimensionResult:
        """Analyze how target handles error conditions."""
        if not error_responses:
            return DimensionResult("D5", 0.0, {'errors_detected': 0}, 0.0)
        
        details = {
            'errors_detected': len(error_responses),
            'error_types': {},
            'rst_on_closed': False,
            'silence_on_filtered': False
        }
        
        for resp in error_responses:
            err_type = resp.get('type', 'unknown')
            details['error_types'][err_type] = details['error_types'].get(err_type, 0) + 1
        
        # Check for specific error patterns
        for resp in error_responses:
            if resp.get('flags', {}).get('rst'):
                details['rst_on_closed'] = True
            if resp.get('type') == 'timeout':
                details['silence_on_filtered'] = True
        
        # Score based on error pattern specificity
        if details['error_types']:
            score = min(len(details['error_types']) * 0.2 + 0.5, 1.0)
        else:
            score = 0.5
        
        return DimensionResult(
            dimension="D5",
            score=score,
            details=details,
            confidence=min(score * 100, 100.0)
        )


class D6UDPAnalyzer:
    """D6: UDP behavior analysis."""
    
    def analyze(self, udp_responses: List[Dict[str, Any]]) -> DimensionResult:
        """Analyze UDP response patterns."""
        if not udp_responses:
            return DimensionResult("D6", 0.0, {'responses_detected': 0}, 0.0)
        
        details = {
            'responses_detected': len(udp_responses),
            'port_unreachable': 0,
            'icmp_unreachable': 0,
            'no_response': 0
        }
        
        for resp in udp_responses:
            resp_type = resp.get('type', '')
            if 'port_unreachable' in resp_type.lower():
                details['port_unreachable'] += 1
            elif 'unreachable' in resp_type.lower():
                details['icmp_unreachable'] += 1
            elif resp_type == 'no_response':
                details['no_response'] += 1
        
        # Score based on response characteristics
        if details['port_unreachable'] > 0:
            score = 0.8  # Good - UDP closed port response
        elif details['icmp_unreachable'] > 0:
            score = 0.6  # Partial - ICMP response
        elif details['no_response'] > 0:
            score = 0.4  # Filtered UDP
        else:
            score = 0.3
        
        return DimensionResult(
            dimension="D6",
            score=score,
            details=details,
            confidence=min(score * 100, 100.0)
        )


class D7TLSAnalyzer:
    """D7: TLS/SSL handshake analysis."""
    
    def analyze(self, tls_responses: List[Dict[str, Any]]) -> DimensionResult:
        """Analyze TLS/SSL handshake patterns."""
        if not tls_responses:
            return DimensionResult("D7", 0.0, {'handshakes_analyzed': 0}, 0.0)
        
        details = {
            'handshakes_analyzed': len(tls_responses),
            'supported_versions': [],
            'cipher_suites': [],
            'extensions': []
        }
        
        for resp in tls_responses:
            version = resp.get('version', '')
            if version:
                details['supported_versions'].append(version)
            
            ciphers = resp.get('cipher_suites', [])
            if ciphers:
                details['cipher_suites'].extend(ciphers)
            
            exts = resp.get('extensions', [])
            if exts:
                details['extensions'].extend(exts)
        
        # Score based on TLS fingerprint specificity
        version_count = len(set(details['supported_versions']))
        cipher_count = len(set(details['cipher_suites']))
        
        score = min(0.3 + (version_count * 0.2) + min(cipher_count * 0.05, 0.4), 1.0)
        
        return DimensionResult(
            dimension="D7",
            score=score,
            details=details,
            confidence=min(score * 100, 100.0)
        )


class D8HardwareAnalyzer:
    """D8: Hardware/virtualization detection."""
    
    def analyze(self, all_responses: Dict[str, Any]) -> DimensionResult:
        """Detect hardware type and virtualization."""
        details = {
            'indicators': [],
            'environment': 'unknown',
            'virtualization': False,
            'container': False
        }
        
        # Check TCP timestamp behavior
        tcp_ts = all_responses.get('tcp_syn_ack', {}).get('options', [])
        if 'Timestamp' in tcp_ts:
            details['indicators'].append('tcp_timestamp')
        
        # Check window size patterns (often VM-specific)
        window = all_responses.get('tcp_syn_ack', {}).get('window_size', 0)
        if window in [5840, 65535, 14600]:
            details['indicators'].append(f'common_window_{window}')
        
        # Check TTL patterns
        ttl = all_responses.get('tcp_syn_ack', {}).get('ttl', 0)
        if ttl <= 64:
            details['indicators'].append('likely_virtual_ttl')
        elif ttl >= 128:
            details['indicators'].append('likely_physical_ttl')
        
        # Determine environment
        if any('ec2' in str(d).lower() for d in details['indicators']):
            details['environment'] = 'cloud'
            details['virtualization'] = True
        elif 'likely_virtual_ttl' in details['indicators']:
            details['environment'] = 'virtual'
            details['virtualization'] = True
        elif 'likely_physical_ttl' in details['indicators']:
            details['environment'] = 'physical'
        
        score = min(len(details['indicators']) * 0.2 + 0.3, 1.0)
        
        return DimensionResult(
            dimension="D8",
            score=score,
            details=details,
            confidence=min(score * 100, 100.0)
        )


class BehavioralAnalyzer:
    """Main behavioral analysis engine combining all dimensions."""
    
    def __init__(self):
        self.analyzers = {
            "D1": D1StaticTCPAnalyzer(),
            "D2": D2TCPBehaviorAnalyzer(),
            "D3": D3TemporalAnalyzer(),
            "D4": D4ICMPAnalyzer(),
            "D5": D5ErrorHandlingAnalyzer(),
            "D6": D6UDPAnalyzer(),
            "D7": D7TLSAnalyzer(),
            "D8": D8HardwareAnalyzer(),
        }
    
    def analyze_all(self, fingerprint_data: Dict[str, Any]) -> Dict[str, DimensionResult]:
        """Run all dimension analyzers."""
        results = {}
        
        # D1: Static TCP
        tcp_response = fingerprint_data.get('probe_responses', {}).get('tcp_syn_ack', {})
        if tcp_response:
            results['D1'] = self.analyzers["D1"].analyze(tcp_response)
        
        # D2: TCP behavior (requires multiple responses)
        tcp_responses = fingerprint_data.get('probe_responses', {}).get('tcp_multiple', [])
        if tcp_responses:
            results['D2'] = self.analyzers["D2"].analyze(tcp_responses)
        
        # D3: Temporal
        response_times = fingerprint_data.get('temporal', {}).get('response_times', [])
        if response_times:
            results['D3'] = self.analyzers["D3"].analyze(response_times)
        
        # D4: ICMP
        icmp_responses = fingerprint_data.get('probe_responses', {}).get('icmp', [])
        if icmp_responses:
            results['D4'] = self.analyzers["D4"].analyze(icmp_responses)
        
        # D5: Error handling
        error_responses = fingerprint_data.get('error_responses', [])
        if error_responses:
            results['D5'] = self.analyzers["D5"].analyze(error_responses)
        
        # D6: UDP
        udp_responses = fingerprint_data.get('probe_responses', {}).get('udp', [])
        if udp_responses:
            results['D6'] = self.analyzers["D6"].analyze(udp_responses)
        
        # D7: TLS
        tls_responses = fingerprint_data.get('probe_responses', {}).get('tls', [])
        if tls_responses:
            results['D7'] = self.analyzers["D7"].analyze(tls_responses)
        
        # D8: Hardware
        results['D8'] = self.analyzers["D8"].analyze(fingerprint_data)
        
        return results
    
    def get_overall_score(self, dimension_results: Dict[str, DimensionResult]) -> float:
        """Calculate overall behavioral score."""
        if not dimension_results:
            return 0.0
        
        scores = [r.score for r in dimension_results.values()]
        return statistics.mean(scores) if scores else 0.0
    
    def get_dimension_weights(self) -> Dict[str, float]:
        """Get weighting factors for each dimension."""
        return {
            "D1": 0.20,  # Static TCP - high importance
            "D2": 0.15,  # TCP behavior
            "D3": 0.15,  # Temporal
            "D4": 0.10,  # ICMP
            "D5": 0.10,  # Error handling
            "D6": 0.10,  # UDP
            "D7": 0.10,  # TLS
            "D8": 0.10,  # Hardware
        }
    
    def calculate_weighted_score(self, dimension_results: Dict[str, DimensionResult]) -> float:
        """Calculate weighted overall score."""
        weights = self.get_dimension_weights()
        weighted_sum = 0.0
        weight_total = 0.0
        
        for dim, result in dimension_results.items():
            if dim in weights:
                weighted_sum += result.score * weights[dim]
                weight_total += weights[dim]
        
        if weight_total == 0:
            return 0.0
        
        return weighted_sum / weight_total
