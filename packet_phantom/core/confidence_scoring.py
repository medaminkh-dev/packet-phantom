"""
Confidence Scoring Engine for OS Fingerprinting
=================================================

This module provides multi-factor confidence scoring for OS fingerprint
matching, calculating the probability that a fingerprint matches a
known signature.

Author: Dr. Packet (Network Security Research Division)
Version: 2.0.0
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
import math
import logging

logger = logging.getLogger(__name__)


@dataclass
class ConfidenceFactors:
    """
    Weight factors for confidence calculation.
    
    Each factor represents the importance of a particular fingerprint
    characteristic in determining OS match confidence.
    
    Attributes:
        ttl_match: Weight for TTL value match (default: 0.15)
        window_size_match: Weight for window size match (default: 0.15)
        options_match: Weight for TCP options match (default: 0.15)
        timing_match: Weight for response timing match (default: 0.20)
        jitter_match: Weight for jitter consistency (default: 0.10)
        behavior_match: Weight for behavioral patterns (default: 0.15)
        error_handling: Weight for error response patterns (default: 0.10)
    """
    ttl_match: float = 0.15
    window_size_match: float = 0.15
    options_match: float = 0.15
    timing_match: float = 0.20
    jitter_match: float = 0.10
    behavior_match: float = 0.15
    error_handling: float = 0.10


@dataclass
class MatchResult:
    """
    Result of a fingerprint matching operation.
    
    Attributes:
        signature_id: ID of the matched signature
        confidence: Overall confidence score (0.0 - 100.0)
        is_positive_match: Whether the match exceeds the threshold
        factor_scores: Individual factor scores
        match_quality: Text description of match quality
        recommendations: Suggested actions based on confidence level
    """
    signature_id: str
    confidence: float
    is_positive_match: bool
    factor_scores: Dict[str, float]
    match_quality: str
    recommendations: List[str]


class ConfidenceCalculator:
    """
    Calculate OS fingerprint confidence scores using multi-factor analysis.
    
    This class implements various scoring algorithms for different fingerprint
    characteristics and combines them into an overall confidence score.
    """
    
    # TTL tolerance thresholds (OS-specific variations)
    TTL_TOLERANCE_EXACT = 0  # Exact TTL match
    TTL_TOLERANCE_CLOSE = 2  # Within 2 hops (some TTL decrement variation)
    TTL_TOLERANCE_LOOSE = 4  # Within 4 hops (significant variation)
    
    # Window size tolerance ratios
    WINDOW_SIZE_EXACT_RATIO = 1.0
    WINDOW_SIZE_CLOSE_RATIO = 0.95
    WINDOW_SIZE_LOOSE_RATIO = 0.85
    
    # Timing tolerance ratios
    TIMING_EXACT_RATIO = 0.1  # ±10% variation
    TIMING_CLOSE_RATIO = 0.25  # ±25% variation
    TIMING_LOOSE_RATIO = 0.5  # ±50% variation
    
    # Confidence thresholds
    HIGH_CONFIDENCE_THRESHOLD = 99.0
    MEDIUM_CONFIDENCE_THRESHOLD = 85.0
    LOW_CONFIDENCE_THRESHOLD = 70.0
    
    def __init__(self, factors: Optional[ConfidenceFactors] = None):
        """
        Initialize the confidence calculator.
        
        Args:
            factors: Optional custom confidence factors (uses defaults if None)
        """
        self.factors = factors or ConfidenceFactors()
    
    def calculate_ttl_score(self, observed_ttl: int, expected_ttl: int) -> float:
        """
        Score TTL match with tolerance for network variation.
        
        Args:
            observed_ttl: TTL value observed from target
            expected_ttl: TTL value from signature
            
        Returns:
            Score from 0.0 to 1.0
        """
        if expected_ttl == 0:
            # No TTL expected, skip validation
            return 1.0
        
        diff = abs(observed_ttl - expected_ttl)
        
        if diff == self.TTL_TOLERANCE_EXACT:
            return 1.0
        elif diff <= self.TTL_TOLERANCE_CLOSE:
            return 0.8
        elif diff <= self.TTL_TOLERANCE_LOOSE:
            return 0.5
        else:
            # Check if TTL is in a reasonable range (1-255)
            if observed_ttl < 1 or observed_ttl > 255:
                return 0.0
            return 0.2
    
    def calculate_window_score(self, observed: int, expected: int) -> float:
        """
        Score window size match with ratio-based tolerance.
        
        Args:
            observed: Window size observed from target
            expected: Window size from signature
            
        Returns:
            Score from 0.0 to 1.0
        """
        if expected == 0:
            return 1.0
        
        if observed == expected:
            return 1.0
        
        # Calculate ratio (cap at 1.0)
        ratio = min(observed, expected) / max(observed, expected)
        
        if ratio >= self.WINDOW_SIZE_EXACT_RATIO:
            return 1.0
        elif ratio >= self.WINDOW_SIZE_CLOSE_RATIO:
            return 0.8
        elif ratio >= self.WINDOW_SIZE_LOOSE_RATIO:
            return 0.5
        else:
            return 0.2
    
    def calculate_options_score(
        self,
        observed: List[str],
        expected: List[str]
    ) -> float:
        """
        Score TCP options match using Jaccard similarity with order weighting.
        
        Args:
            observed: List of TCP options observed from target
            expected: List of TCP options from signature
            
        Returns:
            Score from 0.0 to 1.0
        """
        if not observed and not expected:
            return 1.0
        
        obs_set = set(observed)
        exp_set = set(expected)
        
        # Calculate Jaccard similarity
        intersection = len(obs_set & exp_set)
        union = len(obs_set | exp_set)
        
        if union == 0:
            return 0.0
        
        jaccard = intersection / union
        
        # Bonus for exact order match
        order_bonus = 0.0
        if observed == expected:
            order_bonus = 0.15
            # Cap at 1.0
            return min(jaccard + order_bonus, 1.0)
        
        # Check if expected options are a subset of observed
        if exp_set.issubset(obs_set):
            # Observed has all expected options
            return min(jaccard + 0.1, 1.0)
        
        return jaccard
    
    def calculate_timing_score(
        self,
        observed_ms: float,
        expected_ms: float
    ) -> float:
        """
        Score response timing match with ratio-based tolerance.
        
        Args:
            observed_ms: Response time observed from target (in milliseconds)
            expected_ms: Response time from signature (in milliseconds)
            
        Returns:
            Score from 0.0 to 1.0
        """
        if expected_ms == 0:
            # Immediate response expected
            if observed_ms < 100:  # Less than 100ms
                return 1.0
            elif observed_ms < 500:
                return 0.7
            else:
                return 0.3
        
        # Calculate ratio
        ratio = observed_ms / expected_ms
        
        if ratio == 0:
            ratio = float('inf')
        
        if 1.0 - self.TIMING_EXACT_RATIO <= ratio <= 1.0 + self.TIMING_EXACT_RATIO:
            return 1.0
        elif 1.0 - self.TIMING_CLOSE_RATIO <= ratio <= 1.0 + self.TIMING_CLOSE_RATIO:
            return 0.7
        elif 1.0 - self.TIMING_LOOSE_RATIO <= ratio <= 1.0 + self.TIMING_LOOSE_RATIO:
            return 0.4
        else:
            return 0.1
    
    def calculate_jitter_score(
        self,
        observed_jitter_ms: float,
        expected_jitter_ms: float
    ) -> float:
        """
        Score jitter consistency match.
        
        Args:
            observed_jitter_ms: Jitter observed from target
            expected_jitter_ms: Jitter from signature
            
        Returns:
            Score from 0.0 to 1.0
        """
        if expected_jitter_ms == 0:
            # Low jitter expected
            if observed_jitter_ms < 1.0:
                return 1.0
            elif observed_jitter_ms < 5.0:
                return 0.7
            else:
                return 0.3
        
        ratio = observed_jitter_ms / expected_jitter_ms
        
        if 0.5 <= ratio <= 2.0:
            return 1.0
        elif 0.2 <= ratio <= 5.0:
            return 0.6
        else:
            return 0.2
    
    def calculate_behavior_score(
        self,
        observed_behavior: Dict[str, Any],
        expected_behavior: Dict[str, Any]
    ) -> float:
        """
        Score behavioral patterns match.
        
        Args:
            observed_behavior: Behavioral characteristics observed
            expected_behavior: Behavioral characteristics from signature
            
        Returns:
            Score from 0.0 to 1.0
        """
        if not expected_behavior:
            return 1.0
        
        if not observed_behavior:
            return 0.5
        
        score = 0.0
        total_weight = 0.0
        
        # Check individual behavioral factors
        factors = {
            'df_flag': 0.2,
            'mss': 0.2,
            'wscale': 0.1,
            'sack_permitted': 0.1,
            'timestamp': 0.1,
            'ip_id_pattern': 0.3
        }
        
        for factor, weight in factors.items():
            if factor in expected_behavior:
                total_weight += weight
                obs_val = observed_behavior.get(factor)
                exp_val = expected_behavior.get(factor)
                
                if obs_val == exp_val:
                    score += weight
                elif isinstance(obs_val, (int, float)) and isinstance(exp_val, (int, float)):
                    # For numeric values, use ratio
                    if exp_val != 0:
                        ratio = min(obs_val, exp_val) / max(obs_val, exp_val)
                        score += weight * ratio
        
        if total_weight > 0:
            return score / total_weight
        return 0.5
    
    def calculate_error_handling_score(
        self,
        observed_errors: Dict[str, Any],
        expected_errors: Dict[str, Any]
    ) -> float:
        """
        Score error response patterns match.
        
        Args:
            observed_errors: Error handling observed from target
            expected_errors: Error handling from signature
            
        Returns:
            Score from 0.0 to 1.0
        """
        if not expected_errors:
            return 1.0
        
        if not observed_errors:
            # No error data available, assume neutral match
            return 0.7
        
        score = 0.0
        factors = {
            'rst_on_closed': 0.3,
            'icmp_unreachable': 0.3,
            'rate_limiting': 0.2,
            'port_unreachable': 0.2
        }
        
        for factor, weight in factors.items():
            if factor in expected_errors:
                obs = observed_errors.get(factor, False)
                exp = expected_errors.get(factor, False)
                if obs == exp:
                    score += weight
        
        return score
    
    def calculate_overall_confidence(
        self,
        fingerprint: Dict[str, Any],
        signature: Dict[str, Any]
    ) -> float:
        """
        Calculate overall confidence score combining all factors.
        
        Args:
            fingerprint: Observed fingerprint data from target
            signature: Known signature to match against
            
        Returns:
            Overall confidence score from 0.0 to 100.0
        """
        score = 0.0
        
        # Extract data from v2 format
        sig_structure = signature.get('structure', signature)
        fp_structure = fingerprint.get('structure', fingerprint)
        
        # D1: TCP Fingerprint scoring
        tcp_syn_ack = sig_structure.get('probe_responses', {}).get('tcp_syn_ack', {})
        obs_tcp = fp_structure.get('probe_responses', {}).get('tcp_syn_ack', {})
        
        if tcp_syn_ack and obs_tcp:
            # TTL score
            ttl_score = self.calculate_ttl_score(
                obs_tcp.get('ttl', 0),
                tcp_syn_ack.get('ttl', 64)
            )
            score += ttl_score * self.factors.ttl_match
            
            # Window size score
            window_score = self.calculate_window_score(
                obs_tcp.get('window_size', 0),
                tcp_syn_ack.get('window_size', 5840)
            )
            score += window_score * self.factors.window_size_match
            
            # Options score
            options_score = self.calculate_options_score(
                obs_tcp.get('options', []),
                tcp_syn_ack.get('options', [])
            )
            score += options_score * self.factors.options_match
        
        # D3: Temporal scoring
        temporal = fp_structure.get('temporal', {})
        temporal_sig = sig_structure.get('temporal', {})
        
        obs_time = temporal.get('response_time_ms', 0)
        exp_time = temporal_sig.get('response_time_ms', 0)
        
        timing_score = self.calculate_timing_score(obs_time, exp_time)
        score += timing_score * self.factors.timing_match
        
        # Jitter scoring
        obs_jitter = temporal.get('jitter_ms', 0)
        exp_jitter = temporal_sig.get('jitter_ms', 0)
        
        jitter_score = self.calculate_jitter_score(obs_jitter, exp_jitter)
        score += jitter_score * self.factors.jitter_match
        
        # Behavioral scoring
        behavioral = fp_structure.get('behavioral', {})
        behavioral_sig = sig_structure.get('behavioral', {})
        
        behavior_score = self.calculate_behavior_score(behavioral, behavioral_sig)
        score += behavior_score * self.factors.behavior_match
        
        # Error handling scoring
        error_obs = fingerprint.get('error_responses', {})
        error_exp = signature.get('error_responses', {})
        
        error_score = self.calculate_error_handling_score(error_obs, error_exp)
        score += error_score * self.factors.error_handling
        
        # Normalize to percentage
        return min(score * 100, 100.0)
    
    def calculate_threshold_flags(self, confidence: float) -> Dict[str, bool]:
        """
        Determine accuracy thresholds based on confidence score.
        
        Args:
            confidence: Confidence score (0.0 - 100.0)
            
        Returns:
            Dictionary of threshold flags
        """
        return {
            'high_confidence': confidence >= self.HIGH_CONFIDENCE_THRESHOLD,
            'medium_confidence': confidence >= self.MEDIUM_CONFIDENCE_THRESHOLD,
            'low_confidence': confidence < self.LOW_CONFIDENCE_THRESHOLD,
            'is_positive_match': confidence >= self.MEDIUM_CONFIDENCE_THRESHOLD
        }
    
    def get_match_quality(self, confidence: float) -> str:
        """
        Get text description of match quality.
        
        Args:
            confidence: Confidence score
            
        Returns:
            Quality description string
        """
        if confidence >= self.HIGH_CONFIDENCE_THRESHOLD:
            return "Excellent"
        elif confidence >= self.MEDIUM_CONFIDENCE_THRESHOLD:
            return "Good"
        elif confidence >= self.LOW_CONFIDENCE_THRESHOLD:
            return "Fair"
        else:
            return "Poor"
    
    def get_recommendations(self, confidence: float) -> List[str]:
        """
        Get recommendations based on confidence level.
        
        Args:
            confidence: Confidence score
            
        Returns:
            List of recommendation strings
        """
        recommendations = []
        
        if confidence >= self.HIGH_CONFIDENCE_THRESHOLD:
            recommendations.append("High confidence match - OS identification reliable")
            recommendations.append("No additional probes needed")
        elif confidence >= self.MEDIUM_CONFIDENCE_THRESHOLD:
            recommendations.append("Good confidence match - results should be accurate")
            recommendations.append("Consider deep probe sequence for verification")
        elif confidence >= self.LOW_CONFIDENCE_THRESHOLD:
            recommendations.append("Fair confidence - results may vary")
            recommendations.append("Use forensic probe sequence for better accuracy")
            recommendations.append("Check for network issues affecting timing")
        else:
            recommendations.append("Low confidence - unreliable match")
            recommendations.append("Run forensic probe sequence")
            recommendations.append("Verify target is responsive")
            recommendations.append("Consider multiple probe attempts")
            recommendations.append("Target may be behind firewall/NAT")
        
        return recommendations
    
    def match_fingerprint(
        self,
        fingerprint: Dict[str, Any],
        signature: Dict[str, Any],
        signature_id: str
    ) -> MatchResult:
        """
        Perform complete fingerprint matching.
        
        Args:
            fingerprint: Observed fingerprint data
            signature: Known signature to match against
            signature_id: Identifier for the signature
            
        Returns:
            MatchResult with confidence and details
        """
        # Calculate overall confidence
        confidence = self.calculate_overall_confidence(fingerprint, signature)
        
        # Get threshold flags
        thresholds = self.calculate_threshold_flags(confidence)
        
        # Get match quality
        quality = self.get_match_quality(confidence)
        
        # Get recommendations
        recommendations = self.get_recommendations(confidence)
        
        return MatchResult(
            signature_id=signature_id,
            confidence=confidence,
            is_positive_match=thresholds['is_positive_match'],
            factor_scores={
                'ttl_match': self.calculate_ttl_score(
                    fingerprint.get('structure', {}).get('probe_responses', {}).get('tcp_syn_ack', {}).get('ttl', 0),
                    signature.get('structure', {}).get('probe_responses', {}).get('tcp_syn_ack', {}).get('ttl', 64)
                ),
                'window_match': self.calculate_window_score(
                    fingerprint.get('structure', {}).get('probe_responses', {}).get('tcp_syn_ack', {}).get('window_size', 0),
                    signature.get('structure', {}).get('probe_responses', {}).get('tcp_syn_ack', {}).get('window_size', 5840)
                ),
                'timing_match': self.calculate_timing_score(
                    fingerprint.get('structure', {}).get('temporal', {}).get('response_time_ms', 0),
                    signature.get('structure', {}).get('temporal', {}).get('response_time_ms', 0)
                )
            },
            match_quality=quality,
            recommendations=recommendations
        )


# Example usage and testing
if __name__ == "__main__":
    # Configure logging
    logging.basicConfig(level=logging.INFO)
    
    print("=== Confidence Scoring Engine Test ===\n")
    
    # Test individual scoring functions
    calc = ConfidenceCalculator()
    
    print("TTL Scoring:")
    print(f"  Exact match (64 vs 64): {calc.calculate_ttl_score(64, 64):.2f}")
    print(f"  Close match (62 vs 64): {calc.calculate_ttl_score(62, 64):.2f}")
    print(f"  Loose match (60 vs 64): {calc.calculate_ttl_score(60, 64):.2f}")
    print(f"  No match (50 vs 64): {calc.calculate_ttl_score(50, 64):.2f}")
    
    print("\nWindow Size Scoring:")
    print(f"  Exact match (65535 vs 65535): {calc.calculate_window_score(65535, 65535):.2f}")
    print(f"  Close match (62345 vs 65535): {calc.calculate_window_score(62345, 65535):.2f}")
    print(f"  Different (4096 vs 65535): {calc.calculate_window_score(4096, 65535):.2f}")
    
    print("\nOptions Scoring:")
    print(f"  Exact match: {calc.calculate_options_score(['MSS', 'WScale', 'SACK', 'Timestamp'], ['MSS', 'WScale', 'SACK', 'Timestamp']):.2f}")
    print(f"  Partial match: {calc.calculate_options_score(['MSS', 'WScale'], ['MSS', 'WScale', 'SACK', 'Timestamp']):.2f}")
    print(f"  No match: {calc.calculate_options_score(['MSS'], ['WScale', 'SACK']):.2f}")
    
    print("\nTiming Scoring:")
    print(f"  Exact timing: {calc.calculate_timing_score(150, 150):.2f}")
    print(f"  Close timing: {calc.calculate_timing_score(180, 150):.2f}")
    print(f"  Loose timing: {calc.calculate_timing_score(250, 150):.2f}")
    
    print("\nThreshold Flags:")
    thresholds = calc.calculate_threshold_flags(95.0)
    print(f"  95% confidence: {thresholds}")
    
    thresholds = calc.calculate_threshold_flags(85.0)
    print(f"  85% confidence: {thresholds}")
    
    thresholds = calc.calculate_threshold_flags(70.0)
    print(f"  70% confidence: {thresholds}")
    
    print("\nMatch Quality:")
    print(f"  99.5%: {calc.get_match_quality(99.5)}")
    print(f"  90%: {calc.get_match_quality(90)}")
    print(f"  75%: {calc.get_match_quality(75)}")
    print(f"  50%: {calc.get_match_quality(50)}")
    
    print("\nRecommendations:")
    recommendations = calc.get_recommendations(95.0)
    for rec in recommendations:
        print(f"  - {rec}")
    
    # Test full fingerprint matching
    print("\n=== Full Fingerprint Match Test ===")
    
    # Sample fingerprint (observed from target)
    fingerprint = {
        "structure": {
            "probe_responses": {
                "tcp_syn_ack": {
                    "ttl": 64,
                    "window_size": 65535,
                    "options": ["MSS", "WScale", "SACK", "Timestamp"],
                    "df_bit": True
                }
            },
            "temporal": {
                "response_time_ms": 150.0,
                "jitter_ms": 0.5,
                "consistency_score": 0.95
            },
            "metadata": {
                "target_os": "Linux",
                "version": "5.x"
            }
        }
    }
    
    # Sample signature
    signature = {
        "structure": {
            "probe_responses": {
                "tcp_syn_ack": {
                    "ttl": 64,
                    "window_size": 65535,
                    "options": ["MSS", "WScale", "SACK", "Timestamp"],
                    "df_bit": True
                }
            },
            "temporal": {
                "response_time_ms": 145.0,
                "jitter_ms": 0.3,
                "consistency_score": 0.9
            },
            "metadata": {
                "target_os": "Linux_5.x",
                "version": "5.4"
            }
        }
    }
    
    result = calc.match_fingerprint(fingerprint, signature, "Linux_5.x")
    print(f"\nMatch Result:")
    print(f"  Signature ID: {result.signature_id}")
    print(f"  Confidence: {result.confidence:.2f}%")
    print(f"  Quality: {result.match_quality}")
    print(f"  Positive Match: {result.is_positive_match}")
    print(f"  Factor Scores: {result.factor_scores}")
