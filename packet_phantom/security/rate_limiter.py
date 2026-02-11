"""
Token Bucket Rate Limiter

A thread-safe token bucket implementation for rate limiting packet sending.

SECURITY FEATURES:
- Thread-safe token operations
- Mode-aware rate limits (EDU vs LIVE)
- Automatic rate capping for educational mode
- Token bucket bursting control

Author: Packet Phantom Team
Version: 2.0.0
"""

import time
import threading
import logging
from typing import Optional

# Setup logging
security_logger = logging.getLogger('security')


# Mode constants for rate limiting
class OperationMode:
    """Operation mode constants for rate limiting."""
    EDUCATIONAL = "edu"
    LIVE = "live"


# Security: Rate limits by mode (prevents DoS attacks)
MAX_RATE_LIVE = 10000  # 10k pkt/s max for LIVE mode
MAX_RATE_EDU = 100     # 100 pkt/s educational cap


def enforce_rate_limit(rate: Optional[int], mode: OperationMode) -> int:
    """
    Enforce rate limit based on operation mode.
    
    SECURITY: Ensures rate cannot exceed mode-specific limits.
    This prevents accidental or intentional DoS attacks.
    
    Args:
        rate: User-specified rate (None means use default)
        mode: Operation mode (EDUCATIONAL or LIVE)
        
    Returns:
        int: Enforced rate limit
    """
    if mode == OperationMode.EDUCATIONAL:
        # EDU mode: Strict cap regardless of user input
        max_rate = MAX_RATE_EDU
        if rate is None:
            security_logger.info(f"EDU mode: using default rate {max_rate} pkt/s")
            return max_rate
        
        if rate > max_rate:
            security_logger.warning(
                f"EDU mode: rate {rate} pkt/s exceeds max {max_rate}, capping"
            )
            return max_rate
        
        return rate
    
    else:  # LIVE mode
        max_rate = MAX_RATE_LIVE
        if rate is None:
            return max_rate
        
        if rate > max_rate:
            security_logger.warning(
                f"LIVE mode: rate {rate} pkt/s exceeds max {max_rate}, capping"
            )
            return max_rate
        
        return rate


class TokenBucket:
    """
    Thread-safe token bucket rate limiter.
    
    SECURITY: Ensures rate limiting cannot be bypassed in multi-threaded
    environments. All operations are atomic and use proper locking.
    
    Attributes:
        rate: Tokens added per second
        capacity: Maximum tokens the bucket can hold
        tokens: Current number of tokens in the bucket
        last_update: Timestamp of last token update
    """
    
    def __init__(self, rate: float = 1000, capacity: float = 1000):
        """
        Initialize token bucket.
        
        Args:
            rate: Tokens added per second
            capacity: Maximum tokens the bucket can hold
        """
        self._rate = rate
        self._capacity = capacity
        self._tokens = capacity
        self._last_update = time.time()
        self._lock = threading.Lock()
    
    @property
    def rate(self) -> float:
        """Get the token refill rate."""
        return self._rate
    
    @property
    def capacity(self) -> float:
        """Get the bucket capacity."""
        return self._capacity
    
    def _add_tokens(self) -> None:
        """Add tokens based on elapsed time (thread-safe)."""
        with self._lock:
            now = time.time()
            elapsed = now - self._last_update
            
            if elapsed > 0:
                new_tokens = elapsed * self._rate
                self._tokens = min(self._capacity, self._tokens + new_tokens)
                self._last_update = now
    
    def consume(self, tokens: float = 1) -> bool:
        """
        Consume tokens from the bucket.
        
        SECURITY: Atomic operation that cannot be interrupted.
        
        Args:
            tokens: Number of tokens to consume
            
        Returns:
            True if tokens were consumed, False if bucket is empty
        """
        with self._lock:
            self._add_tokens()
            
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False
    
    def get_tokens(self) -> float:
        """Get current number of tokens (thread-safe)."""
        with self._lock:
            self._add_tokens()
            return self._tokens
    
    def get_rate(self) -> float:
        """Get the token refill rate."""
        return self._rate
    
    def get_capacity(self) -> float:
        """Get the bucket capacity."""
        return self._capacity
    
    def reset(self) -> None:
        """Reset the bucket to full capacity (thread-safe)."""
        with self._lock:
            self._tokens = self._capacity
            self._last_update = time.time()
    
    def set_rate(self, rate: float) -> None:
        """
        Set a new rate (thread-safe).
        
        Args:
            rate: New tokens per second rate
        """
        with self._lock:
            self._add_tokens()  # Update tokens before rate change
            self._rate = max(0, rate)  # Prevent negative rates
    
    def set_capacity(self, capacity: float) -> None:
        """
        Set a new capacity (thread-safe).
        
        Args:
            capacity: New maximum capacity
        """
        with self._lock:
            self._tokens = min(self._tokens, capacity)
            self._capacity = max(0, capacity)  # Prevent negative capacity
