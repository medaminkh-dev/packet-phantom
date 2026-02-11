"""
Performance Optimization Engine for Parallel Probing and Caching
================================================================

This module provides performance optimization components for OS fingerprinting:
- ParallelProbeEngine: Execute probes concurrently with controlled concurrency
- ProbeCache: TTL-based caching for frequently scanned targets
- OptimizedProbeEngine: Extended ProbeEngine with caching and parallel execution

Version: 2.0.0
"""

from __future__ import annotations

import concurrent.futures
from typing import List, Dict, Any, Callable, Optional
import threading
import time
import hashlib
import json
import logging

from cachetools import TTLCache

logger = logging.getLogger(__name__)


class ParallelProbeEngine:
    """Optimized probe engine with parallel execution and intelligent retries."""
    
    def __init__(self, max_workers: int = 4, timeout: float = 5.0):
        """
        Initialize the parallel probe engine.
        
        Args:
            max_workers: Maximum number of concurrent probe workers
            timeout: Default timeout for probe responses
        """
        self.max_workers = max_workers
        self.timeout = timeout
        self._lock = threading.Lock()
        self._stats = {
            'total_probes': 0,
            'successful_probes': 0,
            'failed_probes': 0,
            'total_time': 0.0
        }
    
    def _update_stats(self, success: bool, elapsed: float) -> None:
        """Update engine statistics in a thread-safe manner."""
        with self._lock:
            self._stats['total_probes'] += 1
            if success:
                self._stats['successful_probes'] += 1
            else:
                self._stats['failed_probes'] += 1
            self._stats['total_time'] += elapsed
    
    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        with self._lock:
            total = self._stats['total_probes']
            success = self._stats['successful_probes']
            return {
                'total_probes': total,
                'successful_probes': success,
                'failed_probes': self._stats['failed_probes'],
                'success_rate': success / total if total > 0 else 0,
                'total_time_sec': self._stats['total_time']
            }
    
    def run_parallel_probes(
        self,
        probes: List[Dict[str, Any]],
        send_func: Callable[[Dict], Any],
        max_concurrent: int = None
    ) -> List[Dict[str, Any]]:
        """
        Run probes in parallel with controlled concurrency.
        
        Args:
            probes: List of probe configurations
            send_func: Function to send a single probe
            max_concurrent: Maximum concurrent probes (defaults to max_workers)
            
        Returns:
            List of probe results
        """
        if max_concurrent is None:
            max_concurrent = self.max_workers
        
        results = []
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_concurrent) as executor:
            # Submit all probes
            future_to_probe = {
                executor.submit(send_func, probe): probe 
                for probe in probes
            }
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_probe, timeout=self.timeout):
                probe = future_to_probe[future]
                elapsed = time.time() - start_time
                
                try:
                    result = future.result()
                    result['elapsed_ms'] = elapsed * 1000
                    results.append(result)
                    self._update_stats(result.get('success', False), elapsed)
                except Exception as e:
                    error_result = {
                        'probe': probe.get('name', 'unknown'),
                        'error': str(e),
                        'success': False,
                        'elapsed_ms': elapsed * 1000
                    }
                    results.append(error_result)
                    self._update_stats(False, elapsed)
        
        return results
    
    def run_intelligent_retry(
        self,
        failed_probes: List[Dict],
        send_func: Callable,
        max_retries: int = 3,
        base_delay: float = 1.0
    ) -> List[Dict]:
        """
        Retry failed probes with exponential backoff.
        
        Args:
            failed_probes: List of probes that failed initially
            send_func: Function to send a single probe
            max_retries: Maximum retry attempts
            base_delay: Base delay in seconds for exponential backoff
            
        Returns:
            List of retry results
        """
        results = []
        
        for probe in failed_probes:
            for attempt in range(max_retries):
                wait_time = base_delay * (2 ** attempt)  # Exponential backoff
                time.sleep(wait_time)
                
                try:
                    result = send_func(probe)
                    if result.get('success'):
                        result['retry_attempt'] = attempt + 1
                        results.append(result)
                        break
                    elif attempt == max_retries - 1:
                        results.append({
                            'probe': probe,
                            'error': 'Max retries exceeded',
                            'attempts': max_retries
                        })
                except Exception as e:
                    if attempt == max_retries - 1:
                        results.append({
                            'probe': probe,
                            'error': str(e),
                            'attempts': max_retries
                        })
        
        return results
    
    def run_burst_mode(
        self,
        targets: List[str],
        probe_template: Dict[str, Any],
        send_func: Callable[[str, Dict], Any],
        burst_size: int = 100,
        delay_ms: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Run burst probe mode for quick network scanning.
        
        Args:
            targets: List of target IP addresses
            probe_template: Template for probe configuration
            send_func: Function to send probe to a target
            burst_size: Number of targets to probe simultaneously
            delay_ms: Delay between bursts in milliseconds
            
        Returns:
            List of burst results
        """
        all_results = []
        
        for i in range(0, len(targets), burst_size):
            burst_targets = targets[i:i + burst_size]
            
            # Prepare probes for this burst
            probes = [
                {**probe_template, 'target': target}
                for target in burst_targets
            ]
            
            # Run burst in parallel
            burst_results = self.run_parallel_probes(probes, send_func)
            all_results.extend(burst_results)
            
            # Delay between bursts
            if i + burst_size < len(targets):
                time.sleep(delay_ms / 1000)
        
        return all_results


class ProbeCache:
    """Cache for frequently scanned targets with TTL support."""
    
    def __init__(self, max_size: int = 1000, ttl: int = 3600):
        """
        Initialize the probe cache.
        
        Args:
            max_size: Maximum number of cached entries
            ttl: Time-to-live in seconds (default: 1 hour)
        """
        self.cache = TTLCache(maxsize=max_size, ttl=ttl)
        self._lock = threading.Lock()
        self._stats = {
            'hits': 0,
            'misses': 0,
            'sets': 0,
            'evictions': 0
        }
    
    def _get_cache_key(self, target: str, probe_sequence: str) -> str:
        """
        Generate cache key for target + probe combination.
        
        Args:
            target: Target IP or hostname
            probe_sequence: Name of probe sequence used
            
        Returns:
            MD5 hash key for caching
        """
        key_data = f"{target}:{probe_sequence}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def get(self, target: str, probe_sequence: str) -> Optional[Dict]:
        """
        Get cached result for target.
        
        Args:
            target: Target IP or hostname
            probe_sequence: Name of probe sequence used
            
        Returns:
            Cached result dict or None if not found/expired
        """
        key = self._get_cache_key(target, probe_sequence)
        
        with self._lock:
            result = self.cache.get(key)
            if result is not None:
                self._stats['hits'] += 1
                return result
            else:
                self._stats['misses'] += 1
                return None
    
    def set(self, target: str, probe_sequence: str, result: Dict) -> None:
        """
        Cache probe result.
        
        Args:
            target: Target IP or hostname
            probe_sequence: Name of probe sequence used
            result: Result dictionary to cache
        """
        key = self._get_cache_key(target, probe_sequence)
        
        with self._lock:
            # Check if we're at capacity before setting
            if len(self.cache) >= self.cache.maxsize:
                self._stats['evictions'] += 1
            
            self.cache[key] = result
            self._stats['sets'] += 1
    
    def invalidate(self, target: str) -> int:
        """
        Invalidate all cached results for a target.
        
        Args:
            target: Target IP or hostname prefix
            
        Returns:
            Number of entries invalidated
        """
        count = 0
        
        with self._lock:
            keys_to_remove = [
                key for key in self.cache.keys()
                if key.startswith(target.split('.')[0]) or key.startswith(target)
            ]
            for key in keys_to_remove:
                del self.cache[key]
                count += 1
        
        logger.info(f"Invalidated {count} cache entries for {target}")
        return count
    
    def invalidate_all(self) -> int:
        """
        Invalidate all cached results.
        
        Returns:
            Number of entries invalidated
        """
        with self._lock:
            count = len(self.cache)
            self.cache.clear()
        
        logger.info(f"Invalidated all {count} cache entries")
        return count
    
    def get_stats(self) -> Dict[str, int]:
        """Get cache statistics."""
        with self._lock:
            total = self._stats['hits'] + self._stats['misses']
            return {
                **self._stats,
                'total_requests': total,
                'hit_rate': self._stats['hits'] / total if total > 0 else 0,
                'current_size': len(self.cache)
            }
    
    def get_size(self) -> int:
        """Get current cache size."""
        with self._lock:
            return len(self.cache)


class OptimizedProbeEngine:
    """
    Probe engine with performance optimizations including caching and parallel execution.
    
    This class extends the base ProbeEngine with:
    - Result caching for repeated scans
    - Parallel probe execution
    - Intelligent retry with exponential backoff
    """
    
    def __init__(
        self,
        base_engine,
        use_cache: bool = True,
        cache_ttl: int = 3600,
        max_workers: int = 4,
        timeout: float = 5.0
    ):
        """
        Initialize the optimized probe engine.
        
        Args:
            base_engine: Base ProbeEngine instance
            use_cache: Whether to enable caching
            cache_ttl: Cache TTL in seconds
            max_workers: Maximum parallel workers
            timeout: Default timeout for probes
        """
        # Store base engine attributes
        self.target = base_engine.target
        self.sequence_name = base_engine.sequence_name
        self.sequence = base_engine.sequence
        self.timeout = base_engine.timeout
        self.results = []
        
        # Initialize optimization components
        self.cache = ProbeCache(ttl=cache_ttl) if use_cache else None
        self.parallel_engine = ParallelProbeEngine(max_workers=max_workers, timeout=timeout)
    
    def run_sequence_with_cache(
        self,
        progress_callback: Callable[[int, int, str], None] = None
    ) -> List[Dict[str, Any]]:
        """
        Run probe sequence with caching support.
        
        Args:
            progress_callback: Optional callback for progress updates
            
        Returns:
            List of probe results
        """
        # Check cache first
        if self.cache:
            cached_result = self.cache.get(self.target, self.sequence_name)
            if cached_result is not None:
                logger.info(f"Using cached result for {self.target}")
                return cached_result
        
        # Run sequence using base engine
        if hasattr(self, '_base_run_sequence'):
            results = self._base_run_sequence(progress_callback)
        else:
            # Fallback: run probes sequentially
            results = self._run_sequence_sequential(progress_callback)
        
        # Cache result
        if self.cache:
            self.cache.set(self.target, self.sequence_name, results)
        
        return results
    
    def _run_sequence_sequential(
        self,
        progress_callback: Callable[[int, int, str], None] = None
    ) -> List[Dict[str, Any]]:
        """
        Run probe sequence sequentially (fallback method).
        
        Args:
            progress_callback: Optional callback for progress updates
            
        Returns:
            List of probe results
        """
        from packet_phantom.core.probe_engine import ProbeEngine
        
        engine = ProbeEngine(self.target, self.sequence_name)
        results = engine.run_sequence(progress_callback)
        
        return results
    
    def run_parallel_probe_burst(
        self,
        burst_size: int = 10,
        delay_ms: int = 100
    ) -> List[Dict]:
        """
        Run probe burst in parallel for quick scanning.
        
        Args:
            burst_size: Number of probes to run simultaneously
            delay_ms: Delay between bursts in milliseconds
            
        Returns:
            List of burst results
        """
        from packet_phantom.core.probe_engine import Probe
        
        # Select burst probes from sequence
        burst_probes = self.sequence['probes'][:burst_size]
        
        # Convert to dict format
        probe_dicts = [
            {
                'name': p.name,
                'type': p.probe_type.value if hasattr(p.probe_type, 'value') else str(p.probe_type),
                'port': p.target_port,
                'timeout': p.timeout,
                'payload': p.payload.hex() if p.payload else None
            }
            for p in burst_probes
        ]
        
        def send_probe(probe_dict: Dict) -> Dict:
            """Send a single probe and return result."""
            from packet_phantom.core.probe_engine import ProbeEngine
            
            try:
                engine = ProbeEngine(self.target, self.sequence_name)
                # Find matching probe in sequence
                matching_probe = next(
                    (p for p in self.sequence['probes'] if p.name == probe_dict['name']),
                    None
                )
                if matching_probe:
                    result = engine.run_probe(matching_probe)
                    result['success'] = True
                    return result
                else:
                    return {'probe': probe_dict['name'], 'success': False, 'error': 'Probe not found'}
            except Exception as e:
                return {'probe': probe_dict['name'], 'success': False, 'error': str(e)}
        
        # Run in parallel
        return self.parallel_engine.run_parallel_probes(probe_dicts, send_probe)
    
    def run_optimized_sequence(
        self,
        progress_callback: Callable[[int, int, str], None] = None,
        use_parallel: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Run probe sequence with optimizations.
        
        Args:
            progress_callback: Optional callback for progress updates
            use_parallel: Whether to use parallel execution
            
        Returns:
            List of probe results
        """
        # Try cache first
        if self.cache:
            cached = self.cache.get(self.target, self.sequence_name)
            if cached is not None:
                logger.info(f"Cache hit for {self.target}")
                return cached
        
        if use_parallel and len(self.sequence['probes']) > 1:
            # Run in parallel mode
            results = self._run_parallel(progress_callback)
        else:
            # Run sequentially
            results = self._run_sequence_sequential(progress_callback)
        
        # Cache results
        if self.cache:
            self.cache.set(self.target, self.sequence_name, results)
        
        return results
    
    def _run_parallel(
        self,
        progress_callback: Callable[[int, int, str], None] = None
    ) -> List[Dict[str, Any]]:
        """
        Run probes in parallel.
        
        Args:
            progress_callback: Optional callback for progress updates
            
        Returns:
            List of probe results
        """
        from packet_phantom.core.probe_engine import ProbeEngine
        
        def run_single_probe(probe) -> Dict:
            """Run a single probe."""
            engine = ProbeEngine(self.target, self.sequence_name)
            return engine.run_probe(probe)
        
        # Prepare probe list
        probes = self.sequence['probes']
        total_probes = len(probes)
        
        # Run in parallel
        results = self.parallel_engine.run_parallel_probes(
            [{'name': p.name, 'index': i} for i, p in enumerate(probes)],
            lambda p: run_single_probe(probes[p['index']])
        )
        
        # Report progress
        if progress_callback:
            for i, result in enumerate(results):
                progress_callback(i, total_probes, result.get('probe_name', 'unknown'))
        
        return results
    
    def clear_cache(self) -> None:
        """Clear the probe cache for this engine."""
        if self.cache:
            self.cache.invalidate_all()
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        if self.cache:
            return self.cache.get_stats()
        return {'error': 'Cache not enabled'}
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics."""
        return {
            'cache': self.get_cache_stats(),
            'parallel': self.parallel_engine.get_stats(),
            'target': self.target,
            'sequence': self.sequence_name
        }


# Convenience function to create optimized engine
def create_optimized_engine(
    target: str,
    sequence: str = 'quick',
    use_cache: bool = True,
    max_workers: int = 4,
    timeout: float = 5.0
) -> OptimizedProbeEngine:
    """
    Create an optimized probe engine for a target.
    
    Args:
        target: Target IP or hostname
        sequence: Probe sequence name ('quick', 'deep', 'forensic')
        use_cache: Whether to enable caching
        max_workers: Maximum parallel workers
        timeout: Default timeout for probes
        
    Returns:
        Configured OptimizedProbeEngine instance
    """
    from packet_phantom.core.probe_engine import ProbeEngine
    
    base_engine = ProbeEngine(target, sequence)
    return OptimizedProbeEngine(
        base_engine=base_engine,
        use_cache=use_cache,
        max_workers=max_workers,
        timeout=timeout
    )


# Example usage and testing
if __name__ == "__main__":
    # Test ProbeCache
    print("=== ProbeCache Test ===")
    cache = ProbeCache(max_size=10, ttl=60)
    
    cache.set('192.168.1.1', 'quick', {'result': 'test_data'})
    result = cache.get('192.168.1.1', 'quick')
    print(f"Cache get: {result}")
    
    result = cache.get('192.168.1.1', 'deep')  # Different sequence
    print(f"Cache miss (different sequence): {result}")
    
    cache.invalidate('192.168.1.1')
    result = cache.get('192.168.1.1', 'quick')
    print(f"After invalidate: {result}")
    
    stats = cache.get_stats()
    print(f"Cache stats: {stats}")
    
    # Test ParallelProbeEngine
    print("\n=== ParallelProbeEngine Test ===")
    engine = ParallelProbeEngine(max_workers=4, timeout=5.0)
    
    def mock_send(probe):
        time.sleep(0.1)  # Simulate network delay
        return {'probe': probe['name'], 'success': True, 'response_time_ms': 100}
    
    probes = [{'name': f'probe_{i}'} for i in range(10)]
    results = engine.run_parallel_probes(probes, mock_send)
    print(f"Parallel results: {len(results)} probes completed")
    
    stats = engine.get_stats()
    print(f"Engine stats: {stats}")
    
    print("\n=== OptimizedProbeEngine Test ===")
    from packet_phantom.core.probe_engine import ProbeEngine
    
    base = ProbeEngine('127.0.0.1', 'quick')
    opt_engine = OptimizedProbeEngine(base, use_cache=True, max_workers=2)
    
    print(f"Target: {opt_engine.target}")
    print(f"Sequence: {opt_engine.sequence_name}")
    print(f"Cache enabled: {opt_engine.cache is not None}")
