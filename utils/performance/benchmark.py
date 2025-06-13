"""
Performance benchmarking utility.

This module provides tools to benchmark:
1. Function execution time
2. Memory usage
3. Resource consumption
4. Response times
5. Throughput
"""

import time
import logging
import tracemalloc
import gc
from typing import Callable, Any, Dict
from utils.performance.monitor import ResourceMonitor


class PerformanceBenchmark:
    """
    Performance benchmarking class.
    
    Args:
        config: Configuration dictionary containing:
            - sample_interval: Time between samples
            - warmup_time: Time to warm up before benchmark
            - iterations: Number of iterations to run
            - logging_config: Logging configuration
    """
    
    DEFAULT_CONFIG = {
        'sample_interval': 0.1,  # seconds
        'warmup_time': 2.0,  # seconds
        'iterations': 100,
        'logging_config': {
            'level': 'INFO',
            'file': 'benchmark.log'
        }
    }
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize benchmark."""
        self.config = {**self.DEFAULT_CONFIG, **config}
        self.logger = self._setup_logger()
        self.monitor = ResourceMonitor(config)
        self._initialize_metrics()
    
    def _setup_logger(self) -> logging.Logger:
        """Set up logger for benchmarking."""
        logger = logging.getLogger('benchmark')
        logger.setLevel(self.config['logging_config']['level'])
        
        # Create file handler
        handler = logging.FileHandler(self.config['logging_config']['file'])
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def _initialize_metrics(self) -> None:
        """Initialize benchmark metrics."""
        self.metrics = {
            'execution_time': [],
            'memory_usage': [],
            'cpu_usage': [],
            'response_time': [],
            'throughput': []
        }
    
    def benchmark_function(self, func: Callable, *args, **kwargs) -> Dict[str, Any]:
        """
        Benchmark a function's performance.
        
        Args:
            func: Function to benchmark
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Dictionary of performance metrics
        """
        # Warm up
        self.logger.info("Warming up...")
        time.sleep(self.config['warmup_time'])
        
        # Start monitoring
        self.monitor.start_monitoring()
        
        # Start memory tracking
        tracemalloc.start()
        
        # Run iterations
        total_time = 0
        for i in range(self.config['iterations']):
            # Start timing
            start_time = time.perf_counter()
            
            # Run function
            result = func(*args, **kwargs)
            
            # Record time
            end_time = time.perf_counter()
            execution_time = end_time - start_time
            total_time += execution_time
            
            # Record memory
            current, peak = tracemalloc.get_traced_memory()
            memory_usage = current / 1024 / 1024  # Convert to MB
            
            # Record metrics
            self.metrics['execution_time'].append(execution_time)
            self.metrics['memory_usage'].append(memory_usage)
            
            # Force garbage collection
            gc.collect()
            
            # Reset memory tracking
            tracemalloc.reset_peak()
            
        # Stop monitoring
        self.monitor.stop_monitoring()
        
        # Calculate statistics
        avg_time = total_time / self.config['iterations']
        avg_memory = sum(self.metrics['memory_usage']) / len(self.metrics['memory_usage'])
        
        # Get resource metrics
        resource_metrics = self.monitor.get_metrics_summary()
        
        # Log results
        self.logger.info(f"Benchmark results for {func.__name__}:")
        self.logger.info(f"Average execution time: {avg_time:.6f}s")
        self.logger.info(f"Average memory usage: {avg_memory:.2f}MB")
        
        return {
            'function': func.__name__,
            'iterations': self.config['iterations'],
            'avg_execution_time': avg_time,
            'avg_memory_usage': avg_memory,
            'resource_metrics': resource_metrics,
            'metrics': self.metrics
        }
    
    def benchmark_throughput(self, func: Callable, target_throughput: int) -> Dict[str, Any]:
        """
        Benchmark function throughput.
        
        Args:
            func: Function to benchmark
            target_throughput: Target operations per second
            
        Returns:
            Dictionary of throughput metrics
        """
        # Calculate target interval
        target_interval = 1.0 / target_throughput
        
        # Initialize metrics
        total_time = 0
        total_ops = 0
        
        # Start monitoring
        self.monitor.start_monitoring()
        
        # Run until we reach target throughput
        start_time = time.time()
        while time.time() - start_time < 60:  # Run for 60 seconds
            start_op = time.time()
            
            # Run function
            func()
            
            # Record timing
            end_op = time.time()
            op_time = end_op - start_op
            
            # Sleep to maintain target throughput
            sleep_time = target_interval - op_time
            if sleep_time > 0:
                time.sleep(sleep_time)
            
            total_time += op_time
            total_ops += 1
        
        # Calculate throughput
        actual_throughput = total_ops / total_time
        
        # Get resource metrics
        resource_metrics = self.monitor.get_metrics_summary()
        
        # Log results
        self.logger.info(f"Throughput benchmark results:")
        self.logger.info(f"Target throughput: {target_throughput} ops/s")
        self.logger.info(f"Actual throughput: {actual_throughput:.2f} ops/s")
        
        return {
            'target_throughput': target_throughput,
            'actual_throughput': actual_throughput,
            'resource_metrics': resource_metrics
        }
    
    def benchmark_memory(self, func: Callable, *args, **kwargs) -> Dict[str, Any]:
        """
        Benchmark memory usage of a function.
        
        Args:
            func: Function to benchmark
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Dictionary of memory metrics
        """
        # Start memory tracking
        tracemalloc.start()
        
        # Run function
        result = func(*args, **kwargs)
        
        # Get memory stats
        current, peak = tracemalloc.get_traced_memory()
        
        # Stop tracking
        tracemalloc.stop()
        
        # Convert to MB
        current_mb = current / 1024 / 1024
        peak_mb = peak / 1024 / 1024
        
        # Log results
        self.logger.info(f"Memory benchmark results:")
        self.logger.info(f"Current memory usage: {current_mb:.2f}MB")
        self.logger.info(f"Peak memory usage: {peak_mb:.2f}MB")
        
        return {
            'function': func.__name__,
            'current_memory': current_mb,
            'peak_memory': peak_mb,
            'resource_metrics': self.monitor.get_metrics_summary()
        }
    
    def benchmark_response_time(self, func: Callable, *args, **kwargs) -> Dict[str, Any]:
        """
        Benchmark response time of a function.
        
        Args:
            func: Function to benchmark
            *args: Function arguments
            **kwargs: Function keyword arguments
            
        Returns:
            Dictionary of response time metrics
        """
        # Initialize metrics
        response_times = []
        
        # Run iterations
        for _ in range(self.config['iterations']):
            # Start timing
            start_time = time.perf_counter()
            
            # Run function
            result = func(*args, **kwargs)
            
            # Record time
            end_time = time.perf_counter()
            response_time = end_time - start_time
            response_times.append(response_time)
            
            # Force garbage collection
            gc.collect()
        
        # Calculate statistics
        avg_response = sum(response_times) / len(response_times)
        max_response = max(response_times)
        min_response = min(response_times)
        
        # Get resource metrics
        resource_metrics = self.monitor.get_metrics_summary()
        
        # Log results
        self.logger.info(f"Response time benchmark results:")
        self.logger.info(f"Average response time: {avg_response:.6f}s")
        self.logger.info(f"Maximum response time: {max_response:.6f}s")
        self.logger.info(f"Minimum response time: {min_response:.6f}s")
        
        return {
            'function': func.__name__,
            'avg_response': avg_response,
            'max_response': max_response,
            'min_response': min_response,
            'resource_metrics': resource_metrics
        }
