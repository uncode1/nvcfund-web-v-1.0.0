"""
Performance test script.

This script runs comprehensive performance benchmarks including:
1. Function execution time
2. Memory usage
3. Resource consumption
4. Response times
5. Throughput
"""

import pytest
import logging
from utils.performance.benchmark import PerformanceBenchmark
from utils.performance.monitor import ResourceMonitor
from utils.logging.config import LoggingConfig


class TestPerformance:
    """
    Performance test class.
    
    Tests verify:
    - Function execution time
    - Memory usage
    - Resource consumption
    - Response times
    - Throughput
    """
    
    def setup_class(cls):
        """Set up class-level fixtures."""
        cls.config = {
            'sample_interval': 0.1,
            'warmup_time': 2.0,
            'iterations': 100,
            'logging_config': {
                'level': 'INFO',
                'file': 'performance_test.log'
            },
            'warning_thresholds': {
                'cpu': 80.0,
                'memory': 85.0,
                'disk_io': 1000000,
                'network_io': 10000000
            }
        }
        
        cls.benchmark = PerformanceBenchmark(cls.config)
        cls.monitor = ResourceMonitor(cls.config)
        
    def test_logging_performance(self):
        """Test logging performance."""
        # Initialize logger
        logger = LoggingConfig(self.config).get_module_logger('test')
        
        # Benchmark logging
        result = self.benchmark.benchmark_function(
            logger.info,
            "Test log message"
        )
        
        # Verify performance
        assert result['avg_execution_time'] < 0.001  # Should be less than 1ms
        assert result['avg_memory_usage'] < 1.0  # Should be less than 1MB
        
        # Check resource usage
        metrics = result['resource_metrics']
        assert metrics['cpu']['avg'] < 50.0  # CPU usage should be reasonable
        assert metrics['memory']['avg'] < 85.0  # Memory usage should be reasonable
        
    def test_audit_logging_performance(self):
        """Test audit logging performance."""
        from utils.audit_logging.audit_logger import AuditLogger
        
        # Initialize audit logger
        audit_logger = AuditLogger(self.config)
        
        # Benchmark audit logging
        result = self.benchmark.benchmark_function(
            audit_logger.log_audit_event,
            event_type='test_event',
            user_id='test_user',
            data={'test': 'data'}
        )
        
        # Verify performance
        assert result['avg_execution_time'] < 0.01  # Should be less than 10ms
        assert result['avg_memory_usage'] < 2.0  # Should be less than 2MB
        
        # Check resource usage
        metrics = result['resource_metrics']
        assert metrics['cpu']['avg'] < 50.0
        assert metrics['memory']['avg'] < 85.0
        
    def test_code_style_checking_performance(self):
        """Test code style checking performance."""
        from utils.code_style_checker import CodeStyleChecker
        
        # Initialize checker
        checker = CodeStyleChecker(self.config)
        
        # Create test file
        test_file = 'test_files/test_code.py'
        with open(test_file, 'w') as f:
            f.write("""
def test_function():
    print('Hello')
""")
        
        # Benchmark code style checking
        result = self.benchmark.benchmark_function(
            checker.check_file,
            test_file
        )
        
        # Verify performance
        assert result['avg_execution_time'] < 0.1  # Should be less than 100ms
        assert result['avg_memory_usage'] < 10.0  # Should be less than 10MB
        
        # Check resource usage
        metrics = result['resource_metrics']
        assert metrics['cpu']['avg'] < 50.0
        assert metrics['memory']['avg'] < 85.0
        
    def test_large_volume_performance(self):
        """Test performance with large volume of operations."""
        # Benchmark with high throughput
        result = self.benchmark.benchmark_throughput(
            lambda: logging.info("Test message"),
            target_throughput=1000  # Try to achieve 1000 ops/s
        )
        
        # Verify throughput
        assert result['actual_throughput'] > 500  # Should achieve at least 500 ops/s
        
        # Check resource usage
        metrics = result['resource_metrics']
        assert metrics['cpu']['avg'] < 70.0
        assert metrics['memory']['avg'] < 85.0
        
    def test_memory_usage(self):
        """Test memory usage."""
        # Benchmark memory usage
        result = self.benchmark.benchmark_memory(
            lambda: logging.info("Test message"),
            "Test message"
        )
        
        # Verify memory usage
        assert result['current_memory'] < 1.0  # Should be less than 1MB
        assert result['peak_memory'] < 2.0  # Peak should be less than 2MB
        
    def test_response_time(self):
        """Test response time."""
        # Benchmark response time
        result = self.benchmark.benchmark_response_time(
            lambda: logging.info("Test message"),
            "Test message"
        )
        
        # Verify response times
        assert result['avg_response'] < 0.001  # Should be less than 1ms
        assert result['max_response'] < 0.01  # Maximum should be less than 10ms
        
    def test_resource_limits(self):
        """Test resource usage limits."""
        # Run operations to check resource limits
        for _ in range(1000):
            logging.info("Test message")
            
        # Check resource usage
        metrics = self.monitor.get_metrics_summary()
        
        # Verify limits
        assert metrics['cpu']['max'] < 80.0  # CPU shouldn't exceed 80%
        assert metrics['memory']['max'] < 85.0  # Memory shouldn't exceed 85%
        assert metrics['disk_io']['max'] < 1000000  # Disk IO shouldn't exceed 1MB/s
        assert metrics['network_io']['max'] < 10000000  # Network IO shouldn't exceed 10MB/s

if __name__ == '__main__':
    pytest.main(['-v', __file__])
