"""
System resource monitoring utility.

This module provides tools to monitor:
1. CPU usage
2. Memory usage
3. Disk I/O
4. Network I/O
5. Process metrics
6. System load
"""

import psutil
import time
import logging
import os
from typing import Dict, Any
from datetime import datetime


class ResourceMonitor:
    """
    Resource monitoring class.
    
    Args:
        config: Configuration dictionary containing:
            - sample_interval: Time between samples (seconds)
            - warning_thresholds: Thresholds for warnings
            - logging_config: Logging configuration
    """
    
    DEFAULT_CONFIG = {
        'sample_interval': 1.0,  # seconds
        'warning_thresholds': {
            'cpu': 80.0,  # %
            'memory': 85.0,  # %
            'disk_io': 1000000,  # bytes/s
            'network_io': 10000000,  # bytes/s
        },
        'logging_config': {
            'level': 'WARNING',
            'file': 'resource_monitor.log'
        }
    }
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize resource monitor."""
        self.config = {**self.DEFAULT_CONFIG, **config}
        self.logger = self._setup_logger()
        self._initialize_metrics()
    
    def _setup_logger(self) -> logging.Logger:
        """Set up logger for resource monitoring."""
        logger = logging.getLogger('resource_monitor')
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
        """Initialize performance metrics."""
        self.metrics = {
            'cpu': [],
            'memory': [],
            'disk_io': [],
            'network_io': [],
            'process': [],
            'system_load': []
        }
        
    def get_cpu_usage(self) -> float:
        """Get current CPU usage percentage."""
        return psutil.cpu_percent(interval=0.1)
    
    def get_memory_usage(self) -> Dict[str, float]:
        """Get memory usage statistics."""
        mem = psutil.virtual_memory()
        return {
            'total': mem.total,
            'used': mem.used,
            'percent': mem.percent
        }
    
    def get_disk_io(self) -> Dict[str, float]:
        """Get disk I/O statistics."""
        io = psutil.disk_io_counters()
        return {
            'read_bytes': io.read_bytes,
            'write_bytes': io.write_bytes,
            'read_time': io.read_time,
            'write_time': io.write_time
        }
    
    def get_network_io(self) -> Dict[str, float]:
        """Get network I/O statistics."""
        net = psutil.net_io_counters()
        return {
            'bytes_sent': net.bytes_sent,
            'bytes_recv': net.bytes_recv,
            'packets_sent': net.packets_sent,
            'packets_recv': net.packets_recv
        }
    
    def get_process_metrics(self) -> Dict[str, Any]:
        """Get process metrics for current process."""
        process = psutil.Process()
        return {
            'cpu_percent': process.cpu_percent(interval=0.1),
            'memory_info': process.memory_info(),
            'num_threads': process.num_threads(),
            'num_fds': process.num_fds()
        }
    
    def get_system_load(self) -> Dict[str, float]:
        """Get system load statistics."""
        return {
            'load1': os.getloadavg()[0],
            'load5': os.getloadavg()[1],
            'load15': os.getloadavg()[2]
        }
    
    def collect_metrics(self) -> Dict[str, Any]:
        """Collect all metrics and store them."""
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'cpu': self.get_cpu_usage(),
            'memory': self.get_memory_usage(),
            'disk_io': self.get_disk_io(),
            'network_io': self.get_network_io(),
            'process': self.get_process_metrics(),
            'system_load': self.get_system_load()
        }
        
        # Store metrics
        for key, value in metrics.items():
            if key in self.metrics:
                self.metrics[key].append(value)
                
                # Keep only last N samples
                max_samples = 100
                if len(self.metrics[key]) > max_samples:
                    self.metrics[key].pop(0)
        
        # Check thresholds
        self._check_thresholds(metrics)
        
        return metrics
    
    def _check_thresholds(self, metrics: Dict[str, Any]) -> None:
        """Check if any metrics exceed thresholds."""
        thresholds = self.config['warning_thresholds']
        
        # CPU threshold
        if metrics['cpu'] > thresholds['cpu']:
            self.logger.warning(
                f"High CPU usage: {metrics['cpu']}% > {thresholds['cpu']}%"
            )
        
        # Memory threshold
        if metrics['memory']['percent'] > thresholds['memory']:
            self.logger.warning(
                f"High memory usage: {metrics['memory']['percent']}% > {thresholds['memory']}%"
            )
        
        # Disk I/O threshold
        if metrics['disk_io']['write_bytes'] > thresholds['disk_io']:
            self.logger.warning(
                f"High disk write: {metrics['disk_io']['write_bytes']} > {thresholds['disk_io']}"
            )
        
        # Network I/O threshold
        total_network = metrics['network_io']['bytes_sent'] + metrics['network_io']['bytes_recv']
        if total_network > thresholds['network_io']:
            self.logger.warning(
                f"High network usage: {total_network} > {thresholds['network_io']}"
            )
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of collected metrics."""
        summary = {}
        
        for metric_type, samples in self.metrics.items():
            if samples:
                summary[metric_type] = {
                    'min': min(samples, key=lambda x: x['value'])['value'],
                    'max': max(samples, key=lambda x: x['value'])['value'],
                    'avg': sum(x['value'] for x in samples) / len(samples),
                    'current': samples[-1]['value']
                }
        
        return summary
    
    def start_monitoring(self) -> None:
        """Start continuous monitoring."""
        while True:
            try:
                metrics = self.collect_metrics()
                time.sleep(self.config['sample_interval'])
            except Exception as e:
                self.logger.error(f"Error in monitoring: {str(e)}")
                time.sleep(1)
