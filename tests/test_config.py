"""
Test configuration file.

This file contains configuration settings for all test suites.
"""

TEST_CONFIG = {
    'logging': {
        'level': 'DEBUG',
        'file': 'test.log',
        'max_file_size': 1048576,  # 1MB
        'backup_count': 2,
        'enable_console': True,
        'enable_syslog': False,
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    },
    'performance': {
        'sample_interval': 0.1,
        'warmup_time': 2.0,
        'iterations': 100,
        'target_throughput': 1000,
        'warning_thresholds': {
            'cpu': 80.0,
            'memory': 85.0,
            'disk_io': 1000000,
            'network_io': 10000000
        }
    },
    'security': {
        'scan_depth': 10,
        'timeout': 300,
        'max_vulnerabilities': 0,
        'check_types': ['sql', 'xss', 'csrf', 'auth']
    },
    'code_style': {
        'max_line_length': 100,
        'indent_size': 4,
        'tab_width': 4,
        'ignore_patterns': ['__init__.py', 'test_*.py'],
        'fix_on_error': True
    },
    'test_environment': {
        'database': 'test_db',
        'cache': 'test_cache',
        'storage': 'test_storage',
        'cleanup_on_exit': True
    },
    'resource_limits': {
        'max_cpu_percent': 90.0,
        'max_memory_percent': 95.0,
        'max_disk_io': 2000000,
        'max_network_io': 20000000
    },
    'test_timeout': {
        'unit': 30,
        'integration': 60,
        'performance': 120,
        'security': 180,
        'total': 300
    }
}

# Export configuration
CONFIG = TEST_CONFIG
