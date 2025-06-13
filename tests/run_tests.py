"""
Test runner script.

This script runs all tests and generates a detailed report.
"""

import os
import sys
import pytest
import logging
from datetime import datetime
from utils.logging.config import LoggingConfig


def main():
    """Main function to run tests."""
    # Set up test logging
    test_config = {
        'log_level': 'INFO',
        'log_file': f'test_results_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
        'max_file_size': 10485760,  # 10MB
        'backup_count': 5,
        'enable_console': True,
        'enable_syslog': False
    }
    
    # Initialize logger
    logger = LoggingConfig(test_config).get_module_logger('test_runner')
    
    try:
        # Run tests
        logger.info("Starting test suite")
        
        # Get test directory
        test_dir = os.path.dirname(os.path.abspath(__file__))
        
        # Run pytest with detailed output
        pytest.main([
            test_dir,
            '-v',  # Verbose output
            '--tb=short',  # Short traceback
            '--junit-xml=test_results.xml',  # XML report
            '--cov=.',  # Code coverage
            '--cov-report=term-missing'  # Show missing lines
        ])
        
        logger.info("Test suite completed successfully")
        
    except Exception as e:
        logger.error(f"Test suite failed: {str(e)}")
        raise

if __name__ == '__main__':
    main()
