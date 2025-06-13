"""
Test configuration and fixtures.
"""

import pytest
import logging
from utils.logging.config import LoggingConfig
from typing import List, Dict, Any, Optional
from datetime import datetime
from utils.audit_logging.audit_logger import AuditLogger
from utils.code_style_checker import CodeStyleChecker

@pytest.fixture(scope='session')
def test_config():
    """Test configuration fixture."""
    return {
        'log_level': 'DEBUG',
        'log_file': 'test.log',
        'max_file_size': 1048576,  # 1MB
        'backup_count': 2,
        'enable_console': True,
        'enable_syslog': False,
        'storage_type': 'file',
        'audit_retention_days': 7,
        'encryption_key': 'test-encryption-key'
    }

@pytest.fixture(scope='session')
def logger(test_config):
    """Logging fixture."""
    config = LoggingConfig(test_config)
    return config.get_module_logger('test')

@pytest.fixture(scope='session')
def audit_logger(test_config):
    """Audit logging fixture."""
    return AuditLogger(test_config)

@pytest.fixture(scope='session')
def code_style_checker(test_config):
    """Code style checker fixture."""
    return CodeStyleChecker(test_config)

@pytest.fixture(autouse=True)
def setup_test_environment():
    """Set up test environment."""
    # Clear test files
    import os
    import shutil
    
    test_dir = 'test_files'
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
    
    os.makedirs(test_dir, exist_ok=True)
    
    yield
    
    # Clean up after tests
    if os.path.exists(test_dir):
        shutil.rmtree(test_dir)
