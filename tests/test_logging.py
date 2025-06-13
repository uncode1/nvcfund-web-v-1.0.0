"""
Test suite for logging system.

This test suite verifies:
1. Logging configuration
2. Log file rotation
3. Log message formatting
4. Multiple log handlers
5. Audit logging
6. Error handling
"""

import os
import logging
import pytest
from datetime import datetime
from utils.logging.config import LoggingConfig
from utils.audit_logging.audit_logger import AuditLogger
from utils.code_style_checker import CodeStyleChecker


class TestLoggingSystem:
    """
    Test class for logging system.
    
    Tests verify:
    - Logging configuration
    - File handlers
    - Console output
    - Audit logging
    - Error handling
    """
    
    def test_logging_config(self, test_config):
        """Test logging configuration."""
        config = LoggingConfig(test_config)
        logger = config.get_module_logger('test')
        
        # Test log levels
        logger.debug('Debug message')
        logger.info('Info message')
        logger.warning('Warning message')
        logger.error('Error message')
        logger.critical('Critical message')
        
        # Verify log file exists
        assert os.path.exists(test_config['log_file'])
        
    def test_log_rotation(self, test_config):
        """Test log file rotation."""
        config = LoggingConfig(test_config)
        logger = config.get_module_logger('test')
        
        # Generate large amount of logs
        for i in range(10000):
            logger.info(f'Test message {i}')
        
        # Verify log rotation
        log_dir = os.path.dirname(test_config['log_file'])
        log_files = [f for f in os.listdir(log_dir) 
                    if f.startswith(os.path.basename(test_config['log_file']))]
        
        assert len(log_files) > 1  # Should have rotated
        
    def test_audit_logging(self, audit_logger):
        """Test audit logging."""
        # Log audit event
        event_id = audit_logger.log_audit_event(
            event_type='test_event',
            user_id='test_user',
            data={'test': 'data'}
        )
        
        # Verify audit record
        record = audit_logger.get_audit_record(event_id)
        assert record['event_type'] == 'test_event'
        assert record['user_id'] == 'test_user'
        assert record['data'] == {'test': 'data'}
        
        # Verify hash integrity
        assert audit_logger.verify_audit_record(event_id)
        
    def test_error_handling(self, logger):
        """Test error logging."""
        try:
            raise ValueError('Test error')
        except Exception as e:
            logger.exception('Test error occurred')
            
        # Verify error is logged
        with open(test_config['log_file'], 'r') as f:
            log_content = f.read()
            assert 'Test error occurred' in log_content
            assert 'ValueError' in log_content
            
    def test_code_style_checker(self, code_style_checker):
        """Test code style checker."""
        # Create test file with issues
        test_file = os.path.join('test_files', 'test_code.py')
        with open(test_file, 'w') as f:
            f.write("""
def test():
    if True:print('Hello')
""")
        
        # Check file
        issues = code_style_checker.check_file(test_file)
        
        # Verify issues found
        assert 'pep8' in issues
        assert len(issues['pep8']) > 0
        
        # Fix issues
        code_style_checker.fix_issues(test_file)
        
        # Verify fixes
        with open(test_file, 'r') as f:
            content = f.read()
            assert 'def test():' in content
            assert '    if True:' in content
            assert '        print' in content
            
    def test_performance(self, logger):
        """Test logging performance."""
        start_time = datetime.now()
        
        # Log 1000 messages
        for i in range(1000):
            logger.info(f'Performance test {i}')
        
        duration = (datetime.now() - start_time).total_seconds()
        assert duration < 1.0  # Should take less than 1 second
        
    def test_security(self, audit_logger):
        """Test security features."""
        # Test encryption
        encrypted_data = audit_logger._encrypt_record({'test': 'data'})
        assert encrypted_data != {'test': 'data'}
        
        # Test hash verification
        record_id = audit_logger.log_audit_event(
            event_type='security_test',
            data={'test': 'data'}
        )
        
        assert audit_logger.verify_audit_record(record_id)
        
    def test_integration(self, logger, audit_logger):
        """Test integration between logging and audit systems."""
        # Log an event
        logger.info('Integration test')
        
        # Audit the event
        event_id = audit_logger.log_audit_event(
            event_type='integration_test',
            data={'log_message': 'Integration test'}
        )
        
        # Verify both systems logged correctly
        with open(test_config['log_file'], 'r') as f:
            log_content = f.read()
            assert 'Integration test' in log_content
            
        audit_record = audit_logger.get_audit_record(event_id)
        assert audit_record['event_type'] == 'integration_test'
        
    def test_large_volume(self, logger, audit_logger):
        """Test handling of large volume of logs."""
        # Generate 10000 log messages
        for i in range(10000):
            logger.info(f'Large volume test {i}')
            
            if i % 100 == 0:
                audit_logger.log_audit_event(
                    event_type='large_volume_test',
                    data={'index': i}
                )
        
        # Verify logs are properly rotated
        log_dir = os.path.dirname(test_config['log_file'])
        log_files = [f for f in os.listdir(log_dir) 
                    if f.startswith(os.path.basename(test_config['log_file']))]
        
        assert len(log_files) > 1  # Should have rotated
        
        # Verify audit records
        audit_records = audit_logger.get_audit_trail(
            user_id=None,
            start_date=datetime.now() - timedelta(days=1),
            end_date=datetime.now()
        )
        
        assert len(audit_records) > 0
