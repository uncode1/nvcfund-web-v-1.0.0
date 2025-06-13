"""
Logging configuration module.

This module provides comprehensive logging configuration for the application.
It supports multiple log levels, formats, and output destinations.
"""

import os
import logging
from logging.handlers import RotatingFileHandler, SysLogHandler
from datetime import datetime
from typing import Dict, Any


class LoggingConfig:
    """
    Logging configuration class.
    
    Args:
        config: Configuration dictionary containing:
            - log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            - log_format: Log message format
            - log_file: Path to log file
            - max_file_size: Maximum log file size in bytes
            - backup_count: Number of backup log files to keep
            - enable_syslog: Whether to enable syslog logging
            - enable_console: Whether to enable console logging
    """
    
    DEFAULT_CONFIG = {
        'log_level': 'INFO',
        'log_format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'log_file': 'nvcfund.log',
        'max_file_size': 10485760,  # 10MB
        'backup_count': 5,
        'enable_syslog': True,
        'enable_console': True
    }
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize logging configuration."""
        self.config = {**self.DEFAULT_CONFIG, **config}
        self._setup_logging()
    
    def _setup_logging(self) -> None:
        """Configure logging handlers and formatters."""
        # Create logger
        logger = logging.getLogger()
        logger.setLevel(self.config['log_level'])
        
        # Create formatter
        formatter = logging.Formatter(self.config['log_format'])
        
        # File handler with rotation
        file_handler = RotatingFileHandler(
            self.config['log_file'],
            maxBytes=self.config['max_file_size'],
            backupCount=self.config['backup_count']
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # Console handler
        if self.config['enable_console']:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            logger.addHandler(console_handler)
        
        # Syslog handler
        if self.config['enable_syslog']:
            syslog_handler = SysLogHandler()
            syslog_handler.setFormatter(formatter)
            logger.addHandler(syslog_handler)
    
    @staticmethod
    def get_module_logger(module_name: str) -> logging.Logger:
        """
        Get a logger instance for a specific module.
        
        Args:
            module_name: Name of the module
            
        Returns:
            Configured logger instance
        """
        return logging.getLogger(module_name)
    
    @staticmethod
    def get_function_logger(function_name: str) -> logging.Logger:
        """
        Get a logger instance for a specific function.
        
        Args:
            function_name: Name of the function
            
        Returns:
            Configured logger instance
        """
        return logging.getLogger(f'function.{function_name}')
    
    @staticmethod
    def get_activity_logger(activity_name: str) -> logging.Logger:
        """
        Get a logger instance for a specific activity.
        
        Args:
            activity_name: Name of the activity
            
        Returns:
            Configured logger instance
        """
        return logging.getLogger(f'activity.{activity_name}')
