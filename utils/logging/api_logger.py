"""
API request/response logging utility.

This module provides tools to log API interactions for monitoring and auditing.
It tracks:
1. Request details (method, URL, headers, body)
2. Response details (status, headers, body)
3. Execution time
4. Error handling
"""

import time
import logging
from typing import Dict, Any, Optional
from utils.logging.config import LoggingConfig


class APILogger:
    """
    API logging class.
    
    Args:
        config: Configuration dictionary
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = LoggingConfig.get_module_logger('api')
    
    def log_request(self, 
                   method: str, 
                   url: str, 
                   headers: Dict[str, str], 
                   body: Optional[Dict[str, Any]] = None) -> None:
        """
        Log API request details.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Request URL
            headers: Request headers
            body: Request body (optional)
        """
        self.logger.info(
            f"API Request: {method} {url}"
            f"\nHeaders: {headers}"
            f"\nBody: {body if body else 'None'}"
        )
    
    def log_response(self, 
                    status_code: int, 
                    headers: Dict[str, str], 
                    body: Dict[str, Any],
                    execution_time: float) -> None:
        """
        Log API response details.
        
        Args:
            status_code: HTTP status code
            headers: Response headers
            body: Response body
            execution_time: Request execution time in seconds
        """
        self.logger.info(
            f"API Response: Status {status_code}"
            f"\nHeaders: {headers}"
            f"\nBody: {body}"
            f"\nExecution time: {execution_time:.4f}s"
        )
    
    def log_error(self, 
                 error: Exception, 
                 method: str, 
                 url: str,
                 request_body: Optional[Dict[str, Any]] = None) -> None:
        """
        Log API error.
        
        Args:
            error: Exception object
            method: HTTP method
            url: Request URL
            request_body: Request body (optional)
        """
        self.logger.error(
            f"API Error: {str(error)}"
            f"\nMethod: {method}"
            f"\nURL: {url}"
            f"\nRequest Body: {request_body if request_body else 'None'}"
        )
    
    def log_performance(self, 
                       method: str, 
                       url: str, 
                       execution_time: float) -> None:
        """
        Log API performance metrics.
        
        Args:
            method: HTTP method
            url: Request URL
            execution_time: Request execution time in seconds
        """
        self.logger.info(
            f"API Performance: {method} {url}"
            f"\nExecution time: {execution_time:.4f}s"
        )
    
    def log_authentication(self, 
                          user_id: str, 
                          success: bool, 
                          method: str) -> None:
        """
        Log authentication attempts.
        
        Args:
            user_id: User identifier
            success: Whether authentication was successful
            method: Authentication method (e.g., JWT, OAuth)
        """
        status = "Success" if success else "Failed"
        self.logger.info(
            f"Authentication {status}: User {user_id}"
            f"\nMethod: {method}"
        )
