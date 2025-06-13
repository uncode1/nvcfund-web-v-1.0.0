"""
Logging decorators for tracking function calls and activities.

This module provides decorators that automatically log:
1. Function calls with arguments and return values
2. Activity execution with timing and status
3. Error handling and exceptions
4. Performance metrics
"""

import functools
import time
import traceback
from typing import Callable, Any, Dict
from utils.logging.config import LoggingConfig


class LoggingDecorator:
    """
    Logging decorator class.
    
    Args:
        config: Logging configuration
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = LoggingConfig.get_module_logger(__name__)
    
    def log_function(self, func: Callable) -> Callable:
        """
        Decorator to log function calls.
        
        Args:
            func: Function to decorate
            
        Returns:
            Decorated function
        """
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # Log function call
            self.logger.info(
                f"Function {func.__name__} called with args: {args}, kwargs: {kwargs}"
            )
            
            # Track execution time
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                
                # Log successful execution
                self.logger.info(
                    f"Function {func.__name__} completed successfully."
                    f" Return value: {result}"
                    f" Execution time: {time.time() - start_time:.4f}s"
                )
                return result
                
            except Exception as e:
                # Log error with traceback
                self.logger.error(
                    f"Error in function {func.__name__}: {str(e)}"
                    f"\nTraceback: {traceback.format_exc()}"
                )
                raise
        
        return wrapper
    
    def log_activity(self, activity_name: str) -> Callable:
        """
        Decorator to log specific activities.
        
        Args:
            activity_name: Name of the activity
            
        Returns:
            Decorated function
        """
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs) -> Any:
                # Get activity logger
                activity_logger = LoggingConfig.get_activity_logger(activity_name)
                
                # Log activity start
                activity_logger.info(f"Starting activity: {activity_name}")
                
                # Track execution time
                start_time = time.time()
                
                try:
                    result = func(*args, **kwargs)
                    
                    # Log activity completion
                    activity_logger.info(
                        f"Completed activity: {activity_name}"
                        f"\nStatus: Success"
                        f"\nExecution time: {time.time() - start_time:.4f}s"
                    )
                    return result
                    
                except Exception as e:
                    # Log activity failure
                    activity_logger.error(
                        f"Activity {activity_name} failed: {str(e)}"
                        f"\nTraceback: {traceback.format_exc()}"
                    )
                    raise
            
            return wrapper
        
        return decorator
    
    def log_performance(self, func: Callable) -> Callable:
        """
        Decorator to log performance metrics.
        
        Args:
            func: Function to decorate
            
        Returns:
            Decorated function
        """
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            # Get performance logger
            perf_logger = LoggingConfig.get_activity_logger('performance')
            
            # Log start
            perf_logger.info(f"Starting performance monitoring for {func.__name__}")
            
            # Track execution time
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                
                # Calculate metrics
                exec_time = time.time() - start_time
                memory_usage = self._get_memory_usage()
                
                # Log performance metrics
                perf_logger.info(
                    f"Performance metrics for {func.__name__}"
                    f"\nExecution time: {exec_time:.4f}s"
                    f"\nMemory usage: {memory_usage:.2f}MB"
                )
                return result
                
            except Exception as e:
                perf_logger.error(
                    f"Performance monitoring failed for {func.__name__}: {str(e)}"
                )
                raise
        
        return wrapper
    
    @staticmethod
    def _get_memory_usage() -> float:
        """Get current memory usage in MB."""
        import psutil
        process = psutil.Process()
        return process.memory_info().rss / 1024 / 1024
