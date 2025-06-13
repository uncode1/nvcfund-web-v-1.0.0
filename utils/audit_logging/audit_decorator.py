"""
Audit logging decorators for regulatory compliance.

This module provides decorators that automatically log:
1. Critical business operations
2. User actions
3. Financial transactions
4. System changes
5. Security events
"""

import functools
import time
from typing import Callable, Any, Dict
from utils.audit_logging.audit_logger import AuditLogger


class AuditDecorator:
    """
    Audit logging decorator class.
    
    Args:
        audit_logger: Audit logger instance
    """
    
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
    
    def audit_transaction(self, event_type: str) -> Callable:
        """
        Decorator to log financial transactions.
        
        Args:
            event_type: Type of transaction (e.g., 'deposit', 'withdrawal')
            
        Returns:
            Decorated function
        """
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs) -> Any:
                try:
                    # Log transaction start
                    event_id = self.audit_logger.log_audit_event(
                        event_type=event_type,
                        user_id=kwargs.get('user_id'),
                        data={
                            'args': args,
                            'kwargs': kwargs,
                            'status': 'started'
                        }
                    )
                    
                    # Execute transaction
                    result = func(*args, **kwargs)
                    
                    # Log transaction completion
                    self.audit_logger.log_audit_event(
                        event_type=event_type,
                        user_id=kwargs.get('user_id'),
                        data={
                            'result': result,
                            'status': 'completed'
                        },
                        metadata={'event_id': event_id}
                    )
                    
                    return result
                    
                except Exception as e:
                    # Log transaction error
                    self.audit_logger.log_audit_event(
                        event_type=event_type,
                        user_id=kwargs.get('user_id'),
                        data={
                            'error': str(e),
                            'status': 'failed'
                        },
                        metadata={'event_id': event_id}
                    )
                    raise
            
            return wrapper
        
        return decorator
    
    def audit_security(self, event_type: str) -> Callable:
        """
        Decorator to log security events.
        
        Args:
            event_type: Type of security event (e.g., 'login', 'logout')
            
        Returns:
            Decorated function
        """
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs) -> Any:
                try:
                    # Log security event
                    event_id = self.audit_logger.log_audit_event(
                        event_type=event_type,
                        user_id=kwargs.get('user_id'),
                        data={
                            'args': args,
                            'kwargs': kwargs,
                            'status': 'started'
                        }
                    )
                    
                    # Execute security operation
                    result = func(*args, **kwargs)
                    
                    # Log completion
                    self.audit_logger.log_audit_event(
                        event_type=event_type,
                        user_id=kwargs.get('user_id'),
                        data={
                            'result': result,
                            'status': 'completed'
                        },
                        metadata={'event_id': event_id}
                    )
                    
                    return result
                    
                except Exception as e:
                    # Log security failure
                    self.audit_logger.log_audit_event(
                        event_type=event_type,
                        user_id=kwargs.get('user_id'),
                        data={
                            'error': str(e),
                            'status': 'failed'
                        },
                        metadata={'event_id': event_id}
                    )
                    raise
            
            return wrapper
        
        return decorator
    
    def audit_system(self, event_type: str) -> Callable:
        """
        Decorator to log system events.
        
        Args:
            event_type: Type of system event (e.g., 'startup', 'shutdown')
            
        Returns:
            Decorated function
        """
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs) -> Any:
                try:
                    # Log system event
                    event_id = self.audit_logger.log_audit_event(
                        event_type=event_type,
                        data={
                            'args': args,
                            'kwargs': kwargs,
                            'status': 'started'
                        }
                    )
                    
                    # Execute system operation
                    result = func(*args, **kwargs)
                    
                    # Log completion
                    self.audit_logger.log_audit_event(
                        event_type=event_type,
                        data={
                            'result': result,
                            'status': 'completed'
                        },
                        metadata={'event_id': event_id}
                    )
                    
                    return result
                    
                except Exception as e:
                    # Log system error
                    self.audit_logger.log_audit_event(
                        event_type=event_type,
                        data={
                            'error': str(e),
                            'status': 'failed'
                        },
                        metadata={'event_id': event_id}
                    )
                    raise
            
            return wrapper
        
        return decorator
    
    def audit_user_action(self, event_type: str) -> Callable:
        """
        Decorator to log user actions.
        
        Args:
            event_type: Type of user action (e.g., 'deposit', 'withdraw')
            
        Returns:
            Decorated function
        """
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs) -> Any:
                try:
                    # Log user action
                    event_id = self.audit_logger.log_audit_event(
                        event_type=event_type,
                        user_id=kwargs.get('user_id'),
                        data={
                            'args': args,
                            'kwargs': kwargs,
                            'status': 'started'
                        }
                    )
                    
                    # Execute user action
                    result = func(*args, **kwargs)
                    
                    # Log completion
                    self.audit_logger.log_audit_event(
                        event_type=event_type,
                        user_id=kwargs.get('user_id'),
                        data={
                            'result': result,
                            'status': 'completed'
                        },
                        metadata={'event_id': event_id}
                    )
                    
                    return result
                    
                except Exception as e:
                    # Log action failure
                    self.audit_logger.log_audit_event(
                        event_type=event_type,
                        user_id=kwargs.get('user_id'),
                        data={
                            'error': str(e),
                            'status': 'failed'
                        },
                        metadata={'event_id': event_id}
                    )
                    raise
            
            return wrapper
        
        return decorator
