"""
SQL query logging utility.

This module provides tools to log SQL queries for monitoring and auditing.
It tracks:
1. Query execution time
2. Query parameters
3. Query results
4. Database performance metrics
"""

import time
import logging
from typing import Any, Dict, List, Optional
from utils.logging.config import LoggingConfig
from sqlalchemy.engine import Engine
from sqlalchemy import event


class SQLLogger:
    """
    SQL query logging class.
    
    Args:
        config: Configuration dictionary
        engine: SQLAlchemy engine
    """
    
    def __init__(self, config: Dict[str, Any], engine: Engine):
        self.config = config
        self.engine = engine
        self.logger = LoggingConfig.get_module_logger('sql')
        self._setup_event_listeners()
    
    def _setup_event_listeners(self) -> None:
        """Set up SQLAlchemy event listeners."""
        # Log query start
        @event.listens_for(self.engine, "before_cursor_execute")
        def before_cursor_execute(
            conn,
            cursor,
            statement,
            parameters,
            context,
            executemany
        ):
            context._query_start_time = time.time()
            self.logger.info(
                f"SQL Query: {statement}"
                f"\nParameters: {parameters}"
            )
        
        # Log query completion
        @event.listens_for(self.engine, "after_cursor_execute")
        def after_cursor_execute(
            conn,
            cursor,
            statement,
            parameters,
            context,
            executemany
        ):
            total = time.time() - context._query_start_time
            self.logger.info(
                f"Query Complete: {statement}"
                f"\nExecution time: {total:.4f}s"
                f"\nResult: {cursor.rowcount} rows affected"
            )
    
    def log_transaction(self, transaction: Any) -> None:
        """
        Log database transaction.
        
        Args:
            transaction: SQLAlchemy transaction object
        """
        self.logger.info(
            f"Transaction started: {transaction}"
            f"\nIsolation level: {transaction.isolation_level}"
        )
    
    def log_error(self, error: Exception, statement: str, parameters: Dict) -> None:
        """
        Log SQL error.
        
        Args:
            error: Exception object
            statement: SQL statement
            parameters: Query parameters
        """
        self.logger.error(
            f"SQL Error: {str(error)}"
            f"\nQuery: {statement}"
            f"\nParameters: {parameters}"
        )
    
    def log_performance(self, statement: str, execution_time: float) -> None:
        """
        Log SQL performance metrics.
        
        Args:
            statement: SQL statement
            execution_time: Query execution time in seconds
        """
        self.logger.info(
            f"SQL Performance: {statement}"
            f"\nExecution time: {execution_time:.4f}s"
        )
