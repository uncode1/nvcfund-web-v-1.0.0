"""
Log rotation service for managing log files and storage.
"""

from typing import Dict, Any, Optional, List
import logging
import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from config import config
from src.services.remote_logging_service import RemoteLoggingService
from security.logging.security_logger import SecurityLogger

class LogRotationService:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = SecurityLogger(config)
        self.remote_logging = RemoteLoggingService(config)
        self._initialize_paths()

    def _initialize_paths(self) -> None:
        """Initialize log file paths."""
        self.log_dir = Path(self.config.get('LOG_DIR', '/var/log/nvcfund'))
        self.archive_dir = self.log_dir / 'archive'
        self.current_log = self.log_dir / 'nvcfund.log'
        
        # Create directories if they don't exist
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.archive_dir.mkdir(exist_ok=True)

    def rotate_logs(self) -> None:
        """Rotate logs based on configuration."""
        try:
            # Rotate local logs
            self._rotate_local_logs()
            
            # Rotate remote logs
            self._rotate_remote_logs()
            
            # Clean up old archives
            self._cleanup_old_archives()
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='log_rotation_failed',
                error=str(e)
            )
            raise

    def _rotate_local_logs(self) -> None:
        """Rotate local log files."""
        try:
            # Check if log file exists and is large enough
            if self.current_log.exists() and self.current_log.stat().st_size > self._get_max_size():
                # Create archive filename
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                archive_file = self.archive_dir / f'nvcfund_{timestamp}.log.gz'
                
                # Compress and archive
                with open(self.current_log, 'rb') as f_in:
                    with gzip.open(archive_file, 'wb') as f_out:
                        shutil.copyfileobj(f_in, f_out)
                
                # Create new log file
                self.current_log.unlink()
                self.current_log.touch()
                
                self.logger.log_event(
                    SecurityEventType.INFO,
                    SecurityEventSeverity.INFO,
                    event_type='log_rotation_completed',
                    archive_file=str(archive_file)
                )
                
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='local_log_rotation_failed',
                error=str(e)
            )
            raise

    def _rotate_remote_logs(self) -> None:
        """Rotate remote logs."""
        try:
            # Rotate S3 logs
            self.remote_logging.rotate_logs()
            
            # Rotate database logs
            self._rotate_database_logs()
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='remote_log_rotation_failed',
                error=str(e)
            )
            raise

    def _rotate_database_logs(self) -> None:
        """Rotate database logs."""
        try:
            # Get database session
            db = self.remote_logging.db_client.get_session()
            
            # Get retention period
            retention_days = self.config['LOGGING']['ROTATION']['RETENTION_DAYS']['DATABASE']
            threshold = datetime.now() - timedelta(days=retention_days)
            
            # Delete old logs
            db.query(SecurityLog)\
              .filter(SecurityLog.timestamp < threshold)\
              .delete()
            db.commit()
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='database_log_rotation_failed',
                error=str(e)
            )
            raise

    def _cleanup_old_archives(self) -> None:
        """Clean up old archive files."""
        try:
            # Get retention period
            retention_days = self.config['LOGGING']['ROTATION']['RETENTION_DAYS']['LOCAL']
            threshold = datetime.now() - timedelta(days=retention_days)
            
            # Remove old archives
            for file in self.archive_dir.glob('*.log.gz'):
                if file.stat().st_mtime < threshold.timestamp():
                    file.unlink()
                    
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='archive_cleanup_failed',
                error=str(e)
            )
            raise

    def _get_max_size(self) -> int:
        """Get maximum log file size in bytes."""
        return int(os.getenv('LOG_MAX_SIZE', '104857600'))  # 100MB default

    def get_log_stats(self) -> Dict[str, Any]:
        """Get statistics about log files."""
        try:
            stats = {
                'current_log': {
                    'size': self.current_log.stat().st_size if self.current_log.exists() else 0,
                    'modified': datetime.fromtimestamp(self.current_log.stat().st_mtime).isoformat() if self.current_log.exists() else None
                },
                'archives': {
                    'count': len(list(self.archive_dir.glob('*.log.gz'))),
                    'total_size': sum(f.stat().st_size for f in self.archive_dir.glob('*.log.gz'))
                },
                'remote': {
                    's3': {
                        'enabled': self.config['LOGGING']['S3']['ENABLED'],
                        'bucket': self.config['LOGGING']['S3']['BUCKET']
                    },
                    'database': {
                        'enabled': self.config['LOGGING']['DATABASE']['ENABLED'],
                        'table': self.config['LOGGING']['DATABASE']['TABLE']
                    }
                }
            }
            
            return stats
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='log_stats_failed',
                error=str(e)
            )
            raise
