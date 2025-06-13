"""
Audit logging system for regulatory compliance.

This module provides specialized logging for regulatory compliance that:
1. Minimizes storage overhead
2. Ensures data integrity
3. Maintains audit trails
4. Supports regulatory requirements
"""

import hashlib
import json
import time
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime
import boto3


class AuditLogger:
    """
    Audit logging class for regulatory compliance.
    
    Args:
        config: Configuration dictionary containing:
            - log_level: Minimum log level to record
            - retention_days: Number of days to retain logs
            - storage_type: Type of storage (file, s3, database)
            - encryption_key: Encryption key for sensitive data
            - max_file_size: Maximum size per log file
    """
    
    DEFAULT_CONFIG = {
        'log_level': 'INFO',
        'retention_days': 365,
        'storage_type': 'file',  # file, s3, database
        'encryption_key': None,
        'max_file_size': 1048576,  # 1MB
        'compress_logs': True
    }
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize audit logger."""
        self.config = {**self.DEFAULT_CONFIG, **config}
        self.logger = logging.getLogger('audit')
        self._setup_storage()
        self._setup_compression()
    
    def _setup_storage(self) -> None:
        """Set up appropriate storage based on configuration."""
        if self.config['storage_type'] == 's3':
            self.storage = S3AuditStorage(self.config)
        elif self.config['storage_type'] == 'database':
            self.storage = DatabaseAuditStorage(self.config)
        else:  # default to file
            self.storage = FileAuditStorage(self.config)
    
    def _setup_compression(self) -> None:
        """Set up log compression if enabled."""
        if self.config['compress_logs']:
            self.compressor = LogCompressor()
        else:
            self.compressor = None
    
    def log_audit_event(self, 
                       event_type: str, 
                       user_id: Optional[str] = None, 
                       data: Dict[str, Any] = None,
                       metadata: Dict[str, Any] = None) -> str:
        """
        Log an audit event with minimal overhead.
        
        Args:
            event_type: Type of audit event
            user_id: User identifier (optional)
            data: Event data (optional)
            metadata: Additional metadata (optional)
            
        Returns:
            Audit event ID
        """
        # Create audit record
        audit_record = {
            'event_type': event_type,
            'timestamp': datetime.utcnow().isoformat(),
            'user_id': user_id,
            'data': data or {},
            'metadata': metadata or {},
            'hash': self._calculate_hash(event_type, data)
        }
        
        # Compress if enabled
        if self.compressor:
            compressed_data = self.compressor.compress(audit_record)
            audit_record['compressed'] = True
            audit_record['data'] = compressed_data
        
        # Store audit record
        event_id = self.storage.store_audit_record(audit_record)
        
        return event_id
    
    def _calculate_hash(self, event_type: str, data: Dict[str, Any]) -> str:
        """Calculate hash for data integrity."""
        hash_data = json.dumps({
            'event_type': event_type,
            'data': data,
            'timestamp': datetime.utcnow().isoformat()
        }, sort_keys=True).encode()
        return hashlib.sha256(hash_data).hexdigest()
    
    def get_audit_trail(self, 
                       user_id: str, 
                       start_date: datetime, 
                       end_date: datetime) -> List[Dict[str, Any]]:
        """
        Get audit trail for a user.
        
        Args:
            user_id: User identifier
            start_date: Start date for audit trail
            end_date: End date for audit trail
            
        Returns:
            List of audit records
        """
        return self.storage.get_audit_trail(user_id, start_date, end_date)
    
    def verify_audit_record(self, record_id: str) -> bool:
        """
        Verify the integrity of an audit record.
        
        Args:
            record_id: Audit record ID
            
        Returns:
            True if record is valid, False otherwise
        """
        record = self.storage.get_audit_record(record_id)
        if not record:
            return False
            
        calculated_hash = self._calculate_hash(
            record['event_type'],
            record['data']
        )
        
        return record['hash'] == calculated_hash

class S3AuditStorage:
    """Audit storage implementation using AWS S3."""
    
    def __init__(self, config: Dict[str, Any]):
        self.s3 = boto3.client('s3')
        self.bucket = config.get('s3_bucket', 'nvcfund-audit-logs')
        self.prefix = config.get('s3_prefix', 'audit/')
        
    def store_audit_record(self, record: Dict[str, Any]) -> str:
        """Store audit record in S3."""
        record_id = hashlib.sha256(str(time.time()).encode()).hexdigest()
        key = f"{self.prefix}{record_id}.json"
        
        # Encrypt if key is provided
        if config.get('encryption_key'):
            record = self._encrypt_record(record)
            
        self.s3.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=json.dumps(record),
            ServerSideEncryption='AES256'
        )
        
        return record_id
    
    def get_audit_record(self, record_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve audit record from S3."""
        key = f"{self.prefix}{record_id}.json"
        try:
            obj = self.s3.get_object(Bucket=self.bucket, Key=key)
            record = json.loads(obj['Body'].read().decode())
            return record
        except Exception:
            return None

class DatabaseAuditStorage:
    """Audit storage implementation using database."""
    
    def __init__(self, config: Dict[str, Any]):
        self.db = config['database']
        self._create_tables()
        
    def _create_tables(self) -> None:
        """Create audit tables if they don't exist."""
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS audit_records (
                id VARCHAR(64) PRIMARY KEY,
                event_type VARCHAR(50),
                user_id VARCHAR(50),
                data JSON,
                metadata JSON,
                timestamp TIMESTAMP,
                hash VARCHAR(64),
                compressed BOOLEAN DEFAULT FALSE
            )
        """)
        
    def store_audit_record(self, record: Dict[str, Any]) -> str:
        """Store audit record in database."""
        record_id = hashlib.sha256(str(time.time()).encode()).hexdigest()
        
        self.db.execute("""
            INSERT INTO audit_records (id, event_type, user_id, data, metadata,
                                     timestamp, hash, compressed)
            VALUES (:id, :event_type, :user_id, :data, :metadata,
                   CURRENT_TIMESTAMP, :hash, :compressed)
        """, {
            'id': record_id,
            'event_type': record['event_type'],
            'user_id': record['user_id'],
            'data': json.dumps(record['data']),
            'metadata': json.dumps(record['metadata']),
            'hash': record['hash'],
            'compressed': record.get('compressed', False)
        })
        
        return record_id
    
    def get_audit_record(self, record_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve audit record from database."""
        result = self.db.execute("""
            SELECT * FROM audit_records WHERE id = :id
        """, {'id': record_id}).fetchone()
        
        if result:
            return {
                'id': result.id,
                'event_type': result.event_type,
                'user_id': result.user_id,
                'data': json.loads(result.data),
                'metadata': json.loads(result.metadata),
                'timestamp': result.timestamp,
                'hash': result.hash,
                'compressed': result.compressed
            }
        return None

class FileAuditStorage:
    """Audit storage implementation using local files."""
    
    def __init__(self, config: Dict[str, Any]):
        self.log_dir = config.get('log_dir', 'audit_logs')
        os.makedirs(self.log_dir, exist_ok=True)
        
    def store_audit_record(self, record: Dict[str, Any]) -> str:
        """Store audit record in file."""
        record_id = hashlib.sha256(str(time.time()).encode()).hexdigest()
        filename = os.path.join(self.log_dir, f"{record_id}.json")
        
        with open(filename, 'w') as f:
            json.dump(record, f)
        
        return record_id
    
    def get_audit_record(self, record_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve audit record from file."""
        filename = os.path.join(self.log_dir, f"{record_id}.json")
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except Exception:
            return None
class LogCompressor:
    """Log compression utility."""
    
    def compress(self, data: Dict[str, Any]) -> str:
        """Compress log data."""
        import zlib
        compressed = zlib.compress(json.dumps(data).encode())
        return base64.b64encode(compressed).decode()
    
    def decompress(self, data: str) -> Dict[str, Any]:
        """Decompress log data."""
        import zlib
        compressed = base64.b64decode(data)
        decompressed = zlib.decompress(compressed)
        return json.loads(decompressed.decode())
