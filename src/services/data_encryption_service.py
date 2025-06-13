"""
Data encryption service for sensitive information with support engineer access.
"""

from typing import Dict, Any, Optional
import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from sqlalchemy import text
from config import config
from security.logging.security_logger import SecurityLogger


class DataEncryptionService:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = SecurityLogger(config)
        self._initialize_keys()
        self._initialize_db_session()

    def _initialize_keys(self) -> None:
        """Initialize encryption keys."""
        # Application master key (stored in environment)
        self.master_key = os.getenv('MASTER_ENCRYPTION_KEY')
        if not self.master_key:
            self.master_key = self._generate_master_key()
            self.logger.log_event(
                SecurityEventType.INFO,
                SecurityEventSeverity.INFO,
                event_type='new_master_key_generated'
            )

        # Generate Fernet key from master key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=os.getenv('ENCRYPTION_SALT', 'default-salt').encode(),
            iterations=100000
        )
        self.fernet_key = base64.urlsafe_b64encode(kdf.derive(self.master_key.encode()))
        self.fernet = Fernet(self.fernet_key)

    def _initialize_db_session(self) -> None:
        """Initialize database session."""
        # Implementation for database session
        pass

    def encrypt_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Encrypt sensitive data fields.
        
        Args:
            data: Dictionary containing sensitive data
        
        Returns:
            Dictionary with encrypted sensitive fields
        """
        encrypted_data = data.copy()
        sensitive_fields = self.config.get('SENSITIVE_FIELDS', [])
        
        for field in sensitive_fields:
            if field in encrypted_data:
                if isinstance(encrypted_data[field], str):
                    encrypted_data[field] = self._encrypt_string(encrypted_data[field])
                elif isinstance(encrypted_data[field], (int, float)):
                    encrypted_data[field] = self._encrypt_number(encrypted_data[field])
                
        return encrypted_data

    def decrypt_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decrypt sensitive data fields.
        
        Args:
            data: Dictionary containing encrypted sensitive data
        
        Returns:
            Dictionary with decrypted sensitive fields
        """
        decrypted_data = data.copy()
        sensitive_fields = self.config.get('SENSITIVE_FIELDS', [])
        
        for field in sensitive_fields:
            if field in decrypted_data:
                if isinstance(decrypted_data[field], str):
                    decrypted_data[field] = self._decrypt_string(decrypted_data[field])
                elif isinstance(decrypted_data[field], (int, float)):
                    decrypted_data[field] = self._decrypt_number(decrypted_data[field])
        
        return decrypted_data

    def _encrypt_string(self, value: str) -> str:
        """Encrypt a string value."""
        try:
            encrypted = self.fernet.encrypt(value.encode())
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='encryption_failed',
                error=str(e)
            )
            raise

    def _decrypt_string(self, value: str) -> str:
        """Decrypt a string value."""
        try:
            encrypted = base64.b64decode(value.encode())
            return self.fernet.decrypt(encrypted).decode()
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='decryption_failed',
                error=str(e)
            )
            raise

    def _encrypt_number(self, value: float) -> str:
        """Encrypt a number value."""
        return self._encrypt_string(str(value))

    def _decrypt_number(self, value: str) -> float:
        """Decrypt a number value."""
        return float(self._decrypt_string(value))

    def generate_support_key(self, engineer_id: str) -> Dict[str, Any]:
        """
        Generate a support engineer-specific key for database access.
        
        Args:
            engineer_id: Unique ID of the support engineer
            
        Returns:
            Dictionary containing support key and metadata
        """
        try:
            # Generate RSA key pair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            public_key = private_key.public_key()
            
            # Export keys
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Store in database with permissions
            self._store_support_key(engineer_id, private_pem, public_pem)
            
            return {
                'engineer_id': engineer_id,
                'public_key': public_pem.decode(),
                'private_key': private_pem.decode(),
                'created_at': datetime.now().isoformat(),
                'permissions': self.config.get('SUPPORT_ENGINEER_PERMISSIONS', [])
            }
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='support_key_generation_failed',
                error=str(e)
            )
            raise

    def _store_support_key(self, engineer_id: str, private_key: bytes, public_key: bytes) -> None:
        """Store support engineer key in database."""
        try:
            # Store in database with permissions
            self.db.execute(text("""
                INSERT INTO support_engineer_keys (engineer_id, private_key, public_key, created_at)
                VALUES (:engineer_id, :private_key, :public_key, CURRENT_TIMESTAMP)
            """), {
                'engineer_id': engineer_id,
                'private_key': private_key,
                'public_key': public_key
            })
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='support_key_storage_failed',
                error=str(e)
            )
            raise

    def validate_support_key(self, engineer_id: str, private_key: str) -> bool:
        """
        Validate support engineer's key.
        
        Args:
            engineer_id: Unique ID of the support engineer
            private_key: Engineer's private key
            
        Returns:
            True if key is valid, False otherwise
        """
        try:
            # Verify key exists in database
            result = self.db.execute(text("""
                SELECT COUNT(*) FROM support_engineer_keys
                WHERE engineer_id = :engineer_id
                AND private_key = :private_key
            """), {
                'engineer_id': engineer_id,
                'private_key': private_key
            }).scalar()
            
            return result > 0
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='support_key_validation_failed',
                error=str(e)
            )
            raise

    def _generate_master_key(self) -> str:
        """Generate a new master encryption key."""
        return base64.urlsafe_b64encode(os.urandom(32)).decode()

    def get_support_engineer_permissions(self, engineer_id: str) -> List[str]:
        """
        Get permissions for a support engineer.
        
        Args:
            engineer_id: Unique ID of the support engineer
            
        Returns:
            List of permissions
        """
        try:
            # Get permissions from database
            result = self.db.execute(text("""
                SELECT permissions FROM support_engineer_keys
                WHERE engineer_id = :engineer_id
            """), {
                'engineer_id': engineer_id
            }).scalar()
            
            return json.loads(result) if result else []
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='permissions_retrieval_failed',
                error=str(e)
            )
            raise
