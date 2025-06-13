from datetime import datetime, timedelta
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from security.auth.password_strength import PasswordStrengthChecker
from security.logging.security_logger import SecurityLogger

class Role:
    ADMIN = 'admin'
    SUPER_ADMIN = 'super_admin'
    DEVELOPER = 'developer'
    USER = 'user'

class Permission:
    # System permissions
    SYSTEM_ADMIN = 'system_admin'
    SYSTEM_CONFIG = 'system_config'
    
    # User management
    USER_MANAGE = 'user_manage'
    USER_CREATE = 'user_create'
    USER_DELETE = 'user_delete'
    
    # Role management
    ROLE_MANAGE = 'role_manage'
    ROLE_CREATE = 'role_create'
    ROLE_DELETE = 'role_delete'
    
    # Payment permissions
    PAYMENT_PROCESS = 'payment_process'
    PAYMENT_APPROVE = 'payment_approve'
    PAYMENT_REJECT = 'payment_reject'
    
    # Transaction permissions
    TRANSACTION_VIEW = 'transaction_view'
    TRANSACTION_APPROVE = 'transaction_approve'
    TRANSACTION_REJECT = 'transaction_reject'
    
    # Report permissions
    REPORT_GENERATE = 'report_generate'
    REPORT_VIEW = 'report_view'
    
    # Audit permissions
    AUDIT_VIEW = 'audit_view'
    AUDIT_MANAGE = 'audit_manage'

class RoleModel(BaseModel):
    __tablename__ = 'roles'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)
    description = Column(String(200))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    permissions = relationship('PermissionModel', secondary='role_permissions', back_populates='roles')
    users = relationship('User', back_populates='role')

class PermissionModel(BaseModel):
    __tablename__ = 'permissions'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)
    description = Column(String(200))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    roles = relationship('RoleModel', secondary='role_permissions', back_populates='permissions')

class RolePermission(BaseModel):
    __tablename__ = 'role_permissions'
    
    role_id = Column(Integer, ForeignKey('roles.id'), primary_key=True)
    permission_id = Column(Integer, ForeignKey('permissions.id'), primary_key=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class User(BaseModel):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    role_id = Column(Integer, ForeignKey('roles.id'))
    is_active = Column(Boolean, default=True)
    last_login = Column(DateTime)
    failed_login_attempts = Column(Integer, default=0)
    last_failed_login = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    role = relationship('RoleModel', back_populates='users')
    sessions = relationship('Session', back_populates='user')
    
    def set_password(self, password: str) -> None:
        """Set user password with strength checking"""
        checker = PasswordStrengthChecker()
        if not checker.is_strong(password):
            raise ValueError("Password does not meet security requirements")
            
        self.password_hash = generate_password_hash(password)
        self.failed_login_attempts = 0
        self.last_failed_login = None
    
    def check_password(self, password: str) -> bool:
        """Check user password with brute force protection"""
        if self.failed_login_attempts >= 5:
            if datetime.utcnow() - self.last_failed_login < timedelta(minutes=30):
                raise ValueError("Account locked due to too many failed attempts")
            
        if check_password_hash(self.password_hash, password):
            self.failed_login_attempts = 0
            return True
            
        self.failed_login_attempts += 1
        self.last_failed_login = datetime.utcnow()
        return False
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has permission"""
        if not self.role:
            return False
            
        return any(
            perm.name == permission 
            for perm in self.role.permissions
        )
    
    def get_role_permissions(self) -> List[str]:
        """Get all permissions for user's role"""
        return [perm.name for perm in self.role.permissions]
    
    def lock_account(self) -> None:
        """Lock user account"""
        self.is_active = False
        self.failed_login_attempts = 0
    
    def unlock_account(self) -> None:
        """Unlock user account"""
        self.is_active = True
        self.failed_login_attempts = 0
