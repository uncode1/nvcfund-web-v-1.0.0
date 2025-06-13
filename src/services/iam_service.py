from typing import Dict, Any, Optional, List
from datetime import datetime
from sqlalchemy.orm import Session
from models.iam import Role, Permission, RoleModel, PermissionModel, RolePermission
from security.auth.password_strength import PasswordStrengthChecker
from security.logging.security_logger import SecurityLogger

class IAMService:
    def __init__(self, db: Session, config: Dict[str, Any]):
        self.db = db
        self.config = config
        self.logger = SecurityLogger(config)
        self.password_checker = PasswordStrengthChecker(config)
        
    def create_role(self, name: str, description: str, permissions: List[str]) -> RoleModel:
        """Create new role"""
        try:
            # Check if role exists
            existing_role = self.db.query(RoleModel).filter_by(name=name).first()
            if existing_role:
                raise ValueError(f"Role {name} already exists")
                
            # Create role
            role = RoleModel(
                name=name,
                description=description
            )
            
            # Add permissions
            for perm_name in permissions:
                permission = self._get_or_create_permission(perm_name)
                role.permissions.append(permission)
            
            self.db.add(role)
            self.db.commit()
            
            self.logger.log_event(
                SecurityEventType.AUTHORIZATION,
                SecurityEventSeverity.INFO,
                event_type='role_created',
                role_name=name,
                permissions=permissions
            )
            
            return role
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='role_creation_failed',
                error=str(e)
            )
            raise
    
    def update_role(self, role_id: int, permissions: List[str]) -> RoleModel:
        """Update role permissions"""
        try:
            role = self.db.query(RoleModel).get(role_id)
            if not role:
                raise ValueError(f"Role {role_id} not found")
                
            # Clear existing permissions
            role.permissions = []
            
            # Add new permissions
            for perm_name in permissions:
                permission = self._get_or_create_permission(perm_name)
                role.permissions.append(permission)
            
            self.db.commit()
            
            self.logger.log_event(
                SecurityEventType.AUTHORIZATION,
                SecurityEventSeverity.INFO,
                event_type='role_updated',
                role_id=role_id,
                permissions=permissions
            )
            
            return role
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='role_update_failed',
                error=str(e)
            )
            raise
    
    def delete_role(self, role_id: int) -> None:
        """Delete role"""
        try:
            role = self.db.query(RoleModel).get(role_id)
            if not role:
                raise ValueError(f"Role {role_id} not found")
                
            self.db.delete(role)
            self.db.commit()
            
            self.logger.log_event(
                SecurityEventType.AUTHORIZATION,
                SecurityEventSeverity.INFO,
                event_type='role_deleted',
                role_id=role_id
            )
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='role_deletion_failed',
                error=str(e)
            )
            raise
    
    def create_user(self, username: str, email: str, password: str, role_name: str) -> User:
        """Create new user"""
        try:
            # Check if user exists
            existing_user = self.db.query(User).filter_by(username=username).first()
            if existing_user:
                raise ValueError(f"User {username} already exists")
                
            # Validate password
            if not self.password_checker.is_strong(password):
                raise ValueError("Password does not meet security requirements")
                
            # Get role
            role = self.db.query(RoleModel).filter_by(name=role_name).first()
            if not role:
                raise ValueError(f"Role {role_name} not found")
                
            # Create user
            user = User(
                username=username,
                email=email,
                role_id=role.id
            )
            user.set_password(password)
            
            self.db.add(user)
            self.db.commit()
            
            self.logger.log_event(
                SecurityEventType.AUTHENTICATION,
                SecurityEventSeverity.INFO,
                event_type='user_created',
                username=username,
                role=role_name
            )
            
            return user
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='user_creation_failed',
                error=str(e)
            )
            raise
    
    def update_user_role(self, user_id: int, role_name: str) -> User:
        """Update user role"""
        try:
            user = self.db.query(User).get(user_id)
            if not user:
                raise ValueError(f"User {user_id} not found")
                
            role = self.db.query(RoleModel).filter_by(name=role_name).first()
            if not role:
                raise ValueError(f"Role {role_name} not found")
                
            user.role_id = role.id
            self.db.commit()
            
            self.logger.log_event(
                SecurityEventType.AUTHORIZATION,
                SecurityEventSeverity.INFO,
                event_type='user_role_updated',
                user_id=user_id,
                role=role_name
            )
            
            return user
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='user_role_update_failed',
                error=str(e)
            )
            raise
    
    def validate_user_password(self, username: str, password: str) -> User:
        """Validate user password with brute force protection"""
        try:
            user = self.db.query(User).filter_by(username=username).first()
            if not user:
                raise ValueError("Invalid credentials")
                
            # Check password with brute force protection
            if not user.check_password(password):
                raise ValueError("Invalid credentials")
                
            return user
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='password_validation_failed',
                error=str(e)
            )
            raise
    
    def _get_or_create_permission(self, name: str) -> PermissionModel:
        """Get or create permission"""
        permission = self.db.query(PermissionModel).filter_by(name=name).first()
        if not permission:
            permission = PermissionModel(
                name=name,
                description=f"Permission for {name}"
            )
            self.db.add(permission)
            self.db.commit()
        return permission
    
    def get_role_permissions(self, role_name: str) -> List[str]:
        """Get all permissions for a role"""
        role = self.db.query(RoleModel).filter_by(name=role_name).first()
        if role:
            return [perm.name for perm in role.permissions]
        return []
    
    def get_user_permissions(self, username: str) -> List[str]:
        """Get all permissions for a user"""
        user = self.db.query(User).filter_by(username=username).first()
        if user and user.role:
            return [perm.name for perm in user.role.permissions]
        return []
    
    def check_permission(self, username: str, permission: str) -> bool:
        """Check if user has permission"""
        user = self.db.query(User).filter_by(username=username).first()
        if user:
            return user.has_permission(permission)
        return False
