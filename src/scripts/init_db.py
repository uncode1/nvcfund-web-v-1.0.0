from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models.iam import RoleModel, PermissionModel, RolePermission
from src.services.iam_service import IAMService
from config import config

def init_db():
    """Initialize database and create initial roles"""
    # Create database engine
    engine = create_engine(config['SQLALCHEMY_DATABASE_URI'])
    Session = sessionmaker(bind=engine)
    db = Session()
    
    # Create IAM service
    iam_service = IAMService(db, config)
    
    try:
        # Create initial roles with their permissions
        roles = {
            'super_admin': [
                'system_admin',
                'system_config',
                'user_manage',
                'user_create',
                'user_delete',
                'role_manage',
                'role_create',
                'role_delete',
                'payment_process',
                'payment_approve',
                'payment_reject',
                'transaction_view',
                'transaction_approve',
                'transaction_reject',
                'report_generate',
                'report_view',
                'audit_view',
                'audit_manage'
            ],
            'admin': [
                'user_manage',
                'user_create',
                'user_delete',
                'payment_process',
                'payment_approve',
                'payment_reject',
                'transaction_view',
                'transaction_approve',
                'transaction_reject',
                'report_generate',
                'report_view',
                'audit_view'
            ],
            'developer': [
                'system_config',
                'report_view',
                'audit_view'
            ],
            'user': [
                'payment_process',
                'transaction_view',
                'report_view'
            ]
        }
        
        # Create roles
        for role_name, permissions in roles.items():
            print(f"Creating role: {role_name}")
            iam_service.create_role(
                name=role_name,
                description=f"{role_name.capitalize()} role",
                permissions=permissions
            )
        
        # Create initial super admin user
        print("\nCreating initial super admin user...")
        try:
            # Generate strong password
            import secrets
            import string
            password_chars = string.ascii_letters + string.digits + string.punctuation
            password = ''.join(secrets.choice(password_chars) for _ in range(16))
            
            # Create super admin
            super_admin = iam_service.create_user(
                username='superadmin',
                email='superadmin@example.com',
                password=password,
                role_name='super_admin'
            )
            
            print(f"\nInitial super admin created successfully!")
            print(f"Username: superadmin")
            print(f"Password: {password}")
            print("\nPlease save these credentials securely!")
            
        except Exception as e:
            print(f"\nError creating super admin: {str(e)}")
            
        db.commit()
        print("\nDatabase initialization completed successfully!")
        
    except Exception as e:
        db.rollback()
        print(f"\nError initializing database: {str(e)}")
        
    finally:
        db.close()

if __name__ == '__main__':
    init_db()
