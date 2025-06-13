import os
import sys

# Add project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(project_root)

from src.core.app_factory import create_app
from src.models.user import User
from src.models.security_event import SecurityEvent
from werkzeug.security import generate_password_hash

# Create the application
app = create_app()

# Create database directory if it doesn't exist
os.makedirs('database', exist_ok=True)

# Create tables and add test user
with app.app_context():
    # Create tables
    from src.db import db
    db.create_all()
    
    # Create test user
    test_user = User(
        email='admin_user_1@example.com',
        username='admin_user_test_1',
        password_hash=generate_password_hash('password123'),
        first_name='Test',
        last_name='User',
        is_active=True,
        is_admin=True,
        role='ADMIN'
    )
    
    # Add user to database
    db.session.add(test_user)
    db.session.commit()
    
    print("Database setup complete!")
    print(f"Test user created: {test_user.email}")
