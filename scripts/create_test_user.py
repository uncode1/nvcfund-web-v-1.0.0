from src.models.user import User
from werkzeug.security import generate_password_hash
from src.db import db

# Create test user
test_user = User(
    email='test@example.com',
    username='testuser',
    password_hash=generate_password_hash('password123'),
    first_name='Test',
    last_name='User',
    is_active=True,
    is_admin=True,
    role='admin'
)

def create_test_user():
    with db.app.app_context():
        db.session.add(test_user)
        db.session.commit()
        print(f"Created test user: {test_user.email}")
