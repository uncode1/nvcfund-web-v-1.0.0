"""
Test suite for database models.
"""

import pytest
from app_factory import create_app
from extensions import db
from models import User, Role, Permission

@pytest.fixture(scope='module')
def app():
    """Create and configure a new app instance for testing."""
    app = create_app('testing')
    app.config['TESTING'] = True
    
    with app.app_context():
        yield app

@pytest.fixture(scope='function')
def setup_db(app):
    """Set up the database for testing."""
    with app.app_context():
        db.create_all()
        yield
        db.session.remove()
        db.drop_all()

def test_user_creation(setup_db):
    """Test user creation."""
    user = User(username='test', email='test@example.com')
    user.set_password('password')
    db.session.add(user)
    db.session.commit()
    
    assert user in db.session
    assert user.verify_password('password')
    assert not user.verify_password('wrong_password')

def test_role_creation(setup_db):
    """Test role creation."""
    role = Role(name='admin')
    db.session.add(role)
    db.session.commit()
    
    assert role in db.session
    assert role.permissions == []

def test_permission_creation(setup_db):
    """Test permission creation."""
    permission = Permission(name='read')
    db.session.add(permission)
    db.session.commit()
    
    assert permission in db.session

def test_user_role_relationship(setup_db):
    """Test user-role relationship."""
    user = User(username='test', email='test@example.com')
    role = Role(name='admin')
    user.roles.append(role)
    
    db.session.add(user)
    db.session.add(role)
    db.session.commit()
    
    assert user in db.session
    assert role in db.session
    assert role in user.roles

def test_role_permission_relationship(setup_db):
    """Test role-permission relationship."""
    role = Role(name='admin')
    permission = Permission(name='read')
    role.permissions.append(permission)
    
    db.session.add(role)
    db.session.add(permission)
    db.session.commit()
    
    assert role in db.session
    assert permission in db.session
    assert permission in role.permissions
