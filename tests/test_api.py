"""
Test suite for API endpoints.
"""

import pytest
from flask import url_for
from config import config
from app_factory import create_app

@pytest.fixture(scope='module')
def app():
    """Create and configure a new app instance for testing."""
    app = create_app('testing')
    app.config['TESTING'] = True
    
    with app.app_context():
        yield app

@pytest.fixture(scope='module')
def client(app):
    """Create a test client for the app."""
    return app.test_client()

def test_health_check(client):
    """Test the health check endpoint."""
    response = client.get(url_for('health.health_check'))
    assert response.status_code == 200
    assert response.json['status'] == 'healthy'

def test_unauthorized_access(client):
    """Test unauthorized access to protected endpoints."""
    response = client.get(url_for('api.protected'))
    assert response.status_code == 401

def test_login(client):
    """Test user login."""
    response = client.post(
        url_for('auth.login'),
        json={'username': 'test', 'password': 'test'}
    )
    assert response.status_code == 200
    assert 'access_token' in response.json

def test_logout(client):
    """Test user logout."""
    # First login to get token
    login_response = client.post(
        url_for('auth.login'),
        json={'username': 'test', 'password': 'test'}
    )
    token = login_response.json['access_token']
    
    # Then logout
    response = client.post(
        url_for('auth.logout'),
        headers={'Authorization': f'Bearer {token}'}
    )
    assert response.status_code == 200

def test_rate_limiting(client):
    """Test rate limiting."""
    # Try to hit a rate-limited endpoint multiple times
    for _ in range(100):
        response = client.get(url_for('api.rate_limited'))
        if response.status_code == 429:  # Too Many Requests
            break
    else:
        pytest.fail("Rate limiting not working")
