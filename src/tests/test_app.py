import os
import pytest
from flask import Flask
from config import config
from app import create_app

@pytest.fixture
def app():
    """Create and configure a new app instance for each test."""
    # Create the app with test config
    app = create_app('testing')
    
    # Create a test client
    with app.app_context():
        yield app

@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()

def test_app_creation(app):
    """Test that the app is created correctly."""
    assert isinstance(app, Flask)
    assert app.config['TESTING'] is True
    assert app.config['DEBUG'] is False

def test_health_check(client):
    """Test the health check endpoint."""
    response = client.get('/health')
    assert response.status_code == 200
    assert response.json == {'status': 'healthy'}

def test_security_headers(client):
    """Test that security headers are properly set."""
    response = client.get('/')
    headers = response.headers
    
    assert 'X-Frame-Options' in headers
    assert 'X-Content-Type-Options' in headers
    assert 'X-XSS-Protection' in headers
    assert 'Content-Security-Policy' in headers
    assert 'Strict-Transport-Security' in headers

def test_rate_limiting(client):
    """Test rate limiting functionality."""
    # This test assumes we have a rate-limited endpoint
    endpoint = '/test-rate-limited'
    
    # Make requests until we hit the limit
    for _ in range(100):
        response = client.get(endpoint)
        if response.status_code == 429:
            break
    
    assert response.status_code == 429
    assert 'Rate limit exceeded' in response.json['message']

def test_payment_processing(client):
    """Test payment processing functionality."""
    payment_data = {
        'amount': 100.00,
        'currency': 'USD',
        'description': 'Test payment'
    }
    
    response = client.post('/api/payments', json=payment_data)
    assert response.status_code == 200
    assert 'transaction_id' in response.json

def test_currency_conversion(client):
    """Test currency conversion functionality."""
    conversion_data = {
        'amount': 1.0,
        'from_currency': 'BTC',
        'to_currency': 'USD'
    }
    
    response = client.post('/api/conversions', json=conversion_data)
    assert response.status_code == 200
    assert 'converted_amount' in response.json
    assert 'rate' in response.json
