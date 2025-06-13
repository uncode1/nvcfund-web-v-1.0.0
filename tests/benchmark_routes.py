#Test/benchmark_routes.py
import time
import requests
import json
from datetime import datetime
import sys
import os

# Add project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src import config, create_app

# List of all API endpoints to test
ENDPOINTS = [
    # Auth endpoints
    {
        'endpoint': '/auth/login',
        'method': 'POST',
        'data': {
            'email': 'test@example.com',
            'password': 'password123'
        }
    },
    {
        'endpoint': '/auth/register',
        'method': 'POST',
        'data': {
            'email': 'test_new@example.com',
            'password': 'password123',
            'first_name': 'Test',
            'last_name': 'User'
        }
    },
    {
        'endpoint': '/auth/me',
        'method': 'GET',
        'auth_required': True
    },
    
    # Account endpoints
    {
        'endpoint': '/accounts',
        'method': 'GET',
        'auth_required': True
    },
    {
        'endpoint': '/accounts/create',
        'method': 'POST',
        'data': {
            'account_type': 'savings',
            'initial_balance': 1000.0
        },
        'auth_required': True
    },
    {
        'endpoint': '/accounts/1',  # Will be replaced with actual account ID
        'method': 'GET',
        'auth_required': True
    }
]

def benchmark_endpoint(endpoint, base_url, token=None):
    """Benchmark a single endpoint."""
    url = f"{base_url}{endpoint['endpoint']}"
    headers = {'Content-Type': 'application/json'}
    
    if 'auth_required' in endpoint and token:
        headers['Authorization'] = f'Bearer {token}'
    
    data = endpoint.get('data', None)
    
    # Measure response time
    start_time = time.time()
    try:
        if endpoint['method'] == 'GET':
            response = requests.get(url, headers=headers)
        else:
            response = requests.post(url, headers=headers, json=data)
        
        response_time = time.time() - start_time
        status_code = response.status_code
        success = 200 <= status_code < 300
        
        return {
            'endpoint': endpoint['endpoint'],
            'method': endpoint['method'],
            'status_code': status_code,
            'response_time': response_time,
            'success': success,
            'error': None if success else response.text
        }
        
    except Exception as e:
        return {
            'endpoint': endpoint['endpoint'],
            'method': endpoint['method'],
            'status_code': None,
            'response_time': time.time() - start_time,
            'success': False,
            'error': str(e)
        }

def main():
    # Create app and get test client
    app = create_app('testing')
    base_url = f"http://{app.config['SERVER_NAME'] or 'localhost'}:{app.config['PORT']}"
    
    # First get a token by logging in
    login_result = benchmark_endpoint({
        'endpoint': '/auth/login',
        'method': 'POST',
        'data': {
            'email': 'test@example.com',
            'password': 'password123'
        }
    }, base_url)
    
    if not login_result['success']:
        print(f"Login failed: {login_result['error']}")
        return
    
    token = login_result['response'].json()['access_token']
    
    # Run benchmarks
    results = []
    for endpoint in ENDPOINTS:
        result = benchmark_endpoint(endpoint, base_url, token)
        results.append(result)
        
        # Print results immediately
        print(f"\nEndpoint: {endpoint['endpoint']}")
        print(f"Method: {endpoint['method']}")
        print(f"Status Code: {result['status_code']}")
        print(f"Response Time: {result['response_time']:.3f}s")
        if not result['success']:
            print(f"Error: {result['error']}")
    
    # Save results to file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    with open(f'benchmark_results_{timestamp}.json', 'w') as f:
        json.dump({
            'timestamp': timestamp,
            'results': results,
            'summary': {
                'total_requests': len(results),
                'successful': sum(1 for r in results if r['success']),
                'failed': sum(1 for r in results if not r['success']),
                'avg_response_time': sum(r['response_time'] for r in results) / len(results)
            }
        }, f, indent=4)

if __name__ == '__main__':
    main()
