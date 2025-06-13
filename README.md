# NVC Fund Web4 - Enhanced Banking Platform

[![Python Version](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://python.org)
[![Flask Version](https://img.shields.io/badge/flask-2.3.3-green.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/license-Proprietary-red.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-enhanced-brightgreen.svg)](SECURITY.md)

## 🏦 Overview

NVC Fund Web4 is the next-generation banking platform that consolidates and enhances all features from the original nvcfund-web system. Built with modern architecture, comprehensive security, and scalable design patterns, it provides a complete financial services platform.

## ✨ Key Features

### 🔐 Security First
- **Input Validation**: Comprehensive sanitization and validation
- **Access Control**: Role-based permissions with decorators
- **CSRF Protection**: Built-in cross-site request forgery protection
- **SQL Injection Prevention**: ORM-based database interactions
- **Rate Limiting**: API and route-level rate limiting
- **Audit Logging**: Complete audit trail for all operations

### 💰 Financial Services
- **Multi-Currency Support**: USD, EUR, GBP, NVCT, AFD1, and more
- **Payment Processing**: Multiple gateway integration (Stripe, PayPal)
- **Treasury Management**: Account management, investments, transfers
- **Stablecoin Operations**: NVCT token management and transfers
- **SWIFT Integration**: International wire transfers and messaging
- **Blockchain Support**: Ethereum mainnet and testnet integration

### 🏢 Enterprise Features
- **Payroll Management**: Employee management and salary processing
- **Vendor Management**: Contract and bill management
- **Correspondent Banking**: Global banking partnerships
- **Asset Management**: Portfolio tracking and reporting
- **Compliance Tools**: AML, KYC, and regulatory reporting

## 🚀 Quick Start

### Prerequisites
- Python 3.9 or higher
- PostgreSQL 12+ (recommended) or SQLite for development
- Redis (for caching and sessions)
- Node.js 16+ (for frontend assets)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd nvcfund-web4
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\\Scripts\\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment configuration**
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

5. **Database setup**
   ```bash
   flask db init
   flask db migrate -m "Initial migration"
   flask db upgrade
   ```

6. **Run the application**
   ```bash
   python main.py
   ```

The application will be available at `http://localhost:5000`

## 🏗️ Architecture

### Project Structure
```
nvcfund-web4/
├── src/
│   ├── models/          # Database models
│   ├── routes/          # Route blueprints
│   ├── services/        # Business logic
│   ├── utils/           # Utility functions
│   ├── config/          # Configuration files
│   └── core/            # Core application setup
├── templates/           # Jinja2 templates
├── static/             # Static assets (CSS, JS, images)
├── tests/              # Test suite
├── docs/               # Documentation
└── migrations/         # Database migrations
```

### Key Components

#### Models (`src/models/`)
- **Core Models**: User, Account, Transaction
- **Financial**: FinancialInstitution, PaymentGateway, Asset
- **Treasury**: TreasuryAccount, TreasuryInvestment
- **Stablecoin**: StablecoinAccount, LedgerEntry
- **SWIFT**: SwiftMessage, WireTransfer
- **Payroll**: Employee, PayrollBatch, Vendor

#### Services (`src/services/`)
- **PaymentService**: Secure payment processing
- **TreasuryService**: Treasury operations and management
- **Additional services**: As needed for business logic

#### Routes (`src/routes/`)
- **HTTP Routes**: Web interface routes
- **API Routes**: RESTful API endpoints
- **Blueprint Organization**: Modular route structure

## 🔧 Configuration

### Environment Variables

Create a `.env` file with the following variables:

```bash
# Application
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
DEBUG=True

# Database
DATABASE_URL=postgresql://user:password@localhost/nvcfund_web4

# Security
JWT_SECRET_KEY=your-jwt-secret-here
WTF_CSRF_ENABLED=True

# Payment Gateways
STRIPE_PUBLISHABLE_KEY=pk_test_...
STRIPE_SECRET_KEY=sk_test_...
PAYPAL_CLIENT_ID=your-paypal-client-id
PAYPAL_CLIENT_SECRET=your-paypal-secret

# Blockchain
ETHEREUM_NODE_URL=https://mainnet.infura.io/v3/your-project-id
ETHEREUM_PRIVATE_KEY=your-private-key

# Email
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password

# Redis
REDIS_URL=redis://localhost:6379/0

# Monitoring
SENTRY_DSN=your-sentry-dsn
```

### Configuration Classes

- **DevelopmentConfig**: Local development settings
- **ProductionConfig**: Production-ready configuration
- **TestingConfig**: Test environment settings

## 🧪 Testing

### Running Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src

# Run specific test file
pytest tests/test_payment_service.py

# Run with verbose output
pytest -v
```

### Test Structure
```
tests/
├── unit/               # Unit tests
├── integration/        # Integration tests
├── fixtures/           # Test fixtures
└── conftest.py        # Test configuration
```

## 🔒 Security

### Security Features
- **Authentication**: JWT-based authentication
- **Authorization**: Role-based access control
- **Input Validation**: Comprehensive sanitization
- **CSRF Protection**: Built-in protection
- **Rate Limiting**: API and route protection
- **Audit Logging**: Complete audit trail

### Security Best Practices
1. **Password Security**
   - Strong password requirements
   - Secure password hashing
   - Password reset functionality

2. **Session Management**
   - Secure session handling
   - Session timeout
   - Concurrent session control

3. **API Security**
   - API key authentication
   - Rate limiting
   - Request validation

4. **Data Protection**
   - Encryption at rest
   - Secure communication
   - Data sanitization

## 📚 Documentation

### Developer Documentation
- [API Documentation](docs/api.md)
- [Database Schema](docs/schema.md)
- [Security Guide](docs/security.md)
- [Testing Guide](docs/testing.md)

### User Documentation
- [User Guide](docs/user-guide.md)
- [Admin Guide](docs/admin-guide.md)
- [API Reference](docs/api-reference.md)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is proprietary software. All rights reserved.

## 📞 Support

For support, please contact:
- Email: support@nvcfund.com
- Phone: +1 (555) 123-4567
- Website: https://nvcfund.com/support
