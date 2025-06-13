-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email VARCHAR(120) UNIQUE NOT NULL,
    username VARCHAR(64) UNIQUE,
    password_hash VARCHAR(256) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    phone_number VARCHAR(50),
    is_active BOOLEAN DEFAULT TRUE,
    is_admin BOOLEAN DEFAULT FALSE,
    role VARCHAR(20) DEFAULT 'user',
    api_key VARCHAR(64) UNIQUE,
    ethereum_address VARCHAR(64),
    ethereum_private_key VARCHAR(256),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    organization VARCHAR(150),
    country VARCHAR(100),
    newsletter BOOLEAN DEFAULT FALSE,
    email_verified BOOLEAN DEFAULT FALSE,
    external_customer_id VARCHAR(64),
    external_account_id VARCHAR(64),
    external_account_type VARCHAR(32),
    external_account_currency VARCHAR(3),
    external_account_status VARCHAR(16),
    last_sync DATETIME
);

-- Create security_events table
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type VARCHAR(50) NOT NULL,
    threat_level VARCHAR(20) NOT NULL,
    description VARCHAR(500) NOT NULL,
    details VARCHAR(1000),
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    source_ip VARCHAR(45),
    source_port INTEGER,
    destination_ip VARCHAR(45),
    destination_port INTEGER,
    protocol VARCHAR(10),
    user_id INTEGER,
    module VARCHAR(50),
    function VARCHAR(50),
    status VARCHAR(20) DEFAULT 'active',
    resolved_at DATETIME,
    resolution_notes VARCHAR(500),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Create indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX idx_security_events_user_id ON security_events(user_id);
