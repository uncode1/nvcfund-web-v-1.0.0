"""
Partner Integration Models

This module provides flexible models for external partner integration including:
- Dynamic partner configuration
- API endpoint management
- Authentication settings
- Data mapping and transformation
- Webhook management
- Rate limiting configuration
- Audit trails and monitoring
"""

import json
from datetime import datetime
from enum import Enum as PyEnum
from typing import Dict, Any, Optional

from .base import (
    db, BaseModel, Column, String, Boolean, DateTime, Integer, 
    Enum as SAEnum, relationship, Float, ForeignKey, Text
)


class PartnerType(PyEnum):
    """Types of external partners."""
    PAYMENT_PROCESSOR = "payment_processor"
    BANK = "bank"
    FINTECH = "fintech"
    EXCHANGE = "exchange"
    COMPLIANCE_PROVIDER = "compliance_provider"
    DATA_PROVIDER = "data_provider"
    BLOCKCHAIN_SERVICE = "blockchain_service"
    IDENTITY_PROVIDER = "identity_provider"
    NOTIFICATION_SERVICE = "notification_service"
    ANALYTICS_PROVIDER = "analytics_provider"
    GOVERNMENT_AGENCY = "government_agency"
    REGULATORY_BODY = "regulatory_body"
    CREDIT_BUREAU = "credit_bureau"
    INSURANCE_PROVIDER = "insurance_provider"


class IntegrationMethod(PyEnum):
    """Integration methods supported."""
    REST_API = "rest_api"
    SOAP_API = "soap_api"
    GRAPHQL = "graphql"
    WEBHOOK = "webhook"
    FTP = "ftp"
    SFTP = "sftp"
    MESSAGE_QUEUE = "message_queue"
    DATABASE_DIRECT = "database_direct"
    FILE_TRANSFER = "file_transfer"
    EMAIL = "email"
    SMS = "sms"


class AuthenticationType(PyEnum):
    """Authentication types for partner APIs."""
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    JWT = "jwt"
    BASIC_AUTH = "basic_auth"
    MUTUAL_TLS = "mutual_tls"
    HMAC_SIGNATURE = "hmac_signature"
    BEARER_TOKEN = "bearer_token"
    CUSTOM = "custom"
    NONE = "none"


class DataFormat(PyEnum):
    """Data formats for partner communication."""
    JSON = "json"
    XML = "xml"
    CSV = "csv"
    FIXED_WIDTH = "fixed_width"
    DELIMITED = "delimited"
    BINARY = "binary"
    FORM_ENCODED = "form_encoded"
    MULTIPART = "multipart"
    CUSTOM = "custom"


class PartnerStatus(PyEnum):
    """Partner status enumeration."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING_APPROVAL = "pending_approval"
    TESTING = "testing"
    DEPRECATED = "deprecated"


class Partner(BaseModel):
    """
    Main partner model for external integrations.
    
    This model stores comprehensive partner information including
    configuration, authentication, and business rules.
    """
    
    __tablename__ = 'partners'
    
    # Basic Information
    partner_id = Column(String(64), unique=True, nullable=False, index=True)
    name = Column(String(256), nullable=False)
    display_name = Column(String(256))
    description = Column(Text)
    partner_type = Column(SAEnum(PartnerType), nullable=False)
    status = Column(SAEnum(PartnerStatus), default=PartnerStatus.PENDING_APPROVAL)
    
    # Contact Information
    contact_name = Column(String(256))
    contact_email = Column(String(256))
    contact_phone = Column(String(50))
    website = Column(String(512))
    
    # Integration Configuration
    integration_method = Column(SAEnum(IntegrationMethod), nullable=False)
    base_url = Column(String(512))
    api_version = Column(String(32))
    data_format = Column(SAEnum(DataFormat), default=DataFormat.JSON)
    
    # Authentication
    authentication_type = Column(SAEnum(AuthenticationType), nullable=False)
    api_key_encrypted = Column(Text)  # Encrypted API key
    client_id = Column(String(256))
    client_secret_encrypted = Column(Text)  # Encrypted client secret
    oauth_token_url = Column(String(512))
    oauth_scope = Column(String(512))
    certificate_path = Column(String(512))
    private_key_path = Column(String(512))
    
    # Rate Limiting
    rate_limit_requests = Column(Integer, default=100)  # requests per minute
    rate_limit_window = Column(Integer, default=60)  # seconds
    timeout_seconds = Column(Integer, default=30)
    retry_attempts = Column(Integer, default=3)
    retry_delay_seconds = Column(Integer, default=5)
    
    # Webhook Configuration
    webhook_url = Column(String(512))
    webhook_secret_encrypted = Column(Text)  # Encrypted webhook secret
    webhook_events = Column(Text)  # JSON array of subscribed events
    
    # Business Configuration
    custom_headers = Column(Text)  # JSON object of custom headers
    field_mappings = Column(Text)  # JSON object for field mapping
    business_rules = Column(Text)  # JSON object for business rules
    compliance_settings = Column(Text)  # JSON object for compliance settings
    
    # Monitoring and Limits
    daily_transaction_limit = Column(Float)
    monthly_transaction_limit = Column(Float)
    single_transaction_limit = Column(Float)
    supported_currencies = Column(Text)  # JSON array of currency codes
    supported_countries = Column(Text)  # JSON array of country codes
    
    # Operational Settings
    is_sandbox = Column(Boolean, default=True)
    is_active = Column(Boolean, default=False)
    auto_retry_enabled = Column(Boolean, default=True)
    notification_enabled = Column(Boolean, default=True)
    logging_enabled = Column(Boolean, default=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_sync_at = Column(DateTime)
    approved_at = Column(DateTime)
    suspended_at = Column(DateTime)
    
    # Relationships
    endpoints = relationship('PartnerEndpoint', back_populates='partner', cascade='all, delete-orphan')
    api_calls = relationship('PartnerAPICall', back_populates='partner')
    webhooks = relationship('PartnerWebhook', back_populates='partner')
    
    def get_custom_headers(self) -> Dict[str, str]:
        """Get custom headers as dictionary."""
        try:
            return json.loads(self.custom_headers) if self.custom_headers else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    
    def set_custom_headers(self, headers: Dict[str, str]):
        """Set custom headers from dictionary."""
        self.custom_headers = json.dumps(headers) if headers else None
    
    def get_field_mappings(self) -> Dict[str, str]:
        """Get field mappings as dictionary."""
        try:
            return json.loads(self.field_mappings) if self.field_mappings else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    
    def set_field_mappings(self, mappings: Dict[str, str]):
        """Set field mappings from dictionary."""
        self.field_mappings = json.dumps(mappings) if mappings else None
    
    def get_business_rules(self) -> Dict[str, Any]:
        """Get business rules as dictionary."""
        try:
            return json.loads(self.business_rules) if self.business_rules else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    
    def set_business_rules(self, rules: Dict[str, Any]):
        """Set business rules from dictionary."""
        self.business_rules = json.dumps(rules) if rules else None
    
    def get_supported_currencies(self) -> list:
        """Get supported currencies as list."""
        try:
            return json.loads(self.supported_currencies) if self.supported_currencies else []
        except (json.JSONDecodeError, TypeError):
            return []
    
    def set_supported_currencies(self, currencies: list):
        """Set supported currencies from list."""
        self.supported_currencies = json.dumps(currencies) if currencies else None
    
    def get_webhook_events(self) -> list:
        """Get webhook events as list."""
        try:
            return json.loads(self.webhook_events) if self.webhook_events else []
        except (json.JSONDecodeError, TypeError):
            return []
    
    def set_webhook_events(self, events: list):
        """Set webhook events from list."""
        self.webhook_events = json.dumps(events) if events else None
    
    def __repr__(self):
        return f'<Partner {self.partner_id}: {self.name}>'


class PartnerEndpoint(BaseModel):
    """
    Partner API endpoint configuration.
    
    This model stores specific endpoint configurations for each partner,
    allowing for flexible API integration.
    """
    
    __tablename__ = 'partner_endpoints'
    
    partner_id = Column(Integer, ForeignKey('partners.id'), nullable=False)
    endpoint_name = Column(String(128), nullable=False)  # e.g., 'create_payment', 'get_balance'
    endpoint_path = Column(String(512), nullable=False)  # e.g., '/api/v1/payments'
    http_method = Column(String(16), nullable=False)  # GET, POST, PUT, DELETE
    description = Column(Text)
    
    # Request Configuration
    request_format = Column(SAEnum(DataFormat), default=DataFormat.JSON)
    required_fields = Column(Text)  # JSON array of required field names
    optional_fields = Column(Text)  # JSON array of optional field names
    request_template = Column(Text)  # JSON template for request body
    
    # Response Configuration
    response_format = Column(SAEnum(DataFormat), default=DataFormat.JSON)
    response_mapping = Column(Text)  # JSON object for response field mapping
    success_indicators = Column(Text)  # JSON object defining success conditions
    error_indicators = Column(Text)  # JSON object defining error conditions
    
    # Endpoint-specific Settings
    timeout_seconds = Column(Integer)  # Override partner default
    retry_attempts = Column(Integer)  # Override partner default
    rate_limit_override = Column(Integer)  # Override partner rate limit
    requires_authentication = Column(Boolean, default=True)
    is_idempotent = Column(Boolean, default=False)
    
    # Monitoring
    is_active = Column(Boolean, default=True)
    last_used_at = Column(DateTime)
    success_count = Column(Integer, default=0)
    error_count = Column(Integer, default=0)
    average_response_time = Column(Float)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    partner = relationship('Partner', back_populates='endpoints')
    
    def get_required_fields(self) -> list:
        """Get required fields as list."""
        try:
            return json.loads(self.required_fields) if self.required_fields else []
        except (json.JSONDecodeError, TypeError):
            return []
    
    def get_optional_fields(self) -> list:
        """Get optional fields as list."""
        try:
            return json.loads(self.optional_fields) if self.optional_fields else []
        except (json.JSONDecodeError, TypeError):
            return []
    
    def get_request_template(self) -> Dict[str, Any]:
        """Get request template as dictionary."""
        try:
            return json.loads(self.request_template) if self.request_template else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    
    def __repr__(self):
        return f'<PartnerEndpoint {self.endpoint_name} for {self.partner.name}>'


class PartnerAPICall(BaseModel):
    """
    Partner API call log for monitoring and debugging.
    
    This model tracks all API calls made to partners for
    monitoring, debugging, and audit purposes.
    """
    
    __tablename__ = 'partner_api_calls'
    
    partner_id = Column(Integer, ForeignKey('partners.id'), nullable=False)
    endpoint_name = Column(String(128))
    request_id = Column(String(64), index=True)  # Unique request identifier
    
    # Request Details
    http_method = Column(String(16))
    endpoint_url = Column(String(512))
    request_headers = Column(Text)  # JSON object
    request_body = Column(Text)
    request_size = Column(Integer)  # bytes
    
    # Response Details
    response_status = Column(Integer)
    response_headers = Column(Text)  # JSON object
    response_body = Column(Text)
    response_size = Column(Integer)  # bytes
    response_time = Column(Float)  # seconds
    
    # Metadata
    user_id = Column(Integer, ForeignKey('users.id'))
    session_id = Column(String(64))
    ip_address = Column(String(45))
    user_agent = Column(String(512))
    
    # Status and Error Handling
    success = Column(Boolean)
    error_message = Column(Text)
    retry_attempt = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    partner = relationship('Partner', back_populates='api_calls')
    
    def get_request_headers(self) -> Dict[str, str]:
        """Get request headers as dictionary."""
        try:
            return json.loads(self.request_headers) if self.request_headers else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    
    def get_response_headers(self) -> Dict[str, str]:
        """Get response headers as dictionary."""
        try:
            return json.loads(self.response_headers) if self.response_headers else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    
    def __repr__(self):
        return f'<PartnerAPICall {self.request_id} to {self.partner.name}>'


class PartnerWebhook(BaseModel):
    """
    Partner webhook event log.
    
    This model tracks incoming webhook events from partners
    for processing and audit purposes.
    """
    
    __tablename__ = 'partner_webhooks'
    
    partner_id = Column(Integer, ForeignKey('partners.id'), nullable=False)
    webhook_id = Column(String(64), unique=True, nullable=False, index=True)
    event_type = Column(String(128), nullable=False)
    
    # Request Details
    headers = Column(Text)  # JSON object
    payload = Column(Text)
    signature = Column(String(256))
    payload_size = Column(Integer)  # bytes
    
    # Processing Details
    processed = Column(Boolean, default=False)
    processed_at = Column(DateTime)
    processing_time = Column(Float)  # seconds
    success = Column(Boolean)
    error_message = Column(Text)
    
    # Metadata
    ip_address = Column(String(45))
    user_agent = Column(String(512))
    
    # Timestamps
    received_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    partner = relationship('Partner', back_populates='webhooks')
    
    def get_headers(self) -> Dict[str, str]:
        """Get headers as dictionary."""
        try:
            return json.loads(self.headers) if self.headers else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    
    def get_payload(self) -> Dict[str, Any]:
        """Get payload as dictionary."""
        try:
            return json.loads(self.payload) if self.payload else {}
        except (json.JSONDecodeError, TypeError):
            return {'raw_payload': self.payload}
    
    def __repr__(self):
        return f'<PartnerWebhook {self.webhook_id} from {self.partner.name}>'


class PartnerRateLimit(BaseModel):
    """
    Partner rate limiting tracking.
    
    This model tracks rate limiting for each partner to ensure
    we don't exceed their API limits.
    """
    
    __tablename__ = 'partner_rate_limits'
    
    partner_id = Column(Integer, ForeignKey('partners.id'), nullable=False)
    endpoint_name = Column(String(128))  # Optional: per-endpoint rate limiting
    
    # Rate Limit Configuration
    requests_per_window = Column(Integer, nullable=False)
    window_seconds = Column(Integer, nullable=False)
    
    # Current Usage
    current_requests = Column(Integer, default=0)
    window_start = Column(DateTime, default=datetime.utcnow)
    last_request_at = Column(DateTime)
    
    # Status
    is_limited = Column(Boolean, default=False)
    limit_reset_at = Column(DateTime)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    partner = relationship('Partner')
    
    def can_make_request(self) -> bool:
        """Check if a request can be made within rate limits."""
        now = datetime.utcnow()
        
        # Reset window if expired
        if now >= self.window_start + timedelta(seconds=self.window_seconds):
            self.current_requests = 0
            self.window_start = now
            self.is_limited = False
            self.limit_reset_at = None
        
        # Check if under limit
        if self.current_requests < self.requests_per_window:
            return True
        
        # Set limited status
        if not self.is_limited:
            self.is_limited = True
            self.limit_reset_at = self.window_start + timedelta(seconds=self.window_seconds)
        
        return False
    
    def record_request(self):
        """Record a new request."""
        self.current_requests += 1
        self.last_request_at = datetime.utcnow()
    
    def __repr__(self):
        return f'<PartnerRateLimit {self.partner.name}: {self.current_requests}/{self.requests_per_window}>'


class PartnerTransaction(BaseModel):
    """
    Partner transaction mapping.
    
    This model maps internal transactions to partner transactions
    for reconciliation and audit purposes.
    """
    
    __tablename__ = 'partner_transactions'
    
    partner_id = Column(Integer, ForeignKey('partners.id'), nullable=False)
    internal_transaction_id = Column(String(64), ForeignKey('transactions.transaction_id'), nullable=False)
    partner_transaction_id = Column(String(128), nullable=False)
    partner_reference = Column(String(128))
    
    # Transaction Details
    amount = Column(Float, nullable=False)
    currency = Column(String(3), nullable=False)
    transaction_type = Column(String(64))
    status = Column(String(32))
    
    # Partner-specific Data
    partner_data = Column(Text)  # JSON object with partner-specific fields
    partner_fees = Column(Float)
    partner_exchange_rate = Column(Float)
    
    # Reconciliation
    reconciled = Column(Boolean, default=False)
    reconciled_at = Column(DateTime)
    reconciliation_notes = Column(Text)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    partner_created_at = Column(DateTime)
    partner_updated_at = Column(DateTime)
    
    # Relationships
    partner = relationship('Partner')
    transaction = relationship('Transaction')
    
    def get_partner_data(self) -> Dict[str, Any]:
        """Get partner data as dictionary."""
        try:
            return json.loads(self.partner_data) if self.partner_data else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    
    def set_partner_data(self, data: Dict[str, Any]):
        """Set partner data from dictionary."""
        self.partner_data = json.dumps(data) if data else None
    
    def __repr__(self):
        return f'<PartnerTransaction {self.internal_transaction_id} -> {self.partner_transaction_id}>'