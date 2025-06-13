"""
Partner Integration Service Module

This module provides comprehensive partner integration capabilities including:
- Dynamic partner onboarding
- API integration management
- Data transformation and mapping
- Authentication and authorization
- Rate limiting and monitoring
- Webhook management
- Error handling and retry logic
- Partner-specific business rules
- Compliance and audit trails
"""

import logging
import json
import hashlib
import hmac
import base64
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import asyncio
import aiohttp
from urllib.parse import urljoin, urlparse
import xml.etree.ElementTree as ET

from flask import current_app
from sqlalchemy.exc import SQLAlchemyError
from cryptography.fernet import Fernet

from ..models import db
from ..utils.security_utils import sanitize_input, validate_amount
from .logging_service import LoggingService, LogCategory, LogLevel


logger = logging.getLogger(__name__)


class PartnerType(Enum):
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


class IntegrationMethod(Enum):
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


class AuthenticationType(Enum):
    """Authentication types for partner APIs."""
    API_KEY = "api_key"
    OAUTH2 = "oauth2"
    JWT = "jwt"
    BASIC_AUTH = "basic_auth"
    MUTUAL_TLS = "mutual_tls"
    HMAC_SIGNATURE = "hmac_signature"
    CUSTOM = "custom"


class DataFormat(Enum):
    """Data formats for partner communication."""
    JSON = "json"
    XML = "xml"
    CSV = "csv"
    FIXED_WIDTH = "fixed_width"
    DELIMITED = "delimited"
    BINARY = "binary"
    CUSTOM = "custom"


@dataclass
class PartnerConfig:
    """Partner configuration data class."""
    partner_id: str
    name: str
    partner_type: PartnerType
    integration_method: IntegrationMethod
    authentication_type: AuthenticationType
    base_url: str
    api_version: str
    data_format: DataFormat
    rate_limit: int  # requests per minute
    timeout: int  # seconds
    retry_attempts: int
    retry_delay: int  # seconds
    webhook_url: Optional[str]
    webhook_secret: Optional[str]
    api_key: Optional[str]
    client_id: Optional[str]
    client_secret: Optional[str]
    certificate_path: Optional[str]
    private_key_path: Optional[str]
    custom_headers: Dict[str, str]
    field_mappings: Dict[str, str]
    business_rules: Dict[str, Any]
    compliance_settings: Dict[str, Any]
    is_active: bool
    created_at: datetime
    updated_at: datetime


@dataclass
class APIRequest:
    """API request data class."""
    partner_id: str
    endpoint: str
    method: str
    headers: Dict[str, str]
    data: Optional[Dict[str, Any]]
    params: Optional[Dict[str, str]]
    timeout: int
    retry_attempts: int


@dataclass
class APIResponse:
    """API response data class."""
    status_code: int
    headers: Dict[str, str]
    data: Optional[Dict[str, Any]]
    raw_content: str
    response_time: float
    success: bool
    error_message: Optional[str]


class PartnerIntegrationService:
    """
    Comprehensive partner integration service.
    
    This service provides flexible integration capabilities for external partners
    with support for various protocols, authentication methods, and data formats.
    """
    
    def __init__(self):
        """Initialize partner integration service."""
        self.partners: Dict[str, PartnerConfig] = {}
        self.rate_limiters: Dict[str, Dict] = {}
        self.encryption_key = self._get_encryption_key()
        self.session = requests.Session()
        self._load_partner_configs()
    
    def register_partner(self, config: PartnerConfig) -> bool:
        """
        Register a new partner configuration.
        
        Args:
            config: Partner configuration
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Validate configuration
            if not self._validate_partner_config(config):
                return False
            
            # Encrypt sensitive data
            encrypted_config = self._encrypt_sensitive_data(config)
            
            # Store configuration
            self.partners[config.partner_id] = encrypted_config
            
            # Initialize rate limiter
            self.rate_limiters[config.partner_id] = {
                'requests': [],
                'limit': config.rate_limit
            }
            
            # Log partner registration
            LoggingService.log_audit_event(
                action="partner_registered",
                resource=f"partner:{config.partner_id}",
                user_id=0,  # System action
                metadata={
                    'partner_name': config.name,
                    'partner_type': config.partner_type.value,
                    'integration_method': config.integration_method.value
                }
            )
            
            return True
            
        except Exception as e:
            logger.error(f"Error registering partner {config.partner_id}: {str(e)}")
            return False
    
    def make_api_request(
        self,
        partner_id: str,
        endpoint: str,
        method: str = "GET",
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, str]] = None,
        custom_headers: Optional[Dict[str, str]] = None
    ) -> APIResponse:
        """
        Make an API request to a partner.
        
        Args:
            partner_id: Partner identifier
            endpoint: API endpoint
            method: HTTP method
            data: Request data
            params: Query parameters
            custom_headers: Additional headers
            
        Returns:
            APIResponse object
        """
        try:
            # Get partner configuration
            partner = self.partners.get(partner_id)
            if not partner:
                raise ValueError(f"Partner {partner_id} not found")
            
            # Check rate limits
            if not self._check_rate_limit(partner_id):
                raise ValueError(f"Rate limit exceeded for partner {partner_id}")
            
            # Prepare request
            api_request = self._prepare_request(
                partner, endpoint, method, data, params, custom_headers
            )
            
            # Execute request
            response = self._execute_request(api_request)
            
            # Log API request
            LoggingService.log_api_request(
                endpoint=f"{partner_id}:{endpoint}",
                method=method,
                user_id=None,
                status_code=response.status_code,
                response_time=response.response_time,
                metadata={
                    'partner_id': partner_id,
                    'success': response.success
                }
            )
            
            return response
            
        except Exception as e:
            logger.error(f"Error making API request to {partner_id}: {str(e)}")
            return APIResponse(
                status_code=500,
                headers={},
                data=None,
                raw_content="",
                response_time=0.0,
                success=False,
                error_message=str(e)
            )
    
    def process_webhook(
        self,
        partner_id: str,
        headers: Dict[str, str],
        payload: str
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Process incoming webhook from partner.
        
        Args:
            partner_id: Partner identifier
            headers: Request headers
            payload: Webhook payload
            
        Returns:
            Tuple of (success, processed_data)
        """
        try:
            # Get partner configuration
            partner = self.partners.get(partner_id)
            if not partner:
                raise ValueError(f"Partner {partner_id} not found")
            
            # Verify webhook signature
            if not self._verify_webhook_signature(partner, headers, payload):
                raise ValueError("Invalid webhook signature")
            
            # Parse payload
            parsed_data = self._parse_webhook_payload(partner, payload)
            
            # Transform data according to field mappings
            transformed_data = self._transform_data(partner, parsed_data)
            
            # Apply business rules
            processed_data = self._apply_business_rules(partner, transformed_data)
            
            # Log webhook processing
            LoggingService.log(
                level=LogLevel.INFO,
                category=LogCategory.API,
                event_type="webhook_processed",
                message=f"Webhook processed from partner {partner_id}",
                metadata={
                    'partner_id': partner_id,
                    'data_size': len(payload)
                }
            )
            
            return True, processed_data
            
        except Exception as e:
            logger.error(f"Error processing webhook from {partner_id}: {str(e)}")
            return False, {}
    
    def sync_partner_data(
        self,
        partner_id: str,
        data_type: str,
        filters: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Synchronize data with partner.
        
        Args:
            partner_id: Partner identifier
            data_type: Type of data to sync
            filters: Optional filters for data
            
        Returns:
            Tuple of (success, synced_data)
        """
        try:
            partner = self.partners.get(partner_id)
            if not partner:
                raise ValueError(f"Partner {partner_id} not found")
            
            # Determine sync endpoint
            sync_endpoint = self._get_sync_endpoint(partner, data_type)
            
            # Prepare sync request
            sync_params = self._prepare_sync_params(partner, data_type, filters)
            
            # Execute sync request
            response = self.make_api_request(
                partner_id=partner_id,
                endpoint=sync_endpoint,
                method="GET",
                params=sync_params
            )
            
            if not response.success:
                raise ValueError(f"Sync request failed: {response.error_message}")
            
            # Process sync data
            synced_data = self._process_sync_data(partner, response.data)
            
            return True, synced_data
            
        except Exception as e:
            logger.error(f"Error syncing data with {partner_id}: {str(e)}")
            return False, []
    
    def send_data_to_partner(
        self,
        partner_id: str,
        data_type: str,
        data: Dict[str, Any]
    ) -> bool:
        """
        Send data to partner.
        
        Args:
            partner_id: Partner identifier
            data_type: Type of data being sent
            data: Data to send
            
        Returns:
            True if successful, False otherwise
        """
        try:
            partner = self.partners.get(partner_id)
            if not partner:
                raise ValueError(f"Partner {partner_id} not found")
            
            # Transform data for partner
            transformed_data = self._transform_outbound_data(partner, data_type, data)
            
            # Determine endpoint
            endpoint = self._get_outbound_endpoint(partner, data_type)
            
            # Send data
            response = self.make_api_request(
                partner_id=partner_id,
                endpoint=endpoint,
                method="POST",
                data=transformed_data
            )
            
            return response.success
            
        except Exception as e:
            logger.error(f"Error sending data to {partner_id}: {str(e)}")
            return False
    
    def _validate_partner_config(self, config: PartnerConfig) -> bool:
        """Validate partner configuration."""
        try:
            # Required fields validation
            if not config.partner_id or not config.name:
                return False
            
            # URL validation
            if config.base_url:
                parsed_url = urlparse(config.base_url)
                if not parsed_url.scheme or not parsed_url.netloc:
                    return False
            
            # Rate limit validation
            if config.rate_limit <= 0:
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error validating partner config: {str(e)}")
            return False
    
    def _encrypt_sensitive_data(self, config: PartnerConfig) -> PartnerConfig:
        """Encrypt sensitive configuration data."""
        try:
            encrypted_config = config
            
            # Encrypt sensitive fields
            if config.api_key:
                encrypted_config.api_key = self._encrypt_string(config.api_key)
            
            if config.client_secret:
                encrypted_config.client_secret = self._encrypt_string(config.client_secret)
            
            if config.webhook_secret:
                encrypted_config.webhook_secret = self._encrypt_string(config.webhook_secret)
            
            return encrypted_config
            
        except Exception as e:
            logger.error(f"Error encrypting sensitive data: {str(e)}")
            return config
    
    def _check_rate_limit(self, partner_id: str) -> bool:
        """Check if partner rate limit allows request."""
        try:
            rate_limiter = self.rate_limiters.get(partner_id)
            if not rate_limiter:
                return True
            
            now = datetime.utcnow()
            minute_ago = now - timedelta(minutes=1)
            
            # Remove old requests
            rate_limiter['requests'] = [
                req_time for req_time in rate_limiter['requests']
                if req_time > minute_ago
            ]
            
            # Check limit
            if len(rate_limiter['requests']) >= rate_limiter['limit']:
                return False
            
            # Add current request
            rate_limiter['requests'].append(now)
            return True
            
        except Exception as e:
            logger.error(f"Error checking rate limit: {str(e)}")
            return True
    
    def _prepare_request(
        self,
        partner: PartnerConfig,
        endpoint: str,
        method: str,
        data: Optional[Dict[str, Any]],
        params: Optional[Dict[str, str]],
        custom_headers: Optional[Dict[str, str]]
    ) -> APIRequest:
        """Prepare API request."""
        try:
            # Build headers
            headers = partner.custom_headers.copy()
            
            # Add authentication headers
            auth_headers = self._get_auth_headers(partner)
            headers.update(auth_headers)
            
            # Add custom headers
            if custom_headers:
                headers.update(custom_headers)
            
            # Set content type based on data format
            if data and partner.data_format == DataFormat.JSON:
                headers['Content-Type'] = 'application/json'
            elif data and partner.data_format == DataFormat.XML:
                headers['Content-Type'] = 'application/xml'
            
            return APIRequest(
                partner_id=partner.partner_id,
                endpoint=urljoin(partner.base_url, endpoint),
                method=method,
                headers=headers,
                data=data,
                params=params,
                timeout=partner.timeout,
                retry_attempts=partner.retry_attempts
            )
            
        except Exception as e:
            logger.error(f"Error preparing request: {str(e)}")
            raise
    
    def _execute_request(self, api_request: APIRequest) -> APIResponse:
        """Execute API request with retry logic."""
        start_time = datetime.utcnow()
        
        for attempt in range(api_request.retry_attempts + 1):
            try:
                # Prepare request data
                request_kwargs = {
                    'method': api_request.method,
                    'url': api_request.endpoint,
                    'headers': api_request.headers,
                    'timeout': api_request.timeout
                }
                
                if api_request.data:
                    if api_request.headers.get('Content-Type') == 'application/json':
                        request_kwargs['json'] = api_request.data
                    else:
                        request_kwargs['data'] = api_request.data
                
                if api_request.params:
                    request_kwargs['params'] = api_request.params
                
                # Make request
                response = self.session.request(**request_kwargs)
                
                # Calculate response time
                response_time = (datetime.utcnow() - start_time).total_seconds()
                
                # Parse response data
                response_data = None
                try:
                    if response.headers.get('content-type', '').startswith('application/json'):
                        response_data = response.json()
                    elif response.headers.get('content-type', '').startswith('application/xml'):
                        response_data = self._parse_xml_response(response.text)
                except Exception:
                    pass
                
                return APIResponse(
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    data=response_data,
                    raw_content=response.text,
                    response_time=response_time,
                    success=200 <= response.status_code < 300,
                    error_message=None if 200 <= response.status_code < 300 else response.text
                )
                
            except Exception as e:
                if attempt == api_request.retry_attempts:
                    # Last attempt failed
                    response_time = (datetime.utcnow() - start_time).total_seconds()
                    return APIResponse(
                        status_code=500,
                        headers={},
                        data=None,
                        raw_content="",
                        response_time=response_time,
                        success=False,
                        error_message=str(e)
                    )
                
                # Wait before retry
                import time
                time.sleep(2 ** attempt)  # Exponential backoff
    
    def _get_auth_headers(self, partner: PartnerConfig) -> Dict[str, str]:
        """Get authentication headers for partner."""
        headers = {}
        
        try:
            if partner.authentication_type == AuthenticationType.API_KEY:
                if partner.api_key:
                    decrypted_key = self._decrypt_string(partner.api_key)
                    headers['X-API-Key'] = decrypted_key
            
            elif partner.authentication_type == AuthenticationType.BASIC_AUTH:
                if partner.client_id and partner.client_secret:
                    decrypted_secret = self._decrypt_string(partner.client_secret)
                    credentials = base64.b64encode(
                        f"{partner.client_id}:{decrypted_secret}".encode()
                    ).decode()
                    headers['Authorization'] = f"Basic {credentials}"
            
            elif partner.authentication_type == AuthenticationType.HMAC_SIGNATURE:
                # HMAC signature would be calculated per request
                pass
            
        except Exception as e:
            logger.error(f"Error getting auth headers: {str(e)}")
        
        return headers
    
    def _verify_webhook_signature(
        self,
        partner: PartnerConfig,
        headers: Dict[str, str],
        payload: str
    ) -> bool:
        """Verify webhook signature."""
        try:
            if not partner.webhook_secret:
                return True  # No signature verification required
            
            signature_header = headers.get('X-Signature') or headers.get('X-Hub-Signature-256')
            if not signature_header:
                return False
            
            decrypted_secret = self._decrypt_string(partner.webhook_secret)
            expected_signature = hmac.new(
                decrypted_secret.encode(),
                payload.encode(),
                hashlib.sha256
            ).hexdigest()
            
            # Remove algorithm prefix if present
            if signature_header.startswith('sha256='):
                signature_header = signature_header[7:]
            
            return hmac.compare_digest(expected_signature, signature_header)
            
        except Exception as e:
            logger.error(f"Error verifying webhook signature: {str(e)}")
            return False
    
    def _parse_webhook_payload(self, partner: PartnerConfig, payload: str) -> Dict[str, Any]:
        """Parse webhook payload based on partner's data format."""
        try:
            if partner.data_format == DataFormat.JSON:
                return json.loads(payload)
            elif partner.data_format == DataFormat.XML:
                return self._parse_xml_response(payload)
            else:
                return {'raw_payload': payload}
                
        except Exception as e:
            logger.error(f"Error parsing webhook payload: {str(e)}")
            return {'raw_payload': payload}
    
    def _transform_data(self, partner: PartnerConfig, data: Dict[str, Any]) -> Dict[str, Any]:
        """Transform data according to partner's field mappings."""
        try:
            if not partner.field_mappings:
                return data
            
            transformed = {}
            for internal_field, external_field in partner.field_mappings.items():
                if external_field in data:
                    transformed[internal_field] = data[external_field]
            
            return transformed
            
        except Exception as e:
            logger.error(f"Error transforming data: {str(e)}")
            return data
    
    def _apply_business_rules(self, partner: PartnerConfig, data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply partner-specific business rules."""
        try:
            if not partner.business_rules:
                return data
            
            # Apply validation rules
            validation_rules = partner.business_rules.get('validation', {})
            for field, rules in validation_rules.items():
                if field in data:
                    value = data[field]
                    
                    # Apply min/max validation
                    if 'min' in rules and value < rules['min']:
                        raise ValueError(f"Field {field} below minimum: {value} < {rules['min']}")
                    
                    if 'max' in rules and value > rules['max']:
                        raise ValueError(f"Field {field} above maximum: {value} > {rules['max']}")
            
            # Apply transformation rules
            transformation_rules = partner.business_rules.get('transformations', {})
            for field, transform in transformation_rules.items():
                if field in data:
                    if transform['type'] == 'multiply':
                        data[field] = data[field] * transform['factor']
                    elif transform['type'] == 'currency_convert':
                        # Apply currency conversion
                        pass
            
            return data
            
        except Exception as e:
            logger.error(f"Error applying business rules: {str(e)}")
            return data
    
    def _get_encryption_key(self) -> bytes:
        """Get encryption key for sensitive data."""
        try:
            key = current_app.config.get('PARTNER_ENCRYPTION_KEY') if current_app else None
            if not key:
                # Generate a key for development (in production, use a secure key management system)
                key = Fernet.generate_key()
            elif isinstance(key, str):
                key = key.encode()
            return key
        except Exception:
            return Fernet.generate_key()
    
    def _encrypt_string(self, value: str) -> str:
        """Encrypt a string value."""
        try:
            fernet = Fernet(self.encryption_key)
            return fernet.encrypt(value.encode()).decode()
        except Exception as e:
            logger.error(f"Error encrypting string: {str(e)}")
            return value
    
    def _decrypt_string(self, encrypted_value: str) -> str:
        """Decrypt a string value."""
        try:
            fernet = Fernet(self.encryption_key)
            return fernet.decrypt(encrypted_value.encode()).decode()
        except Exception as e:
            logger.error(f"Error decrypting string: {str(e)}")
            return encrypted_value
    
    def _parse_xml_response(self, xml_content: str) -> Dict[str, Any]:
        """Parse XML response to dictionary."""
        try:
            root = ET.fromstring(xml_content)
            return self._xml_to_dict(root)
        except Exception as e:
            logger.error(f"Error parsing XML: {str(e)}")
            return {'raw_xml': xml_content}
    
    def _xml_to_dict(self, element) -> Dict[str, Any]:
        """Convert XML element to dictionary."""
        result = {}
        
        # Add attributes
        if element.attrib:
            result.update(element.attrib)
        
        # Add text content
        if element.text and element.text.strip():
            if len(element) == 0:
                return element.text.strip()
            result['text'] = element.text.strip()
        
        # Add child elements
        for child in element:
            child_data = self._xml_to_dict(child)
            if child.tag in result:
                if not isinstance(result[child.tag], list):
                    result[child.tag] = [result[child.tag]]
                result[child.tag].append(child_data)
            else:
                result[child.tag] = child_data
        
        return result
    
    def _load_partner_configs(self):
        """Load partner configurations from database or config files."""
        try:
            # In a real implementation, this would load from database
            # For now, we'll initialize with empty configs
            pass
        except Exception as e:
            logger.error(f"Error loading partner configs: {str(e)}")
    
    def _get_sync_endpoint(self, partner: PartnerConfig, data_type: str) -> str:
        """Get sync endpoint for data type."""
        # This would be configured per partner
        return f"/api/{partner.api_version}/sync/{data_type}"
    
    def _prepare_sync_params(
        self,
        partner: PartnerConfig,
        data_type: str,
        filters: Optional[Dict[str, Any]]
    ) -> Dict[str, str]:
        """Prepare sync parameters."""
        params = {}
        
        if filters:
            # Transform filters according to partner's field mappings
            for key, value in filters.items():
                mapped_key = partner.field_mappings.get(key, key)
                params[mapped_key] = str(value)
        
        return params
    
    def _process_sync_data(self, partner: PartnerConfig, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process synchronized data."""
        try:
            # Extract data array from response
            if 'data' in data:
                data_list = data['data']
            elif 'items' in data:
                data_list = data['items']
            else:
                data_list = [data]
            
            # Transform each item
            processed_data = []
            for item in data_list:
                transformed_item = self._transform_data(partner, item)
                processed_item = self._apply_business_rules(partner, transformed_item)
                processed_data.append(processed_item)
            
            return processed_data
            
        except Exception as e:
            logger.error(f"Error processing sync data: {str(e)}")
            return []
    
    def _transform_outbound_data(
        self,
        partner: PartnerConfig,
        data_type: str,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Transform outbound data for partner."""
        try:
            # Reverse field mappings for outbound data
            if partner.field_mappings:
                transformed = {}
                reverse_mappings = {v: k for k, v in partner.field_mappings.items()}
                
                for internal_field, value in data.items():
                    external_field = reverse_mappings.get(internal_field, internal_field)
                    transformed[external_field] = value
                
                return transformed
            
            return data
            
        except Exception as e:
            logger.error(f"Error transforming outbound data: {str(e)}")
            return data
    
    def _get_outbound_endpoint(self, partner: PartnerConfig, data_type: str) -> str:
        """Get outbound endpoint for data type."""
        # This would be configured per partner
        return f"/api/{partner.api_version}/{data_type}"


# Global partner integration service instance
partner_service = PartnerIntegrationService()