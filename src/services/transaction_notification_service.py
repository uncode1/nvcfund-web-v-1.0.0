"""
Transaction and login activity notification service.
"""

from typing import Dict, Any, Optional, List
from datetime import datetime
from smtplib import SMTP_SSL
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from twilio.rest import Client
from security.logging.security_logger import SecurityLogger
from security.utils.secure_coding import SecureCoding

class TransactionNotificationService:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = SecurityLogger(config)
        self.secure = SecureCoding(config)
        self._initialize_clients()

    def _initialize_clients(self) -> None:
        """Initialize notification clients."""
        # Email
        self.smtp_server = self.config.get('SMTP_SERVER')
        self.smtp_port = self.config.get('SMTP_PORT')
        self.smtp_user = self.config.get('SMTP_USER')
        self.smtp_password = self.config.get('SMTP_PASSWORD')

        # SMS
        self.twilio_client = Client(
            self.config.get('TWILIO_ACCOUNT_SID'),
            self.config.get('TWILIO_AUTH_TOKEN')
        )

    def send_transaction_notification(self, user: Dict[str, Any], transaction: Dict[str, Any]) -> None:
        """
        Send transaction notification to user.
        
        Args:
            user: User data containing email and phone
            transaction: Transaction data containing:
                - amount: Transaction amount
                - currency: Currency code
                - type: Transaction type (deposit/withdrawal/transfer)
                - timestamp: Transaction time
                - description: Transaction description
        """
        try:
            # Validate input
            if not self.secure.validate_input(user['email'], 'email'):
                raise ValueError("Invalid email address")
                
            # Format notification messages
            email_message = self._format_transaction_email(user, transaction)
            sms_message = self._format_transaction_sms(user, transaction)
            
            # Send notifications
            self._send_email(user['email'], email_message)
            self._send_sms(user['phone'], sms_message)
            
            self.logger.log_event(
                SecurityEventType.NOTIFICATION,
                SecurityEventSeverity.INFO,
                event_type='transaction_notification_sent',
                user_id=user['id'],
                transaction_id=transaction['id']
            )
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='transaction_notification_failed',
                error=str(e)
            )
            raise

    def send_login_notification(self, user: Dict[str, Any], login_data: Dict[str, Any]) -> None:
        """
        Send login activity notification.
        
        Args:
            user: User data containing email and phone
            login_data: Login data containing:
                - timestamp: Login time
                - ip_address: Login IP
                - location: Login location
                - device: Login device
        """
        try:
            # Validate input
            if not self.secure.validate_input(user['email'], 'email'):
                raise ValueError("Invalid email address")
                
            # Format notification messages
            email_message = self._format_login_email(user, login_data)
            sms_message = self._format_login_sms(user, login_data)
            
            # Send notifications
            self._send_email(user['email'], email_message)
            self._send_sms(user['phone'], sms_message)
            
            self.logger.log_event(
                SecurityEventType.NOTIFICATION,
                SecurityEventSeverity.INFO,
                event_type='login_notification_sent',
                user_id=user['id']
            )
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='login_notification_failed',
                error=str(e)
            )
            raise

    def _format_transaction_email(self, user: Dict[str, Any], transaction: Dict[str, Any]) -> str:
        """Format transaction email message."""
        return f"""
Subject: Transaction Notification - {transaction['type'].capitalize()}

Dear {user['name']},

A new transaction has been processed on your account:

Type: {transaction['type'].capitalize()}
Amount: {transaction['amount']} {transaction['currency']}
Description: {transaction['description']}
Time: {transaction['timestamp']}

If you did not authorize this transaction, please contact support immediately.

Best regards,
NVC Fund Team
        """

    def _format_transaction_sms(self, user: Dict[str, Any], transaction: Dict[str, Any]) -> str:
        """Format transaction SMS message."""
        return f"""
NVC Fund: New {transaction['type']} - {transaction['amount']} {transaction['currency']}
Time: {transaction['timestamp']}
If unauthorized, contact support immediately.
        """

    def _format_login_email(self, user: Dict[str, Any], login_data: Dict[str, Any]) -> str:
        """Format login email message."""
        return f"""
Subject: Login Activity Notification

Dear {user['name']},

A new login has been detected on your account:

Time: {login_data['timestamp']}
Location: {login_data['location']}
Device: {login_data['device']}
IP Address: {login_data['ip_address']}

If this was not you, please change your password immediately.

Best regards,
NVC Fund Team
        """

    def _format_login_sms(self, user: Dict[str, Any], login_data: Dict[str, Any]) -> str:
        """Format login SMS message."""
        return f"""
NVC Fund: New login detected
Time: {login_data['timestamp']}
Location: {login_data['location']}
If unauthorized, change password immediately.
        """

    def _send_email(self, recipient: str, message: str) -> None:
        """Send email notification."""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.smtp_user
            msg['To'] = recipient
            msg.attach(MIMEText(message, 'plain'))
            
            with SMTP_SSL(self.smtp_server, self.smtp_port) as server:
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
                
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='email_send_failed',
                error=str(e)
            )
            raise

    def _send_sms(self, recipient: str, message: str) -> None:
        """Send SMS notification."""
        try:
            message = self.twilio_client.messages.create(
                body=message,
                from_=self.config.get('TWILIO_PHONE_NUMBER'),
                to=recipient
            )
            
        except Exception as e:
            self.logger.log_event(
                SecurityEventType.ERROR,
                SecurityEventSeverity.ERROR,
                event_type='sms_send_failed',
                error=str(e)
            )
            raise
