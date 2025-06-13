from src.db import db, BaseModel
from sqlalchemy import Column, Integer, String, DateTime, Float, ForeignKey, Enum as SqlEnum
from enum import Enum as PyEnum
from decimal import Decimal

__all__ = [
    'db', 'BaseModel', 'User', 'Account', 'Transaction', 'TransactionStatus', 'TransactionType',
    'FinancialInstitution', 'PaymentGateway', 'Asset', 'SmartContract', 'BlockchainTransaction',
    'BlockchainAccount', 'TreasuryAccount', 'TreasuryInvestment', 'TreasuryAccountType', 'InvestmentType', 'InvestmentStatus', 'StablecoinAccount', 'LedgerEntry',
    'CorrespondentBank', 'SettlementBatch', 'SwiftMessage', 'TelexMessage', 'WireTransfer',
    'WireTransferStatusHistory', 'Employee', 'PayrollBatch', 'SalaryPayment', 'Vendor', 'Bill',
    'Contract', 'ContractPayment', 'Partner', 'PartnerEndpoint', 'PartnerAPICall', 'PartnerWebhook',
    'PartnerRateLimit', 'PartnerTransaction', 'SecurityEvent', 'SecurityLog', 'ApiKey', 
    'SecurityDashboardEvent', 'SupportEngineerKey', 'AMLTransaction'
]

def init_models(app):
    """Initialize all models with the Flask app."""
    db.init_app(app)
    return db

from . import (
    user, account, transaction, financial_institution, payment_gateway, asset, blockchain, treasury,
    stablecoin, swift, payroll, partner, security_event, security_log, api_key, security_dashboard, 
    support_engineer, aml
)

# Core models
User = user.User
Account = account.Account
Transaction = transaction.Transaction
TransactionStatus = transaction.TransactionStatus
TransactionType = transaction.TransactionType

# Financial models
FinancialInstitution = financial_institution.FinancialInstitution
PaymentGateway = payment_gateway.PaymentGateway
Asset = asset.Asset

# Blockchain models
SmartContract = blockchain.SmartContract
BlockchainTransaction = blockchain.BlockchainTransaction
BlockchainAccount = blockchain.BlockchainAccount

# Treasury models
TreasuryAccount = treasury.TreasuryAccount
TreasuryInvestment = treasury.TreasuryInvestment
TreasuryAccountType = treasury.TreasuryAccountType
InvestmentType = treasury.InvestmentType
InvestmentStatus = treasury.InvestmentStatus

# Stablecoin models
StablecoinAccount = stablecoin.StablecoinAccount
LedgerEntry = stablecoin.LedgerEntry
CorrespondentBank = stablecoin.CorrespondentBank
SettlementBatch = stablecoin.SettlementBatch

# SWIFT and wire transfer models
SwiftMessage = swift.SwiftMessage
TelexMessage = swift.TelexMessage
WireTransfer = swift.WireTransfer
WireTransferStatusHistory = swift.WireTransferStatusHistory

# Payroll and vendor models
Employee = payroll.Employee
PayrollBatch = payroll.PayrollBatch
SalaryPayment = payroll.SalaryPayment
Vendor = payroll.Vendor
Bill = payroll.Bill
Contract = payroll.Contract
ContractPayment = payroll.ContractPayment

# Partner models
Partner = partner.Partner
PartnerEndpoint = partner.PartnerEndpoint
PartnerAPICall = partner.PartnerAPICall
PartnerWebhook = partner.PartnerWebhook
PartnerRateLimit = partner.PartnerRateLimit
PartnerTransaction = partner.PartnerTransaction

# Security and admin models
SecurityEvent = security_event.SecurityEvent
SecurityLog = security_log.SecurityLog
ApiKey = api_key.APIKey
SecurityDashboardEvent = security_dashboard.SecurityDashboardEvent
SupportEngineerKey = support_engineer.SupportEngineerKey
AMLTransaction = aml.AMLTransaction
