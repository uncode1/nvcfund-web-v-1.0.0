from .base import db, BaseModel, Column, String, Boolean, DateTime, Integer, Enum as SAEnum, relationship, Float, ForeignKey
from enum import Enum as PyEnum
from datetime import datetime

class BlockchainNetwork(PyEnum):
    MAINNET = "mainnet"
    TESTNET = "testnet"

class BlockchainTransactionType(PyEnum):
    TOKEN_TRANSFER = "token_transfer"
    CONTRACT_DEPLOY = "contract_deploy"
    CONTRACT_CALL = "contract_call"
    ETH_TRANSFER = "eth_transfer"
    OTHER = "other"

class SmartContractType(PyEnum):
    NVC_TOKEN = "nvc_token"
    SETTLEMENT_CONTRACT = "settlement_contract"
    MULTISIG_WALLET = "multisig_wallet"
    STAKING_CONTRACT = "staking_contract"
    OTHER = "other"

class SmartContract(BaseModel):
    __tablename__ = 'smart_contracts'
    
    name = Column(String(100))
    address = Column(String(42))
    is_active = Column(Boolean, default=True)
    abi = Column(String)
    bytecode = Column(String)
    description = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __repr__(self):
        return f"<SmartContract {self.name}:{self.address}>"

class BlockchainTransaction(BaseModel):
    __tablename__ = 'blockchain_transactions'
    
    transaction_id = Column(Integer)
    amount = Column(Float)
    gas_used = Column(Integer)
    gas_price = Column(Integer)
    block_number = Column(Integer)
    user_id = Column(Integer, ForeignKey('users.id'))
    status = Column(Integer)
    eth_tx_hash = Column(String(66), unique=True)
    from_address = Column(String(42))
    to_address = Column(String(42))
    transaction_type = Column(String(50))
    tx_metadata = Column(String)
    tx_hash = Column(String(66), unique=True)
    contract_address = Column(String(42))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def __init__(self, **kwargs):
        if 'eth_tx_hash' in kwargs and 'tx_hash' not in kwargs:
            kwargs['tx_hash'] = kwargs.pop('eth_tx_hash')
        super(BlockchainTransaction, self).__init__(**kwargs)
    
    def __repr__(self):
        tx_str = self.tx_hash if self.tx_hash else "Unknown"
        tx_type = self.transaction_type if self.transaction_type else "Unknown Type"
        return f"<BlockchainTransaction {tx_str} - {tx_type}>"

class BlockchainAccount(BaseModel):
    __tablename__ = 'blockchain_accounts'
    
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    eth_address = Column(String(64), nullable=False)
    eth_private_key = Column(String(256), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship('User', back_populates='blockchain_accounts')
    
    def __repr__(self):
        return f"<BlockchainAccount {self.eth_address}>"