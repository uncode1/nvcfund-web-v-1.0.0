from typing import Union, Optional, Dict, Any
from decimal import Decimal, ROUND_HALF_UP
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class FinancialUtils:
    """
    A collection of utility functions for financial calculations and operations.
    Provides consistent handling of financial data across the application.
    """
    
    @staticmethod
    def format_currency(amount: Union[float, Decimal, int], 
                      currency_symbol: str = '₦',
                      decimal_places: int = 2) -> str:
        """
        Format a monetary amount with proper currency symbol and decimal places.
        
        Args:
            amount: The monetary amount to format
            currency_symbol: The currency symbol to use (default: ₦)
            decimal_places: Number of decimal places to show (default: 2)
            
        Returns:
            Formatted currency string
        """
        if not isinstance(amount, Decimal):
            amount = Decimal(str(amount))
        
        return f"{currency_symbol}{amount.quantize(Decimal('1.00'), rounding=ROUND_HALF_UP)}"
    
    @staticmethod
    def calculate_interest(principal: Union[float, Decimal], 
                         rate: Union[float, Decimal], 
                         days: int = 365) -> Decimal:
        """
        Calculate simple interest.
        
        Args:
            principal: The principal amount
            rate: Annual interest rate (as decimal, e.g., 0.05 for 5%)
            days: Number of days for the interest period
            
        Returns:
            Calculated interest amount
        """
        if not isinstance(principal, Decimal):
            principal = Decimal(str(principal))
        if not isinstance(rate, Decimal):
            rate = Decimal(str(rate))
            
        interest = principal * rate * Decimal(days) / Decimal(365)
        return interest.quantize(Decimal('1.00'), rounding=ROUND_HALF_UP)
    
    @staticmethod
    def validate_amount(amount: Union[float, Decimal], 
                      min_amount: Optional[Union[float, Decimal]] = None,
                      max_amount: Optional[Union[float, Decimal]] = None) -> bool:
        """
        Validate a monetary amount against minimum and maximum limits.
        
        Args:
            amount: The amount to validate
            min_amount: Minimum allowed amount
            max_amount: Maximum allowed amount
            
        Returns:
            True if valid, False otherwise
        """
        if not isinstance(amount, Decimal):
            amount = Decimal(str(amount))
            
        if min_amount is not None and amount < Decimal(str(min_amount)):
            return False
        if max_amount is not None and amount > Decimal(str(max_amount)):
            return False
            
        return True
    
    @staticmethod
    def calculate_net_amount(amount: Union[float, Decimal], 
                           fees: Optional[Union[float, Decimal]] = None,
                           tax_rate: Optional[Union[float, Decimal]] = None) -> Decimal:
        """
        Calculate net amount after applying fees and taxes.
        
        Args:
            amount: The gross amount
            fees: Amount of fees to deduct
            tax_rate: Tax rate to apply (as decimal, e.g., 0.075 for 7.5%)
            
        Returns:
            Net amount after deductions
        """
        if not isinstance(amount, Decimal):
            amount = Decimal(str(amount))
            
        net = amount
        if fees is not None:
            net -= Decimal(str(fees))
        if tax_rate is not None:
            net -= net * Decimal(str(tax_rate))
            
        return net.quantize(Decimal('1.00'), rounding=ROUND_HALF_UP)
    
    @staticmethod
    def calculate_compound_interest(principal: Union[float, Decimal],
                                  rate: Union[float, Decimal],
                                  periods: int,
                                  compound_freq: int = 12) -> Decimal:
        """
        Calculate compound interest.
        
        Args:
            principal: The principal amount
            rate: Annual interest rate (as decimal)
            periods: Number of periods (years)
            compound_freq: Number of times interest is compounded per year
            
        Returns:
            Future value of the investment
        """
        if not isinstance(principal, Decimal):
            principal = Decimal(str(principal))
        if not isinstance(rate, Decimal):
            rate = Decimal(str(rate))
            
        rate_per_period = rate / compound_freq
        total_periods = periods * compound_freq
        
        future_value = principal * ((1 + rate_per_period) ** total_periods)
        return future_value.quantize(Decimal('1.00'), rounding=ROUND_HALF_UP)

# Example usage:
if __name__ == '__main__':
    # Format currency
    print(FinancialUtils.format_currency(10000))  # Output: ₦10,000.00
    
    # Calculate interest
    interest = FinancialUtils.calculate_interest(100000, 0.05, 30)
    print(f"Interest for 30 days: {FinancialUtils.format_currency(interest)}")
    
    # Validate amount
    print(f"Amount valid: {FinancialUtils.validate_amount(10000, min_amount=5000, max_amount=50000)}")
    
    # Calculate net amount
    net = FinancialUtils.calculate_net_amount(100000, fees=1000, tax_rate=0.075)
    print(f"Net amount: {FinancialUtils.format_currency(net)}")
    
    # Calculate compound interest
    future_value = FinancialUtils.calculate_compound_interest(100000, 0.05, 5, 12)
    print(f"Future value: {FinancialUtils.format_currency(future_value)}")
