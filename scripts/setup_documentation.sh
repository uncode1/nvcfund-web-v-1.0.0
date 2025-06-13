#!/bin/bash

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install required packages
pip install reportlab==4.1.0

# Run documentation generator
python scripts/generate_documentation.py

# Deactivate virtual environment
deactivate

echo "Documentation generation complete. Check NVC_Fund_Web4_Developer_Manual.pdf" 