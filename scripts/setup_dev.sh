#!/bin/bash

# SuperSleuth Network Development Setup Script

echo "🚀 Setting up SuperSleuth Network development environment..."

# Check Python version
python_version=$(python3 --version 2>&1 | awk '{print $2}')
echo "📌 Python version: $python_version"

# Create virtual environment
echo "🔧 Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "🔧 Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "📦 Upgrading pip..."
pip install --upgrade pip

# Install development dependencies
echo "📦 Installing dependencies..."
pip install -r requirements.txt

# Install package in development mode
echo "📦 Installing SuperSleuth Network in development mode..."
pip install -e .

# Check for system dependencies
echo "🔍 Checking system dependencies..."

check_command() {
    if command -v $1 &> /dev/null; then
        echo "✅ $1 is installed"
    else
        echo "❌ $1 is NOT installed - please install it"
    fi
}

check_command nmap
check_command iperf3
check_command traceroute
check_command dig

echo ""
echo "✨ Development environment setup complete!"
echo ""
echo "To activate the virtual environment, run:"
echo "  source venv/bin/activate"
echo ""
echo "To run tests:"
echo "  pytest"
echo ""
echo "To format code:"
echo "  black src/"
echo "  isort src/"