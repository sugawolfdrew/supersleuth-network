# SuperSleuth Network - A Claude Code Diagnostic Toolkit

**A collaborative network diagnostic toolkit designed for IT professionals using Claude Code in VSCode**

## 🎯 What This Is (And Isn't)

SuperSleuth Network is **NOT** a standalone application. It's a **diagnostic toolkit** that becomes powerful when used with Claude Code as your AI co-pilot.

Think of it as:
- 🧰 A toolbox of network diagnostic scripts
- 🤖 Designed for Claude Code to orchestrate and customize
- 👥 A collaborative workspace where human IT professionals and AI work together
- 🔧 Tools that adapt on-the-fly to specific network problems

## How It Works

```
You (IT Professional): "I'm seeing intermittent WiFi drops in the conference room"
Claude Code: "Let me help diagnose that. I'll use the network_discovery tool, 
             but modify it to focus on signal strength fluctuations..."
             *creates custom diagnostic*
             "I see drops every 15 minutes. Let's create an interference scanner..."
```

**You describe the problem. Claude Code adapts the tools. Together, you solve it.**

## Key Features

- **Adaptive Diagnostic Brain**: AI that adjusts diagnostic strategy based on findings
- **Enterprise Security & Compliance**: Zero-trust security model with full audit trails
- **Network Discovery & Asset Management**: Complete network inventory and security assessment
- **Performance Analysis & SLA Monitoring**: Service level agreement validation and optimization
- **Security Assessment**: Enterprise-grade security analysis and threat detection
- **Multi-Tier Reporting**: Reports for technical, IT professional, and executive audiences
- **Collaborative Intelligence**: Adapts to IT professional skill level
- **Comprehensive Event Logging**: Real-time event streaming with multiple output formats
- **Web Dashboard**: Interactive dashboard with live monitoring and control
- **Automated Remediation**: Platform-specific scripts for common issues
- **Authentication Framework** (Optional): Modular authentication system that organizations can enable

## Installation

### Prerequisites

- Python 3.8 or higher
- Administrative/root access for network diagnostics
- Network diagnostic tools (nmap, iperf3, etc.)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/sugawolfdrew/supersleuth-network.git
cd supersleuth-network
```

2. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Install system dependencies:

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install nmap iperf3 traceroute dnsutils wireless-tools net-tools
```

**macOS:**
```bash
brew install nmap iperf3
```

**Windows:**
```bash
# Using Chocolatey
choco install nmap iperf3
```

## Usage - The Claude Code Way

### Prerequisites for the Best Experience

1. **Install Claude Code** in VSCode
2. **Clone this repository** and open in VSCode
3. **Describe your network issue** to Claude Code

### Example Collaborative Sessions

#### Session 1: WiFi Performance Issues
```
You: "Users in the east wing are complaining about slow WiFi"

Claude Code: "I'll help diagnose that. Let me start with a signal strength 
             analysis focused on the east wing. First, I'll run the WiFi 
             scanner with modifications..."
             
*Claude modifies src/diagnostics/wifi_analyzer.py for your specific layout*
*Runs the diagnostic and interprets results*

Claude Code: "I found weak signal strength in rooms 201-205. The access point 
             in that area might be underpowered. Let me create a channel 
             interference test..."
```

#### Session 2: Security Concerns
```
You: "I think we might have unauthorized devices on our network"

Claude Code: "Let's investigate. I'll use the network discovery tool but 
             enhance it to flag suspicious devices. I'll also create a 
             MAC address validator against your known device list..."
             
*Claude creates a custom security scanner based on your environment*
```

### Toolkit Components

The toolkit includes base diagnostic modules that Claude Code can use and modify:

- **Network Discovery** (`src/diagnostics/network_discovery.py`) - Device scanning and identification
- **WiFi Analysis** (`src/diagnostics/wifi_analyzer.py`) - Signal strength and channel analysis  
- **Performance Testing** (`src/diagnostics/performance_analysis.py`) - Bandwidth and latency tests
- **Security Assessment** (`src/diagnostics/security_assessment.py`) - Vulnerability scanning
- **Monitoring** (`src/core/monitoring.py`) - Real-time network monitoring

### Working with Claude Code

1. **Open this project in VSCode**
2. **Start Claude Code** 
3. **Describe your network problem** in natural language
4. **Let Claude Code suggest and modify tools** for your specific situation
5. **Review and run the customized diagnostics**
6. **Collaborate on interpreting results** and next steps

### Standalone Usage (Without Claude Code)

While designed for Claude Code collaboration, you can run tools directly:

```bash
# Run network discovery
python3 -m src.diagnostics.network_discovery

# Launch monitoring dashboard  
python3 -m src.interfaces.web_dashboard

# View event logs
python3 event_viewer.py -f
```

## Authentication (Optional Framework)

SuperSleuth includes an **optional authentication framework** that organizations can enable based on their security requirements. By default, all tools are accessible without authentication.

### Current Status: Demo/Framework

- ✅ **No authentication required** - All tools work immediately out of the box
- ✅ **Modular auth functions** - Ready for organizations to implement
- ✅ **Example implementations** - Shows how LDAP, AD, and local auth would work
- ✅ **Claude Code compatible** - AI can orchestrate auth when configured

### Authentication Options

**1. No Authentication (Default)**
```python
# Just use the tools directly
from src.diagnostics import network_scanner
results = network_scanner.scan()  # Works immediately
```

**2. Local Authentication**
```python
# Configure local users
auth_config = {
    'auth_method': 'local',
    'users': {
        'admin': {'password': 'hashed_pass', 'groups': ['network_admins']}
    }
}
```

**3. LDAP/Active Directory**
```python
# For organizations with central authentication
auth_config = {
    'auth_method': 'active_directory',
    'domain': 'company.local',
    'required_groups': ['IT-Staff', 'Network-Operators']
}
```

### Enabling Authentication

To enable authentication in your deployment:

1. **Configure your auth backend** in `auth_config.json`
2. **Set required groups** for different permission levels
3. **Wrap diagnostic functions** with auth decorators
4. **Deploy with your security policies**

See `examples/authentication_demo.py` for detailed examples.

### Why This Approach?

- **Flexibility**: Use with or without authentication
- **Non-intrusive**: Doesn't force auth on everyone
- **Enterprise-ready**: Can integrate with existing auth systems
- **Compliance-friendly**: Provides audit trails when enabled

## Development

### Project Structure

```
supersleuth-network/
├── src/
│   ├── core/              # Core diagnostic framework
│   ├── diagnostics/       # Network diagnostic modules
│   ├── reporting/         # Multi-tier reporting system
│   ├── utils/            # Utility functions
│   └── interfaces/       # External interfaces
├── tests/                # Unit and integration tests
├── docs/                 # Documentation
├── examples/             # Example scripts
└── scripts/              # Utility scripts
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test suite
pytest tests/unit/
```

### Code Quality

```bash
# Format code
black src/

# Sort imports
isort src/

# Run linting
flake8 src/

# Type checking
mypy src/
```

## Documentation

- [Event Logging Guide](docs/EVENT_LOGGING.md) - Comprehensive event system documentation
- [Claude Code Commands](docs/CLAUDE_CODE_COMMANDS.md) - Custom slash commands for quick access
- [API Reference](docs/API.md) - Coming soon
- [Security Guide](docs/SECURITY.md) - Coming soon
- [Deployment Guide](docs/DEPLOYMENT.md) - Coming soon

## Security & Compliance

SuperSleuth Network implements enterprise-grade security:

- **Zero-Trust Model**: All operations require explicit authorization
- **Audit Logging**: Complete audit trail for all activities
- **Data Protection**: Encryption in transit and at rest
- **Compliance Support**: SOC 2, ISO 27001, PCI DSS, HIPAA
- **No Data Retention**: Client data purged after engagement

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For professional support and enterprise licensing:
- Email: support@supersleuth.network
- Documentation: https://docs.supersleuth.network
- Issues: https://github.com/sugawolfdrew/supersleuth-network/issues