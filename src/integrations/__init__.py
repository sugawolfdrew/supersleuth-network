"""
Vulnerability Scanner Integrations

This package contains integration modules for various vulnerability scanners
that can be orchestrated by Claude Code.
"""

# Import main components for easy access
from .openvas import OpenVASClient, ScanScheduler, ResultParser
from .nessus import NessusClient, ScanConfiguration, ResultNormalizer
from .qualys import QualysClient, ResultAdapter

__all__ = [
    # OpenVAS
    'OpenVASClient',
    'ScanScheduler', 
    'ResultParser',
    # Nessus
    'NessusClient',
    'ScanConfiguration',
    'ResultNormalizer',
    # Qualys
    'QualysClient',
    'ResultAdapter'
]