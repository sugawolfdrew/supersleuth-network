"""
SuperSleuth Network Compliance Framework

This package provides compliance assessment modules for various standards
that Claude Code can orchestrate for enterprise compliance checking.
"""

from .compliance_engine import (
    ComplianceEngine,
    ComplianceModule,
    ComplianceControl,
    ComplianceStatus,
    create_compliance_engine,
    quick_compliance_check,
    generate_compliance_report
)

from .pci_dss import (
    PCIDSSModule,
    assess_pci_compliance,
    check_cardholder_data_protection,
    verify_security_patches
)

from .hipaa import (
    HIPAAModule,
    assess_hipaa_compliance,
    check_phi_encryption,
    verify_hipaa_training
)

from .soc2 import (
    SOC2Module,
    TrustServicePrinciple,
    assess_soc2_compliance,
    check_security_controls,
    verify_availability_controls
)

__all__ = [
    # Engine
    'ComplianceEngine',
    'ComplianceModule',
    'ComplianceControl',
    'ComplianceStatus',
    'create_compliance_engine',
    'quick_compliance_check',
    'generate_compliance_report',
    
    # PCI DSS
    'PCIDSSModule',
    'assess_pci_compliance',
    'check_cardholder_data_protection',
    'verify_security_patches',
    
    # HIPAA
    'HIPAAModule',
    'assess_hipaa_compliance',
    'check_phi_encryption',
    'verify_hipaa_training',
    
    # SOC2
    'SOC2Module',
    'TrustServicePrinciple',
    'assess_soc2_compliance',
    'check_security_controls',
    'verify_availability_controls'
]