"""
Command-line interface for SuperSleuth Network
"""

import argparse
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.utils.logger import get_logger


def main():
    """Main CLI entry point"""
    
    parser = argparse.ArgumentParser(
        description="SuperSleuth Network - Enterprise WiFi & Network Diagnostic Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  supersleuth discover --subnet 192.168.1.0/24 --auth SOW-2024-001
  supersleuth security --compliance SOC2,PCI-DSS --output report.pdf
  supersleuth monitor --duration 300 --sla-file sla.yaml
        """
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='%(prog)s 0.1.0'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Network discovery command
    discover_parser = subparsers.add_parser(
        'discover',
        help='Discover devices on the network'
    )
    discover_parser.add_argument(
        '--subnet',
        required=True,
        help='Subnet to scan (e.g., 192.168.1.0/24)'
    )
    discover_parser.add_argument(
        '--auth',
        required=True,
        help='SOW reference for authorization'
    )
    
    # Security assessment command
    security_parser = subparsers.add_parser(
        'security',
        help='Perform security assessment'
    )
    security_parser.add_argument(
        '--compliance',
        required=True,
        help='Compliance frameworks (comma-separated)'
    )
    security_parser.add_argument(
        '--output',
        required=True,
        help='Output report file'
    )
    
    # Performance monitoring command
    monitor_parser = subparsers.add_parser(
        'monitor',
        help='Monitor network performance'
    )
    monitor_parser.add_argument(
        '--duration',
        type=int,
        default=300,
        help='Monitoring duration in seconds'
    )
    monitor_parser.add_argument(
        '--sla-file',
        help='SLA configuration file'
    )
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    logger = get_logger("CLI")
    
    try:
        if args.command == 'discover':
            logger.info(f"Starting network discovery for subnet {args.subnet}")
            print("Network discovery feature coming soon!")
            
        elif args.command == 'security':
            logger.info(f"Starting security assessment for {args.compliance}")
            print("Security assessment feature coming soon!")
            
        elif args.command == 'monitor':
            logger.info(f"Starting performance monitoring for {args.duration} seconds")
            print("Performance monitoring feature coming soon!")
            
    except Exception as e:
        logger.error(f"Command failed: {str(e)}")
        print(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()