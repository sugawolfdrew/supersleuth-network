#!/usr/bin/env python3
"""
SuperSleuth Network Event Viewer
Launches the console viewer for real-time event monitoring
"""

import sys
from pathlib import Path

# Add project to path
sys.path.append(str(Path(__file__).parent))

from src.utils.console_viewer import main

if __name__ == '__main__':
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                   SUPERSLEUTH NETWORK                         ║
║                     Event Log Viewer                          ║
╚═══════════════════════════════════════════════════════════════╝

Starting event viewer...
""")
    main()