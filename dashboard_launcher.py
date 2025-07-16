#!/usr/bin/env python3
"""
SuperSleuth Network Dashboard Launcher
Quick launcher for the web dashboard interface
"""

import sys
import webbrowser
import time
from pathlib import Path

# Add project to path
sys.path.append(str(Path(__file__).parent))

from src.interfaces.web_dashboard import DashboardServer, create_dashboard_templates


def main():
    """Launch the SuperSleuth Network Dashboard"""
    
    print("""
╔═══════════════════════════════════════════════════════════════╗
║                   SUPERSLEUTH NETWORK                         ║
║                    Web Dashboard Launcher                      ║
╚═══════════════════════════════════════════════════════════════╝

Preparing dashboard...
""")
    
    # Create templates if they don't exist
    create_dashboard_templates()
    print("✅ Dashboard templates ready")
    
    # Create dashboard server
    dashboard = DashboardServer(host='127.0.0.1', port=5000)
    
    # Open browser after a short delay
    def open_browser():
        time.sleep(1.5)
        webbrowser.open('http://127.0.0.1:5000')
    
    import threading
    browser_thread = threading.Thread(target=open_browser)
    browser_thread.daemon = True
    browser_thread.start()
    
    # Run the dashboard
    try:
        dashboard.run()
    except KeyboardInterrupt:
        print("\n\n👋 Dashboard stopped. Thank you for using SuperSleuth Network!")


if __name__ == '__main__':
    main()