#!/bin/bash

# SuperSleuth Network Log Viewer Script
# Provides quick access to various log viewing options

echo "
╔═══════════════════════════════════════════════════════════════╗
║                   SUPERSLEUTH NETWORK                         ║
║                      Log Viewer Menu                          ║
╚═══════════════════════════════════════════════════════════════╝
"

echo "Select a viewing option:"
echo "1) Follow all events in real-time (stream view)"
echo "2) Follow all events in real-time (table view)"
echo "3) View errors only"
echo "4) View security events"
echo "5) View performance metrics"
echo "6) View last 50 events"
echo "7) View event statistics"
echo "8) Open dashboard (with events)"
echo "9) Run event logging demo"
echo "0) Exit"
echo ""
read -p "Enter your choice (0-9): " choice

case $choice in
    1)
        echo "Starting real-time event viewer (stream mode)..."
        echo "Press 'q' to quit, 'p' to pause"
        sleep 2
        python3 event_viewer.py -f
        ;;
    2)
        echo "Starting real-time event viewer (table mode)..."
        echo "Press 'q' to quit, 'p' to pause"
        sleep 2
        python3 event_viewer.py -f -m table
        ;;
    3)
        echo "Viewing errors only..."
        python3 event_viewer.py -f -s error
        ;;
    4)
        echo "Viewing security events..."
        python3 event_viewer.py -f -t security
        ;;
    5)
        echo "Viewing performance metrics..."
        python3 event_viewer.py -f -t performance -m table
        ;;
    6)
        echo "Showing last 50 events..."
        python3 event_viewer.py -n 50
        ;;
    7)
        echo "Generating event statistics..."
        python3 -c "from src.core.event_logger import event_logger; import json; print(json.dumps(event_logger.get_statistics(24), indent=2))"
        ;;
    8)
        echo "Launching dashboard with event monitoring..."
        python3 dashboard_launcher.py
        ;;
    9)
        echo "Running event logging demonstration..."
        python3 examples/event_logging_demo.py
        ;;
    0)
        echo "Exiting..."
        exit 0
        ;;
    *)
        echo "Invalid choice. Please run the script again."
        ;;
esac

echo ""
echo "Done. Press Enter to exit."
read