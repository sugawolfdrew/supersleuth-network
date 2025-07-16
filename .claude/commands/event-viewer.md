Launch the interactive event viewer to monitor SuperSleuth Network events.

Usage: /event-viewer [options]

Options:
- follow - Follow new events in real-time (default)
- table - Display in table format
- json - Display in JSON format
- errors - Show only error events
- security - Show only security events

Example: /event-viewer table

Steps:
1. Parse the display mode option
2. Launch the event viewer with: `python3 event_viewer.py -f -m {mode}`
3. If specific event type requested, add appropriate filters
4. Provide instructions for keyboard controls
5. Monitor the viewer output