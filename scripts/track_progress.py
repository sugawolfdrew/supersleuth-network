#!/usr/bin/env python3
"""
Simple task tracking script for SuperSleuth Network implementation
Run this to see current progress and next priorities
"""

import json
import os
from datetime import datetime
from pathlib import Path

class TaskTracker:
    def __init__(self):
        self.data_file = Path("data/implementation_progress.json")
        self.data_file.parent.mkdir(exist_ok=True)
        self.load_progress()
    
    def load_progress(self):
        """Load existing progress or create new tracking file"""
        if self.data_file.exists():
            with open(self.data_file, 'r') as f:
                self.progress = json.load(f)
        else:
            self.progress = self.initialize_progress()
            self.save_progress()
    
    def initialize_progress(self):
        """Initialize progress tracking structure"""
        return {
            "start_date": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat(),
            "phases": {
                "phase1_core": {
                    "name": "Core Functionality",
                    "status": "in_progress",
                    "progress_percent": 0,
                    "tasks": {
                        "remove_simulated_data": {"status": "pending", "assignee": None},
                        "real_network_scanning": {"status": "pending", "assignee": None},
                        "platform_implementations": {"status": "pending", "assignee": None},
                        "error_handling": {"status": "pending", "assignee": None}
                    }
                },
                "phase2_security": {
                    "name": "Security & Compliance",
                    "status": "pending",
                    "progress_percent": 0,
                    "tasks": {
                        "authentication": {"status": "pending", "assignee": None},
                        "vulnerability_scanning": {"status": "pending", "assignee": None},
                        "compliance_frameworks": {"status": "pending", "assignee": None},
                        "audit_trail": {"status": "pending", "assignee": None}
                    }
                },
                "phase3_performance": {
                    "name": "Performance & Monitoring",
                    "status": "pending",
                    "progress_percent": 0,
                    "tasks": {
                        "real_performance_testing": {"status": "pending", "assignee": None},
                        "data_management": {"status": "pending", "assignee": None},
                        "advanced_monitoring": {"status": "pending", "assignee": None}
                    }
                },
                "phase4_enterprise": {
                    "name": "Enterprise Features",
                    "status": "pending",
                    "progress_percent": 0,
                    "tasks": {
                        "enterprise_integrations": {"status": "pending", "assignee": None},
                        "cloud_support": {"status": "pending", "assignee": None},
                        "api_automation": {"status": "pending", "assignee": None},
                        "multi_tenancy": {"status": "pending", "assignee": None}
                    }
                },
                "phase5_testing": {
                    "name": "Testing & QA",
                    "status": "pending",
                    "progress_percent": 0,
                    "tasks": {
                        "unit_tests": {"status": "pending", "assignee": None},
                        "integration_tests": {"status": "pending", "assignee": None},
                        "performance_tests": {"status": "pending", "assignee": None},
                        "security_tests": {"status": "pending", "assignee": None},
                        "documentation": {"status": "pending", "assignee": None}
                    }
                },
                "phase6_deployment": {
                    "name": "Deployment & Operations",
                    "status": "pending",
                    "progress_percent": 0,
                    "tasks": {
                        "deployment_automation": {"status": "pending", "assignee": None},
                        "operations_support": {"status": "pending", "assignee": None}
                    }
                }
            },
            "blockers": [],
            "notes": []
        }
    
    def save_progress(self):
        """Save progress to file"""
        self.progress["last_updated"] = datetime.now().isoformat()
        with open(self.data_file, 'w') as f:
            json.dump(self.progress, f, indent=2)
    
    def update_task(self, phase, task, status, assignee=None):
        """Update a specific task status"""
        if phase in self.progress["phases"] and task in self.progress["phases"][phase]["tasks"]:
            self.progress["phases"][phase]["tasks"][task]["status"] = status
            if assignee:
                self.progress["phases"][phase]["tasks"][task]["assignee"] = assignee
            self.recalculate_progress(phase)
            self.save_progress()
            return True
        return False
    
    def recalculate_progress(self, phase):
        """Recalculate phase progress percentage"""
        tasks = self.progress["phases"][phase]["tasks"]
        completed = sum(1 for t in tasks.values() if t["status"] == "completed")
        total = len(tasks)
        self.progress["phases"][phase]["progress_percent"] = int((completed / total) * 100)
        
        # Update phase status
        if completed == 0:
            self.progress["phases"][phase]["status"] = "pending"
        elif completed == total:
            self.progress["phases"][phase]["status"] = "completed"
        else:
            self.progress["phases"][phase]["status"] = "in_progress"
    
    def add_blocker(self, blocker):
        """Add a blocker"""
        self.progress["blockers"].append({
            "description": blocker,
            "date": datetime.now().isoformat(),
            "resolved": False
        })
        self.save_progress()
    
    def resolve_blocker(self, index):
        """Mark a blocker as resolved"""
        if 0 <= index < len(self.progress["blockers"]):
            self.progress["blockers"][index]["resolved"] = True
            self.save_progress()
    
    def add_note(self, note):
        """Add a progress note"""
        self.progress["notes"].append({
            "text": note,
            "date": datetime.now().isoformat()
        })
        self.save_progress()
    
    def display_progress(self):
        """Display current progress"""
        print("\n" + "="*60)
        print("SuperSleuth Network - Implementation Progress")
        print("="*60)
        print(f"Started: {self.progress['start_date'][:10]}")
        print(f"Last Updated: {self.progress['last_updated'][:16]}")
        print("\nPhase Progress:")
        print("-"*60)
        
        overall_progress = 0
        phase_count = 0
        
        for phase_id, phase in self.progress["phases"].items():
            status_icon = {
                "pending": "⏳",
                "in_progress": "🔄",
                "completed": "✅"
            }[phase["status"]]
            
            print(f"{status_icon} {phase['name']:<30} {phase['progress_percent']:>3}%")
            
            if phase["status"] == "in_progress":
                # Show task details for active phase
                for task_name, task in phase["tasks"].items():
                    task_icon = {
                        "pending": "  ○",
                        "in_progress": "  ◐",
                        "completed": "  ●"
                    }[task["status"]]
                    assignee = f" ({task['assignee']})" if task.get('assignee') else ""
                    print(f"  {task_icon} {task_name.replace('_', ' ').title()}{assignee}")
            
            overall_progress += phase["progress_percent"]
            phase_count += 1
        
        overall_progress = int(overall_progress / phase_count)
        print("-"*60)
        print(f"Overall Progress: {overall_progress}%")
        
        # Show active blockers
        active_blockers = [b for b in self.progress["blockers"] if not b["resolved"]]
        if active_blockers:
            print(f"\n⚠️  Active Blockers ({len(active_blockers)}):")
            for i, blocker in enumerate(active_blockers):
                print(f"  {i+1}. {blocker['description']} (since {blocker['date'][:10]})")
        
        # Show recent notes
        if self.progress["notes"]:
            print(f"\n📝 Recent Notes:")
            for note in self.progress["notes"][-3:]:  # Last 3 notes
                print(f"  - {note['text']} ({note['date'][:10]})")
        
        print("\n" + "="*60)
        print("Next Steps:")
        self.show_next_steps()
        print("="*60 + "\n")
    
    def show_next_steps(self):
        """Show recommended next steps"""
        for phase_id, phase in self.progress["phases"].items():
            if phase["status"] == "in_progress":
                pending_tasks = [
                    task_name for task_name, task in phase["tasks"].items()
                    if task["status"] == "pending"
                ]
                if pending_tasks:
                    print(f"  - {phase['name']}: Start '{pending_tasks[0].replace('_', ' ')}'")
                break
        else:
            # Find next phase to start
            for phase_id, phase in self.progress["phases"].items():
                if phase["status"] == "pending":
                    print(f"  - Start {phase['name']} phase")
                    break

def main():
    """Main CLI interface"""
    import sys
    
    tracker = TaskTracker()
    
    if len(sys.argv) == 1:
        tracker.display_progress()
    elif sys.argv[1] == "update":
        if len(sys.argv) >= 5:
            phase = sys.argv[2]
            task = sys.argv[3]
            status = sys.argv[4]
            assignee = sys.argv[5] if len(sys.argv) > 5 else None
            if tracker.update_task(phase, task, status, assignee):
                print(f"✅ Updated {task} in {phase} to {status}")
                tracker.display_progress()
            else:
                print(f"❌ Failed to update - check phase and task names")
        else:
            print("Usage: track_progress.py update <phase> <task> <status> [assignee]")
            print("Example: track_progress.py update phase1_core remove_simulated_data in_progress andrew")
    elif sys.argv[1] == "blocker":
        if len(sys.argv) >= 3:
            if sys.argv[2] == "add" and len(sys.argv) > 3:
                blocker = " ".join(sys.argv[3:])
                tracker.add_blocker(blocker)
                print(f"⚠️  Added blocker: {blocker}")
            elif sys.argv[2] == "resolve" and len(sys.argv) > 3:
                index = int(sys.argv[3]) - 1
                tracker.resolve_blocker(index)
                print(f"✅ Resolved blocker #{index + 1}")
        else:
            print("Usage: track_progress.py blocker add <description>")
            print("       track_progress.py blocker resolve <number>")
    elif sys.argv[1] == "note":
        if len(sys.argv) > 2:
            note = " ".join(sys.argv[2:])
            tracker.add_note(note)
            print(f"📝 Added note: {note}")
        else:
            print("Usage: track_progress.py note <text>")
    else:
        print("Commands:")
        print("  track_progress.py                    - Show current progress")
        print("  track_progress.py update ...         - Update task status")
        print("  track_progress.py blocker add ...    - Add a blocker")
        print("  track_progress.py blocker resolve N  - Resolve blocker #N")
        print("  track_progress.py note ...           - Add a progress note")

if __name__ == "__main__":
    main()