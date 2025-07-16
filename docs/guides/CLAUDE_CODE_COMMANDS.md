# Claude Code Custom Slash Commands for SuperSleuth Network

## Overview

Claude Code supports custom slash commands that provide quick access to common tasks and workflows. SuperSleuth Network includes several custom commands designed for network diagnostics and monitoring.

## Available Commands

### 🔍 `/network-scan [subnet]`
Run a network discovery scan on the specified subnet.

**Example:**
```
/network-scan 192.168.1.0/24
```

**What it does:**
- Discovers all devices on the network
- Identifies device types and operating systems
- Maps network topology
- Logs all discoveries to event system

### 📊 `/event-viewer [mode]`
Launch the interactive event viewer.

**Modes:**
- `follow` - Real-time event stream (default)
- `table` - Tabular view
- `json` - JSON format
- `errors` - Error events only
- `security` - Security events only

**Example:**
```
/event-viewer table
```

### 🌐 `/dashboard [port]`
Launch the web dashboard interface.

**Example:**
```
/dashboard 5000
```

**Features:**
- Real-time metrics display
- Diagnostic controls
- Event monitoring
- Report generation

### ⚡ `/quick-scan [target]`
Perform a rapid diagnostic scan.

**Example:**
```
/quick-scan 192.168.1.1
/quick-scan local
```

**Checks:**
- Basic connectivity
- Performance metrics
- Security ports
- Common issues

### 📡 `/wifi-analysis [interface]`
Analyze WiFi infrastructure.

**Example:**
```
/wifi-analysis en0
```

**Analysis includes:**
- Signal strength mapping
- Channel utilization
- Interference detection
- Security assessment
- Optimization recommendations

### 🔒 `/security-check [target] [compliance]`
Run security assessment.

**Example:**
```
/security-check local SOC2
/security-check 192.168.1.0/24
```

**Compliance frameworks:**
- SOC2
- PCI-DSS
- HIPAA
- ISO27001

### 📄 `/generate-report [audience] [format]`
Generate diagnostic report.

**Audiences:**
- `technical` - Full technical details
- `it-professional` - IT team summary
- `executive` - Business overview

**Formats:**
- `pdf` - PDF document
- `html` - Web page
- `markdown` - Markdown file

**Example:**
```
/generate-report executive pdf
```

### 📈 `/monitor [duration] [interval]`
Start continuous monitoring.

**Example:**
```
/monitor 300 60
```

**Parameters:**
- `duration` - Total monitoring time (seconds)
- `interval` - Check interval (seconds)

## Installation

The slash commands are automatically available when you open the SuperSleuth Network project in Claude Code. They are defined in the `.claude/commands/` directory.

## Creating Custom Commands

To add your own slash command:

1. Create a new `.md` file in `.claude/commands/`
2. Name it after your command (e.g., `my-command.md`)
3. Define the command behavior using this template:

```markdown
Brief description of what the command does.

Usage: /my-command [arguments]

Example: /my-command arg1 arg2

Steps:
1. First step
2. Second step
3. Third step
```

## Command Arguments

Claude Code passes arguments to commands through the `$ARGUMENTS` variable:

```markdown
Run diagnostic on: $ARGUMENTS

Steps:
1. Parse arguments: $ARGUMENTS
2. Validate input
3. Execute command
```

## Best Practices

1. **Keep commands focused** - Each command should do one thing well
2. **Provide examples** - Show common usage patterns
3. **Handle errors gracefully** - Check for missing arguments
4. **Log activities** - Use the event logger for audit trails
5. **Show progress** - Provide feedback during long operations

## Integration with SuperSleuth

All commands integrate with SuperSleuth's core systems:

- **Event Logger** - All activities are logged
- **Authorization** - Security checks when needed
- **Reporting** - Results can be exported
- **Monitoring** - Continuous tracking available

## Troubleshooting

### Command not found
- Ensure file is in `.claude/commands/`
- Filename must match command name
- Restart Claude Code if needed

### Arguments not working
- Use `$ARGUMENTS` to access all arguments
- Arguments are passed as a single string
- Parse carefully for multiple arguments

### Python not found
- Commands use `python3` explicitly
- Ensure Python 3.8+ is installed
- Check virtual environment activation

## Examples of Advanced Commands

### Batch Operations
```markdown
Scan multiple subnets: $ARGUMENTS

Steps:
1. Split arguments by space
2. For each subnet:
   - Run network scan
   - Collect results
3. Generate combined report
```

### Conditional Logic
```markdown
Smart diagnostic based on: $ARGUMENTS

Steps:
1. If argument contains IP:
   - Run targeted scan
2. If argument is "full":
   - Run comprehensive diagnostics
3. Otherwise:
   - Run quick scan
```

### Integration with External Tools
```markdown
Export to monitoring system: $ARGUMENTS

Steps:
1. Run diagnostics
2. Format data for external system
3. Send via API
4. Confirm receipt
```

## Command Shortcuts

For frequently used commands, consider creating aliases:

- `/qs` → `/quick-scan`
- `/ev` → `/event-viewer`
- `/db` → `/dashboard`

## Future Enhancements

- Parameter validation
- Command history
- Custom command templates
- Integration with more tools
- Automated command generation

---

**Note:** Slash commands are a powerful way to extend Claude Code's functionality. Use them to streamline your network diagnostic workflows and make SuperSleuth Network even more efficient!