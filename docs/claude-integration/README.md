# Claude Code Integration with SuperSleuth Network

## Overview

Claude Code acts as an intelligent orchestrator for the SuperSleuth Network diagnostic toolkit, allowing IT professionals to use natural language to diagnose and resolve network issues. Instead of memorizing complex command syntax or tool parameters, you can simply describe what you want to investigate.

## How Claude Code Works with SuperSleuth

### 1. Natural Language Understanding
Claude Code interprets your requests and determines:
- What diagnostic information you need
- Which SuperSleuth tools to use
- In what order to run diagnostics
- How to correlate results

### 2. Intelligent Tool Selection
Based on your request, Claude Code automatically selects from:
- **DNS Diagnostics**: For domain resolution issues
- **Routing Diagnostics**: For path and latency problems
- **DHCP Diagnostics**: For IP assignment issues
- **HTTP Diagnostics**: For web service problems
- **Port Scanner**: For connectivity verification
- **Topology Interference**: For network mapping
- **Performance Analysis**: For speed and efficiency issues

### 3. Automated Workflow Execution
Claude Code:
- Runs diagnostics in the optimal order
- Handles errors and retries automatically
- Correlates results across multiple tools
- Presents findings in clear, actionable format

## Getting Started

### Basic Interaction Pattern

```
You: "The network seems slow when accessing external websites"
Claude Code: 
- Analyzes DNS resolution times
- Checks routing paths to popular destinations
- Measures HTTP response times
- Evaluates network metrics
- Provides comprehensive analysis with recommendations
```

### Prerequisites

1. SuperSleuth Network installed and configured
2. Claude Code CLI or API access
3. Appropriate network permissions

## Key Benefits

### For IT Professionals
- **No Command Memorization**: Use natural language instead of complex syntax
- **Contextual Intelligence**: Claude understands related issues and runs comprehensive diagnostics
- **Time Savings**: Automated workflows that would take 30+ minutes manually
- **Learning Tool**: See which tools Claude uses for different scenarios

### For Organizations
- **Standardized Diagnostics**: Consistent troubleshooting across teams
- **Knowledge Capture**: Claude embodies best practices
- **Reduced MTTR**: Faster problem identification and resolution
- **Documentation**: Automatic logging of diagnostic steps

## Common Use Cases

### 1. Performance Issues
```
"Users are complaining about slow internet speeds"
```
Claude Code will analyze bandwidth, latency, packet loss, and routing efficiency.

### 2. Connectivity Problems
```
"Can't reach the internal database server from the web tier"
```
Claude Code will test connectivity, check routing, verify ports, and analyze firewall rules.

### 3. Service Outages
```
"The company website is intermittently unavailable"
```
Claude Code will check DNS, test from multiple locations, analyze HTTP responses, and monitor over time.

### 4. Security Incidents
```
"Suspicious traffic detected from internal network"
```
Claude Code will scan for open ports, analyze traffic patterns, check for unauthorized services.

## Integration Methods

### 1. Interactive CLI
```bash
# Start interactive session
claude-code --supersleuth

# Direct command
claude-code "diagnose slow DNS resolution"
```

### 2. Python Integration
```python
from supersleuth_network import ClaudeCodeIntegration

claude = ClaudeCodeIntegration()
results = claude.diagnose("Network is slow in building A")
```

### 3. API Integration
```bash
curl -X POST https://api.claude.ai/v1/supersleuth \
  -H "Authorization: Bearer YOUR_KEY" \
  -d '{"prompt": "Diagnose connectivity to 192.168.1.100"}'
```

## Best Practices

### 1. Be Specific About Symptoms
- ✅ "DNS lookups taking 5+ seconds for external domains"
- ❌ "Network is broken"

### 2. Provide Context
- ✅ "Started after firewall update this morning"
- ❌ "It doesn't work"

### 3. Include Relevant Details
- ✅ "Affecting all users in subnet 192.168.50.0/24"
- ❌ "Some users have problems"

### 4. Specify Constraints
- ✅ "Need to diagnose without disrupting production traffic"
- ❌ "Fix it"

## Next Steps

1. Review [Prompt Templates](prompt-templates.md) for common scenarios
2. Explore [Workflow Examples](workflow-examples.md) for complex diagnostics
3. Try the [Example Scripts](../../examples/claude_code_integration.py)
4. Practice with [Scenario Scripts](../../examples/claude_code_scenarios/)

## Support and Feedback

- **Documentation**: Full SuperSleuth documentation at `/docs`
- **Examples**: Working examples in `/examples`
- **Community**: Share your prompts and workflows
- **Issues**: Report problems or suggest improvements

Remember: Claude Code is designed to make network diagnostics accessible. Don't hesitate to describe problems in your own words - Claude will translate them into the appropriate technical diagnostics.