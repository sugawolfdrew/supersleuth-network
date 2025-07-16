# SuperSleuth Network Prompt Templates for Claude Code

## Overview

This guide provides effective prompt templates for common network diagnostic scenarios. Each template shows how to communicate with Claude Code to get the best diagnostic results.

## Basic Prompt Structure

### Effective Prompts Include:
1. **Clear Problem Statement**: What's wrong
2. **Affected Scope**: Who/what is impacted
3. **Timeline**: When it started
4. **Constraints**: Any limitations
5. **Desired Outcome**: What you need

### Template Format
```
[Problem] + [Scope] + [Timeline] + [Constraints] + [Outcome]
```

## Performance Diagnostics

### Template 1: General Slowness
```
"Network performance is degraded for [users/services] in [location/subnet]. 
Started [timeframe]. Need to identify bottlenecks without disrupting service."
```

**Good Example:**
```
"Network performance is degraded for all users in Building A (192.168.10.0/24). 
Started after lunch today. Need to identify bottlenecks without disrupting service."
```

**Poor Example:**
```
"Network slow"
```

### Template 2: Specific Service Performance
```
"[Service] response times are [symptom] when accessed from [location]. 
Affecting [impact]. Need root cause analysis."
```

**Good Example:**
```
"SharePoint response times are exceeding 10 seconds when accessed from remote offices. 
Affecting 200+ users. Need root cause analysis."
```

## Connectivity Issues

### Template 3: Cannot Reach Service
```
"Cannot connect to [service/host] from [source]. 
Getting [error/symptom]. Other services [working/not working]. 
Need connectivity path analysis."
```

**Good Example:**
```
"Cannot connect to database server 10.1.5.20:3306 from web servers in DMZ. 
Getting connection timeout. Other internal services working fine. 
Need connectivity path analysis."
```

### Template 4: Intermittent Connectivity
```
"Intermittent connection failures to [destination] occurring [frequency]. 
Pattern appears to be [observation]. Need to capture during failure window."
```

**Good Example:**
```
"Intermittent connection failures to cloud API occurring every 15-20 minutes. 
Pattern appears to be related to peak usage. Need to capture during failure window."
```

## DNS Problems

### Template 5: DNS Resolution Issues
```
"DNS resolution for [domains/pattern] is [symptom]. 
Using DNS servers [servers]. Internal/external domains [affected/not affected]."
```

**Good Example:**
```
"DNS resolution for *.company.com is failing intermittently. 
Using DNS servers 8.8.8.8 and 10.1.1.10. External domains resolve fine."
```

### Template 6: DNS Performance
```
"DNS queries taking [time] for [domain pattern]. 
Normal response time is [baseline]. Started [when]."
```

**Good Example:**
```
"DNS queries taking 5-8 seconds for any external domain. 
Normal response time is <100ms. Started this morning after DNS server update."
```

## Security Incidents

### Template 7: Suspicious Activity
```
"Detected [unusual behavior] from [source]. 
Traffic pattern shows [details]. Need security assessment and recommendations."
```

**Good Example:**
```
"Detected unusual outbound connections from 192.168.1.45 to multiple external IPs on port 445. 
Traffic pattern shows periodic bursts every 5 minutes. Need security assessment and recommendations."
```

### Template 8: Port Scan Request
```
"Need to verify authorized services on [host/network]. 
Specifically checking for [ports/services]. Must avoid triggering IDS."
```

**Good Example:**
```
"Need to verify authorized services on production web servers 10.1.2.0/24. 
Specifically checking for non-standard ports above 8000. Must avoid triggering IDS."
```

## Service Availability

### Template 9: Website/Service Down
```
"[Service] is [completely down/intermittent] for [users]. 
URL/endpoint is [details]. Was working [last known good time]."
```

**Good Example:**
```
"Company website www.example.com is showing 503 errors for all external users. 
Internal users can access fine. Was working until 10 AM today."
```

### Template 10: Multi-Service Outage
```
"Multiple services experiencing issues: [list services]. 
Common factor appears to be [observation]. Need systematic diagnosis."
```

**Good Example:**
```
"Multiple services experiencing issues: Email, VPN, and cloud storage all slow. 
Common factor appears to be services using LDAP authentication. Need systematic diagnosis."
```

## Network Mapping

### Template 11: Topology Discovery
```
"Need to map network topology for [subnet/VLAN]. 
Focus on [layer 2/layer 3/both]. Include [specific requirements]."
```

**Good Example:**
```
"Need to map network topology for new acquisition subnet 172.16.0.0/16. 
Focus on layer 3 routing. Include all active hosts and identify critical services."
```

## Advanced Diagnostics

### Template 12: Complex Multi-Symptom Issues
```
"Experiencing multiple symptoms:
1. [Symptom 1] affecting [scope 1]
2. [Symptom 2] affecting [scope 2]
3. [Symptom 3] affecting [scope 3]
Suspected correlation: [theory]. Need comprehensive analysis."
```

**Good Example:**
```
"Experiencing multiple symptoms:
1. Slow file transfers between offices (10% of normal speed)
2. VoIP calls dropping after exactly 5 minutes
3. Random TCP resets on long-lived connections
Suspected correlation: MTU or QoS misconfiguration. Need comprehensive analysis."
```

## Comparison Diagnostics

### Template 13: Before/After Analysis
```
"[Service/Network] performance degraded after [change/event]. 
Previous baseline: [metrics]. Current state: [metrics]. 
Need comparison analysis."
```

**Good Example:**
```
"Internet bandwidth degraded after ISP circuit upgrade yesterday. 
Previous baseline: 100Mbps symmetric. Current state: 1Gbps down but only 50Mbps up. 
Need comparison analysis."
```

## Tips for Better Prompts

### DO:
- Include specific IP addresses, hostnames, or subnets
- Mention error messages verbatim
- Specify time windows for intermittent issues
- Note any recent changes
- Indicate urgency/priority
- Mention any constraints (production environment, maintenance windows)

### DON'T:
- Use vague terms like "doesn't work" or "broken"
- Assume Claude knows your network layout
- Skip relevant context
- Combine unrelated issues in one prompt

## Prompt Enhancement Examples

### Basic → Better → Best

**Basic:**
"Email slow"

**Better:**
"Email is slow for users in the Boston office"

**Best:**
"Exchange email client experiencing 30-second delays when sending attachments >5MB from Boston office (10.2.0.0/24) to any recipient. Started after Exchange server update on Tuesday. SMTP (port 25) and web access working normally. Need to diagnose without disrupting mail flow."

## Industry-Specific Templates

### Healthcare/HIPAA Environment
```
"Diagnose [issue] in HIPAA-compliant environment. 
Cannot capture packet contents. Need analysis using headers/metadata only."
```

### Financial Services
```
"Troubleshoot [issue] on PCI-compliant network segment. 
Audit logging required. Business hours are 6 AM - 8 PM EST."
```

### Educational Institution
```
"Investigate [issue] affecting [dormitory/classroom/admin] network. 
Student VLAN is 10.x.x.x, Faculty is 172.16.x.x. Peak usage 8 AM - 3 PM."
```

## Emergency Response Templates

### Critical Outage
```
"URGENT: Complete outage of [service] affecting [number] users. 
Business impact: [description]. Need immediate triage and recovery steps."
```

### Security Breach
```
"SECURITY INCIDENT: Detected [indicator] suggesting possible breach. 
Affected systems: [list]. Need immediate assessment and containment recommendations."
```

## Follow-Up Prompts

After initial diagnosis:
- "Dig deeper into [specific finding]"
- "What would cause [observed symptom]?"
- "Check if [theory] explains the symptoms"
- "Verify fix by retesting [original issue]"
- "Document findings for incident report"

Remember: The more specific and contextual your prompt, the more targeted and useful Claude's diagnostic approach will be.