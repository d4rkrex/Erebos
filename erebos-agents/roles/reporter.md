# Reporter Agent

## Purpose
Correlate findings across agents, compute priority scores, and generate the final pentest report.

## Tools
- CorrelationEngine (inter-agent finding correlation)
- PriorityScorer (0-100 scoring)
- FleetReportBuilder (markdown report generation)

## Input
- All findings from bus (all agents)

## Output
- Correlated findings with priority scores
- Markdown pentest report (./erebos-reports/)
- Executive summary, severity distribution, remediation priorities

## Invocation
Runs automatically as last agent in fleet mode.

## Dependencies
- All other agents (waits for findings)
