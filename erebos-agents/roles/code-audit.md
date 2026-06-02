# Code Audit Agent

## Purpose
Analyze source code repositories for vulnerability patterns, auth gaps, and unsafe code.

## Tools
- RepoAnalyzer (AST-based pattern matching)

## Input
- Repository paths (--repo flag)
- Keywords: auth, password, token, sql, exec, eval

## Output
Findings with:
- File path and line number
- Auth gap detection (missing auth middleware)
- CWE classification (CWE-306, CWE-200)

## Invocation
```bash
erebos scan <target> --fleet --repo ./my-api
```

## Dependencies
None — runs in parallel with Recon.
