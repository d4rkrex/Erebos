"""Project-specific learning module.

Learns per-project patterns to reduce repeat false positives:
- Custom sanitizers that cover specific CWEs
- Framework-safe patterns (e.g., Django ORM prevents SQLi)
- Known-safe files that never contain vulnerabilities
- Suppressed rules per project context
"""

from erebos.core.learning.project import ProjectLearning, LearnedPattern, ProjectInsight

__all__ = ["ProjectLearning", "LearnedPattern", "ProjectInsight"]
