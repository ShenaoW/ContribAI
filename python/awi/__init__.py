"""AWI (Agentic Workflow Injection) vulnerability reporting module.

Provides LLM-based issue generation and human-reviewed submission
for GitHub Actions workflows vulnerable to prompt injection attacks.
"""

from contribai.awi.issue_writer import AWIIssueWriter
from contribai.awi.review_gate import IssueReviewDecision, IssueReviewer

__all__ = ["AWIIssueWriter", "IssueReviewer", "IssueReviewDecision"]
