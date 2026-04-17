"""AWI (Agentic Workflow Injection) vulnerability reporting module.

Provides LLM-based issue generation and human-reviewed submission
for GitHub Actions workflows vulnerable to prompt injection attacks.
"""

from awi_contribai.awi.issue_writer import AWIIssueWriter
from awi_contribai.awi.pr_writer import run_awi_pr_submission
from awi_contribai.awi.review_gate import IssueReviewDecision, IssueReviewer

__all__ = ["AWIIssueWriter", "IssueReviewer", "IssueReviewDecision", "run_awi_pr_submission"]
