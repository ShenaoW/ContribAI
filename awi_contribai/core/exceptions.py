"""Small exception hierarchy for AWI ContribAI."""


class AWIContribAIError(Exception):
    """Base exception for all package errors."""


class ConfigError(AWIContribAIError):
    """Configuration loading or validation error."""


class GitHubAPIError(AWIContribAIError):
    """GitHub API request failure."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class RateLimitError(GitHubAPIError):
    """GitHub API rate limit exceeded."""


class LLMError(AWIContribAIError):
    """LLM provider error."""


class LLMRateLimitError(LLMError):
    """LLM provider rate limit exceeded."""


class PRCreationError(AWIContribAIError):
    """Pull request creation failure."""
