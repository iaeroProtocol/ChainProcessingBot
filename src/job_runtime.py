"""Bounded cron execution and credential-safe diagnostics."""
import logging
import re
import signal
from contextlib import contextmanager


class JobDeadlineExceeded(BaseException):
    """Must escape broad per-phase Exception handlers."""


@contextmanager
def job_deadline(seconds):
    if seconds <= 0:
        raise ValueError("MAX_JOB_SECONDS must be positive")
    previous = signal.getsignal(signal.SIGALRM)
    def expire(signum, frame):
        raise JobDeadlineExceeded("Chain-processing job deadline exceeded")
    signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def redact(text):
    text = re.sub(r"https?://[^\s\"<>]+", "[URL redacted]", str(text))
    return re.sub(r"(?i)Bearer\s+[^\s\"<>]+", "Bearer [redacted]", text)


def redact_value(value):
    if isinstance(value, dict):
        return {key: redact_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    return redact(value) if isinstance(value, str) else value


class RedactingFormatter(logging.Formatter):
    def format(self, record):
        return redact(super().format(record))
