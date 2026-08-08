import os
import re
import uuid
import logging
from contextvars import ContextVar
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import Optional

from pulse.config import get_config_dir

# ContextVar for thread-safe scan correlation ID tracking
_SCAN_CORRELATION_ID: ContextVar[Optional[str]] = ContextVar("scan_correlation_id", default=None)

def set_scan_correlation_id(correlation_id: Optional[str] = None) -> str:
    """Sets a unique correlation ID for the active scan run."""
    if not correlation_id:
        timestamp_str = datetime.now().strftime("%Y%m%d-%H%M%S")
        short_uuid = uuid.uuid4().hex[:6]
        correlation_id = f"Scan {timestamp_str}-{short_uuid}"
    _SCAN_CORRELATION_ID.set(correlation_id)
    return correlation_id

def get_scan_correlation_id() -> Optional[str]:
    """Retrieves current scan correlation ID."""
    return _SCAN_CORRELATION_ID.get()

def clear_scan_correlation_id() -> None:
    """Resets active scan correlation ID."""
    _SCAN_CORRELATION_ID.set(None)


class SecretRedactionFilter(logging.Filter):
    """Filter scrubbing secrets, tokens, API keys, and authorization headers from logs."""

    SECRET_PATTERNS = [
        (re.compile(r'(?i)(apiKey|api_key|token|secret|password|auth|authorization)=([^\s&"\'<>]+)'), r'\1=[REDACTED]'),
        (re.compile(r'(?i)(Bearer|Basic)\s+([A-Za-z0-9\-\._~\+\/]+=*)'), r'\1 [REDACTED]'),
        (re.compile(r'(?i)("?(?:apiKey|api_key|token|secret|password|nvd_api_key)"?\s*:\s*)"([^"]+)"'), r'\1"[REDACTED]"'),
        (re.compile(r'(?i)(Cookie|Set-Cookie|X-API-Key|Proxy-Authorization):\s*([^\r\n]+)'), r'\1: [REDACTED]'),
    ]

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.redact(record.msg)
        if record.args:
            if isinstance(record.args, tuple):
                record.args = tuple(self.redact(arg) if isinstance(arg, str) else arg for arg in record.args)
            elif isinstance(record.args, dict):
                record.args = {k: self.redact(v) if isinstance(v, str) else v for k, v in record.args.items()}
        return True

    @classmethod
    def redact(cls, text: str) -> str:
        if not isinstance(text, str) or not text:
            return text
        redacted = text
        for pattern, replacement in cls.SECRET_PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        return redacted


class CorrelationIdFormatter(logging.Formatter):
    """Formatter prepending active scan correlation ID to log lines."""

    def format(self, record: logging.LogRecord) -> str:
        cid = get_scan_correlation_id()
        prefix = f"[{cid}] " if cid else ""
        original = super().format(record)
        return f"{prefix}{original}"


def setup_logging(debug: bool = False, log_level: Optional[str] = None) -> Path:
    """Configures centralized daily rotating log files under ~/.pulse/logs/ pulse.log."""
    logs_dir = get_config_dir() / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_file = logs_dir / "pulse.log"

    root_logger = logging.getLogger()
    
    # Determine log level
    if log_level:
        level = getattr(logging, log_level.upper(), logging.INFO)
    elif debug:
        level = logging.DEBUG
    else:
        level = logging.INFO

    root_logger.setLevel(level)

    # Avoid duplicate handlers
    for h in list(root_logger.handlers):
        if getattr(h, "_pulse_handler", False):
            root_logger.removeHandler(h)

    file_handler = TimedRotatingFileHandler(
        filename=log_file,
        when="midnight",
        interval=1,
        backupCount=30,
        encoding="utf-8"
    )
    file_handler._pulse_handler = True
    file_handler.setLevel(level)

    formatter = CorrelationIdFormatter(
        "%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    file_handler.setFormatter(formatter)
    file_handler.addFilter(SecretRedactionFilter())

    root_logger.addHandler(file_handler)

    return log_file

def get_logger(name: str) -> logging.Logger:
    """Retrieve logger instance with SecretRedactionFilter enabled."""
    logger = logging.getLogger(name)
    if not any(isinstance(f, SecretRedactionFilter) for f in logger.filters):
        logger.addFilter(SecretRedactionFilter())
    return logger
