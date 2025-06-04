"""Configuration management for validate-secrets."""

import os
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dotenv import load_dotenv

from .core.exceptions import ConfigurationError

LOG = logging.getLogger(__name__)


class Config:
    """Configuration manager for validate-secrets."""

    def __init__(self, env_file: Optional[str] = None):
        """Initialize configuration.

        Args:
            env_file: Path to .env file (optional)
        """
        # Load .env file if it exists
        env_path = Path(env_file) if env_file else Path(".env")
        if env_path.exists():
            load_dotenv(env_path)
            LOG.debug(f"Loaded configuration from {env_path}")

    def get_github_config(self) -> Dict[str, Any]:
        """Get GitHub configuration from environment."""
        token = os.getenv("GITHUB_TOKEN")
        if not token:
            raise ConfigurationError("GITHUB_TOKEN environment variable is required")

        return {
            "token": token,
            "org": os.getenv("GITHUB_ORG"),
            "repo": os.getenv("GITHUB_REPO"),
            "api_url": os.getenv("GITHUB_API_URL", "https://api.github.com"),
        }

    def get_log_config(self) -> Dict[str, Any]:
        """Get logging configuration from environment."""
        level = os.getenv("LOG_LEVEL", "INFO").upper()
        format_type = os.getenv("LOG_FORMAT", "text").lower()

        return {"level": getattr(logging, level, logging.INFO), "format": format_type}

    def get_output_config(self) -> Dict[str, Any]:
        """Get output configuration from environment."""
        return {
            "format": os.getenv("DEFAULT_OUTPUT_FORMAT", "csv").lower(),
            "file": os.getenv("DEFAULT_OUTPUT_FILE", "stdout"),
        }
    
    def get_input_format(self) -> Dict[str, Any]:
        """Get input format configuration from environment."""
        return {
            "input_format": os.getenv("DEFAULT_INPUT_FORMAT", "text").lower(),
        }

    def get_validation_config(self) -> Dict[str, Any]:
        """Get validation configuration from environment."""
        return {
            "timeout": int(os.getenv("VALIDATION_TIMEOUT", "30")),
            "notifications": os.getenv("ENABLE_NOTIFICATIONS", "false").lower() == "true",
        }

    def setup_logging(self) -> None:
        """Set up logging based on configuration."""
        log_config = self.get_log_config()

        if log_config["format"] == "json":
            log_format = '{"timestamp": "%(asctime)s", "level": "%(levelname)s", "module": "%(name)s", "message": "%(message)s"}'
        else:
            log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

        logging.basicConfig(
            level=log_config["level"], format=log_format, datefmt="%Y-%m-%d %H:%M:%S"
        )
