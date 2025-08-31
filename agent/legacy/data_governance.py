"""
Data Governance Module for Agent Pipeline

Provides data governance and redaction functionality for sensitive information
handling in the agent pipeline.
"""

import re
from typing import Any, Dict, List, Union
from pathlib import Path
import os


class DataGovernor:
    """Handles data governance and redaction for sensitive information."""

    def __init__(self):
        # Common sensitive patterns to redact
        self.sensitive_patterns = [
            # IP addresses (basic pattern)
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            # Hostnames
            r'\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b',
            # File paths (Unix/Windows)
            r'/[^\s]+',
            r'[A-Za-z]:\\[^\s]+',
            # User names
            r'\buser\s*[:=]\s*\w+\b',
            r'\busername\s*[:=]\s*\w+\b',
            # Password patterns
            r'\bpassword\s*[:=]\s*[^\s]+\b',
            r'\bpasswd\s*[:=]\s*[^\s]+\b',
            # API keys/tokens
            r'\bapi[_-]?key\s*[:=]\s*[^\s]+\b',
            r'\btoken\s*[:=]\s*[^\s]+\b',
            r'\bauth[_-]?key\s*[:=]\s*[^\s]+\b',
        ]

        # Compile regex patterns
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.sensitive_patterns]

        # Load custom redaction rules from config if available
        self._load_custom_rules()

    def _load_custom_rules(self):
        """Load custom redaction rules from configuration."""
        try:
            config_path = Path(__file__).parent / 'config.yaml'
            if config_path.exists():
                import yaml  # type: ignore
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f)
                    custom_patterns = config.get('data_governance', {}).get('redaction_patterns', [])
                    for pattern in custom_patterns:
                        if isinstance(pattern, str):
                            self.compiled_patterns.append(re.compile(pattern, re.IGNORECASE))
        except Exception:
            # Silently ignore config loading errors
            pass

    def redact_for_llm(self, obj: Any) -> Any:
        """
        Redact sensitive information from objects before sending to LLM.

        Args:
            obj: The object to redact (dict, list, string, or other types)

        Returns:
            Redacted version of the object
        """
        if isinstance(obj, dict):
            return self._redact_dict(obj)
        elif isinstance(obj, list):
            return [self.redact_for_llm(item) for item in obj]
        elif isinstance(obj, str):
            return self._redact_string(obj)
        else:
            # For other types, convert to string and redact
            return self._redact_string(str(obj))

    def _redact_dict(self, d: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive information from dictionary."""
        redacted = {}
        for key, value in d.items():
            # Redact sensitive keys
            redacted_key = self._redact_string(key)

            # Redact values
            if isinstance(value, (dict, list)):
                redacted_value = self.redact_for_llm(value)
            else:
                redacted_value = self._redact_string(str(value))

            redacted[redacted_key] = redacted_value
        return redacted

    def _redact_string(self, text: str) -> str:
        """Redact sensitive information from string."""
        redacted = text

        # Apply all redaction patterns
        for pattern in self.compiled_patterns:
            redacted = pattern.sub('[REDACTED]', redacted)

        # Additional custom redaction logic
        redacted = self._apply_custom_redactions(redacted)

        return redacted

    def _apply_custom_redactions(self, text: str) -> str:
        """Apply custom redaction logic."""
        # Redact environment variables that might contain sensitive info
        env_vars_to_redact = ['API_KEY', 'SECRET', 'TOKEN', 'PASSWORD', 'PRIVATE_KEY']
        for env_var in env_vars_to_redact:
            pattern = rf'\b{env_var}\s*[:=]\s*[^\s]+\b'
            text = re.sub(pattern, f'{env_var}=[REDACTED]', text, flags=re.IGNORECASE)

        return text

    def redact_output_narratives(self, summaries: Any) -> Any:
        """
        Redact sensitive information from output narratives.

        This is more conservative than redact_for_llm, focusing on
        protecting sensitive data in final outputs.

        Args:
            summaries: The summaries object to redact

        Returns:
            Redacted summaries
        """
        if not summaries:
            return summaries

        # For summaries, we want to be more conservative
        # Only redact the most sensitive patterns
        critical_patterns = [
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',  # IP addresses
            r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',  # Email addresses
            r'\bpassword\s*[:=]\s*[^\s]+\b',
            r'\btoken\s*[:=]\s*[^\s]+\b',
            r'\bsecret\s*[:=]\s*[^\s]+\b',
        ]

        critical_compiled = [re.compile(p, re.IGNORECASE) for p in critical_patterns]

        def _redact_critical(text: str) -> str:
            for pattern in critical_compiled:
                text = pattern.sub('[REDACTED]', text)
            return text

        return self._apply_redaction_recursive(summaries, _redact_critical)

    def _apply_redaction_recursive(self, obj: Any, redaction_func) -> Any:
        """Recursively apply redaction function to object."""
        if isinstance(obj, dict):
            return {key: self._apply_redaction_recursive(value, redaction_func) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._apply_redaction_recursive(item, redaction_func) for item in obj]
        elif isinstance(obj, str):
            return redaction_func(obj)
        else:
            return obj


# Global instance
_governor = None

def get_data_governor() -> DataGovernor:
    """Get the global data governor instance."""
    global _governor
    if _governor is None:
        _governor = DataGovernor()
    return _governor