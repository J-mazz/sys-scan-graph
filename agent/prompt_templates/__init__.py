#    .________      ._____.___ .______  .______ .______ .___ .______  .___
#    :____.   \     :         |:      \ \____  |\____  |: __|:      \ : __|
#     __|  :/ |     |   \  /  ||   .   |/  ____|/  ____|| : ||       || : |
#    |     :  |     |   |\/   ||   :   |\      |\      ||   ||   |   ||   |
#     \__. __/      |___| |   ||___|   | \__:__| \__:__||   ||___|   ||   |
#        :/               |___|    |___|    :       :   |___|    |___||___|
#        :                                  •       •                 
#                                                                          
#
#    2925
#    __init__.py

# ==============================================================================
from __future__ import annotations
"""Prompt template management system with A/B testing and structured responses.

This module provides versioned prompt templates with A/B testing capabilities,
structured response parsing, and performance tracking for the LLM pipeline.
"""

from typing import Dict, Any, List, Optional, Union, Tuple
from pathlib import Path
import json
import logging
from datetime import datetime
import hashlib
import random
from dataclasses import dataclass, asdict
from enum import Enum

logger = logging.getLogger(__name__)

class PromptVersion(Enum):
    """Prompt template versions for A/B testing."""
    V1 = "v1"
    V2 = "v2"
    V3 = "v3"

class ResponseFormat(Enum):
    """Supported response formats."""
    JSON = "json"
    MARKDOWN = "markdown"
    STRUCTURED = "structured"
    PLAIN = "plain"

@dataclass
class PromptTemplate:
    """A versioned prompt template with metadata."""
    id: str
    version: PromptVersion
    name: str
    description: str
    template: str
    variables: List[str]
    response_format: ResponseFormat
    created_at: str
    updated_at: str
    performance_score: float = 0.0
    usage_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        data = asdict(self)
        data['version'] = self.version.value
        data['response_format'] = self.response_format.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PromptTemplate':
        """Create from dictionary."""
        data_copy = data.copy()
        data_copy['version'] = PromptVersion(data['version'])
        data_copy['response_format'] = ResponseFormat(data['response_format'])
        return cls(**data_copy)

@dataclass
class ABTestResult:
    """Result of A/B testing between prompt versions."""
    test_id: str
    prompt_a: str
    prompt_b: str
    winner: str
    metric: str
    improvement: float
    confidence: float
    sample_size: int
    timestamp: str

class PromptManager:
    """Manager for prompt templates with A/B testing capabilities."""

    def __init__(self, templates_dir: Optional[Path] = None):
        self.templates_dir = templates_dir or Path(__file__).parent / "prompt_templates"
        self.templates_dir.mkdir(exist_ok=True)
        self.templates: Dict[str, PromptTemplate] = {}
        self.ab_tests: List[ABTestResult] = []
        self._load_templates()

    def _load_templates(self):
        """Load templates from disk."""
        for template_file in self.templates_dir.glob("*.json"):
            try:
                with open(template_file, 'r') as f:
                    data = json.load(f)
                    template = PromptTemplate.from_dict(data)
                    self.templates[template.id] = template
            except Exception as e:
                logger.warning(f"Failed to load template {template_file}: {e}")

    def _save_template(self, template: PromptTemplate):
        """Save template to disk."""
        template_file = self.templates_dir / f"{template.id}.json"
        with open(template_file, 'w') as f:
            json.dump(template.to_dict(), f, indent=2)

    def create_template(self, name: str, description: str, template: str,
                       variables: List[str], response_format: ResponseFormat = ResponseFormat.STRUCTURED,
                       version: PromptVersion = PromptVersion.V1) -> PromptTemplate:
        """Create a new prompt template."""
        template_id = hashlib.md5(f"{name}_{version.value}_{datetime.now().isoformat()}".encode()).hexdigest()[:8]

        prompt_template = PromptTemplate(
            id=template_id,
            version=version,
            name=name,
            description=description,
            template=template,
            variables=variables,
            response_format=response_format,
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat()
        )

        self.templates[template_id] = prompt_template
        self._save_template(prompt_template)

        logger.info(f"Created prompt template: {name} ({template_id})")
        return prompt_template

    def get_template(self, template_id: str) -> Optional[PromptTemplate]:
        """Get a template by ID."""
        return self.templates.get(template_id)

    def get_templates_by_name(self, name: str) -> List[PromptTemplate]:
        """Get all versions of a template by name."""
        return [t for t in self.templates.values() if t.name == name]

    def render_template(self, template: PromptTemplate, variables: Dict[str, Any]) -> str:
        """Render a template with variables."""
        try:
            rendered = template.template.format(**variables)
            template.usage_count += 1
            template.updated_at = datetime.now().isoformat()
            self._save_template(template)
            return rendered
        except KeyError as e:
            raise ValueError(f"Missing required variable: {e}")

    def ab_test_templates(self, template_a: PromptTemplate, template_b: PromptTemplate,
                         test_data: List[Dict[str, Any]], metric: str = "quality_score") -> ABTestResult:
        """Run A/B test between two template versions."""
        if len(test_data) < 2:
            raise ValueError("Need at least 2 test cases for A/B testing")

        results_a = []
        results_b = []

        # Simulate testing (in real implementation, this would call actual LLM)
        for i, test_case in enumerate(test_data):
            # Alternate between templates
            if i % 2 == 0:
                # Use template A
                try:
                    prompt = self.render_template(template_a, test_case)
                    score = random.uniform(0.7, 0.9)  # Simulated score
                    results_a.append(score)
                except Exception:
                    results_a.append(0.5)
            else:
                # Use template B
                try:
                    prompt = self.render_template(template_b, test_case)
                    score = random.uniform(0.7, 0.9)  # Simulated score
                    results_b.append(score)
                except Exception:
                    results_b.append(0.5)

        # Calculate results
        avg_a = sum(results_a) / len(results_a) if results_a else 0
        avg_b = sum(results_b) / len(results_b) if results_b else 0

        winner = template_a.id if avg_a > avg_b else template_b.id
        improvement = abs(avg_a - avg_b)
        confidence = min(0.95, len(test_data) / 100.0)  # Simplified confidence calculation

        result = ABTestResult(
            test_id=hashlib.md5(f"{template_a.id}_{template_b.id}_{datetime.now().isoformat()}".encode()).hexdigest()[:8],
            prompt_a=template_a.id,
            prompt_b=template_b.id,
            winner=winner,
            metric=metric,
            improvement=improvement,
            confidence=confidence,
            sample_size=len(test_data),
            timestamp=datetime.now().isoformat()
        )

        self.ab_tests.append(result)
        logger.info(f"A/B test completed: {template_a.name} vs {template_b.name}, winner: {winner}")

        return result

    def get_best_template(self, name: str) -> Optional[PromptTemplate]:
        """Get the best performing template for a given name."""
        candidates = self.get_templates_by_name(name)
        if not candidates:
            return None

        # Return template with highest performance score
        return max(candidates, key=lambda t: t.performance_score)

    def update_performance(self, template_id: str, score: float):
        """Update performance score for a template."""
        if template_id in self.templates:
            template = self.templates[template_id]
            # Simple exponential moving average
            alpha = 0.1
            template.performance_score = (1 - alpha) * template.performance_score + alpha * score
            template.updated_at = datetime.now().isoformat()
            self._save_template(template)

    def get_template_stats(self) -> Dict[str, Any]:
        """Get statistics about template usage and performance."""
        total_templates = len(self.templates)
        total_usage = sum(t.usage_count for t in self.templates.values())
        avg_performance = sum(t.performance_score for t in self.templates.values()) / total_templates if total_templates > 0 else 0

        return {
            'total_templates': total_templates,
            'total_usage': total_usage,
            'average_performance': avg_performance,
            'templates_by_version': {
                version.value: len([t for t in self.templates.values() if t.version == version])
                for version in PromptVersion
            },
            'ab_tests_count': len(self.ab_tests)
        }

# Global prompt manager instance
_prompt_manager: Optional[PromptManager] = None

def get_prompt_manager() -> PromptManager:
    """Get the global prompt manager instance."""
    global _prompt_manager
    if _prompt_manager is None:
        _prompt_manager = PromptManager()
    return _prompt_manager

def create_structured_prompt(name: str, description: str, template: str,
                           variables: List[str], response_format: ResponseFormat = ResponseFormat.STRUCTURED) -> PromptTemplate:
    """Create a structured prompt template."""
    manager = get_prompt_manager()
    return manager.create_template(name, description, template, variables, response_format)

def render_prompt(template_id: str, variables: Dict[str, Any]) -> str:
    """Render a prompt template with variables."""
    manager = get_prompt_manager()
    template = manager.get_template(template_id)
    if not template:
        raise ValueError(f"Template {template_id} not found")
    return manager.render_template(template, variables)

def ab_test_prompts(template_a_id: str, template_b_id: str,
                   test_data: List[Dict[str, Any]], metric: str = "quality_score") -> ABTestResult:
    """Run A/B test between two prompt templates."""
    manager = get_prompt_manager()
    template_a = manager.get_template(template_a_id)
    template_b = manager.get_template(template_b_id)

    if not template_a or not template_b:
        raise ValueError("One or both templates not found")

    return manager.ab_test_templates(template_a, template_b, test_data, metric)

__all__ = [
    'PromptVersion',
    'ResponseFormat',
    'PromptTemplate',
    'ABTestResult',
    'PromptManager',
    'get_prompt_manager',
    'create_structured_prompt',
    'render_prompt',
    'ab_test_prompts'
]