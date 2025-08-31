"""Mock tool server for deterministic tool testing.

This module provides a mock server that simulates tool responses for testing
the tool wrapper and graph integration. It provides fixture-based responses
for baseline query tools with configurable behavior.
"""

from typing import Dict, Any, List, Optional, Union
import json
import time
import logging
from pathlib import Path
from datetime import datetime
import hashlib

logger = logging.getLogger(__name__)

class MockToolServer:
    """Mock server for tool testing with fixture-based responses."""

    def __init__(self, fixture_path: Optional[str] = None):
        self.fixtures: Dict[str, Dict[str, Any]] = {}
        self.call_history: List[Dict[str, Any]] = []
        self.error_mode = False
        self.delay_ms = 0

        # Load default fixtures
        self._load_default_fixtures()

        # Load custom fixtures if provided
        if fixture_path:
            self._load_fixtures_from_file(fixture_path)

    def _load_default_fixtures(self):
        """Load default test fixtures for baseline query tools."""
        self.fixtures = {
            "query_baseline": {
                "default": {
                    "status": "existing",
                    "payload": {
                        "finding_id": "test-finding-001",
                        "composite_hash": "abc123def456",
                        "baseline_status": "known_good",
                        "confidence_score": 0.95,
                        "last_seen": "2024-01-15T10:30:00Z",
                        "occurrences": 42
                    }
                },
                "new_finding": {
                    "status": "new",
                    "payload": {
                        "finding_id": "new-finding-001",
                        "composite_hash": "new123hash456",
                        "baseline_status": "unknown",
                        "confidence_score": 0.0,
                        "last_seen": None,
                        "occurrences": 1
                    }
                },
                "error_case": {
                    "status": "error",
                    "error_msg": "Database connection failed"
                }
            },
            "batch_baseline_query": {
                "default": {
                    "status": "existing",
                    "payload": [
                        {
                            "finding_id": "batch-finding-001",
                            "composite_hash": "batch123hash456",
                            "baseline_status": "known_good",
                            "confidence_score": 0.92,
                            "last_seen": "2024-01-14T09:15:00Z",
                            "occurrences": 38
                        },
                        {
                            "finding_id": "batch-finding-002",
                            "composite_hash": "batch789hash012",
                            "baseline_status": "suspicious",
                            "confidence_score": 0.67,
                            "last_seen": "2024-01-13T14:22:00Z",
                            "occurrences": 5
                        }
                    ]
                },
                "mixed_results": {
                    "status": "existing",
                    "payload": [
                        {
                            "finding_id": "mixed-finding-001",
                            "composite_hash": "mixed123hash456",
                            "baseline_status": "known_good",
                            "confidence_score": 0.89,
                            "last_seen": "2024-01-12T11:45:00Z",
                            "occurrences": 25
                        },
                        {
                            "finding_id": "mixed-finding-002",
                            "composite_hash": "mixed789hash012",
                            "baseline_status": "unknown",
                            "confidence_score": 0.0,
                            "last_seen": None,
                            "occurrences": 1
                        }
                    ]
                },
                "error_case": {
                    "status": "error",
                    "error_msg": "Batch processing failed: connection timeout"
                }
            }
        }

    def _load_fixtures_from_file(self, fixture_path: str):
        """Load custom fixtures from a JSON file."""
        try:
            path = Path(fixture_path)
            if path.exists():
                with open(path, 'r') as f:
                    custom_fixtures = json.load(f)
                self.fixtures.update(custom_fixtures)
                logger.info(f"Loaded custom fixtures from {fixture_path}")
            else:
                logger.warning(f"Fixture file not found: {fixture_path}")
        except Exception as e:
            logger.error(f"Failed to load fixtures from {fixture_path}: {e}")

    def set_error_mode(self, enabled: bool = True):
        """Enable or disable error mode for all tool calls."""
        self.error_mode = enabled
        logger.info(f"Error mode {'enabled' if enabled else 'disabled'}")

    def set_delay(self, delay_ms: int):
        """Set artificial delay for tool responses."""
        self.delay_ms = delay_ms
        logger.info(f"Response delay set to {delay_ms}ms")

    def get_call_history(self) -> List[Dict[str, Any]]:
        """Get the history of all tool calls made to this server."""
        return self.call_history.copy()

    def clear_call_history(self):
        """Clear the call history."""
        self.call_history.clear()

    def query_baseline(self, tool_name: str, args: Dict[str, Any],
                      request_id: str, timestamp: str, version: str) -> Dict[str, Any]:
        """Mock implementation of query_baseline tool."""
        # Record the call
        call_record = {
            "tool_name": tool_name,
            "args": args,
            "request_id": request_id,
            "timestamp": timestamp,
            "version": version,
            "call_time": datetime.now().isoformat()
        }
        self.call_history.append(call_record)

        # Simulate processing delay
        if self.delay_ms > 0:
            time.sleep(self.delay_ms / 1000.0)

        # Determine which fixture to use
        fixture_key = "error_case" if self.error_mode else self._determine_fixture_key(args)

        fixture = self.fixtures.get("query_baseline", {}).get(fixture_key, self.fixtures["query_baseline"]["default"])

        # Create response
        response = {
            "tool_name": tool_name,
            "request_id": request_id,
            "status": fixture["status"],
            "timestamp": datetime.now().isoformat(),
            "version": version,
            "processing_time_ms": self.delay_ms
        }

        if fixture["status"] != "error":
            # Customize payload based on input args
            payload = fixture["payload"].copy()
            if "finding_id" in args:
                payload["finding_id"] = args["finding_id"]
            if "composite_hash" in args:
                payload["composite_hash"] = args["composite_hash"]
            response["payload"] = payload
        else:
            response["error_msg"] = fixture["error_msg"]

        logger.debug(f"Mock query_baseline response: {response}")
        return response

    def batch_baseline_query(self, tool_name: str, args: Dict[str, Any],
                           request_id: str, timestamp: str, version: str) -> Dict[str, Any]:
        """Mock implementation of batch_baseline_query tool."""
        # Record the call
        call_record = {
            "tool_name": tool_name,
            "args": args,
            "request_id": request_id,
            "timestamp": timestamp,
            "version": version,
            "call_time": datetime.now().isoformat()
        }
        self.call_history.append(call_record)

        # Simulate processing delay
        if self.delay_ms > 0:
            time.sleep(self.delay_ms / 1000.0)

        # Determine which fixture to use
        fixture_key = "error_case" if self.error_mode else self._determine_batch_fixture_key(args)

        fixture = self.fixtures.get("batch_baseline_query", {}).get(fixture_key, self.fixtures["batch_baseline_query"]["default"])

        # Create response
        response = {
            "tool_name": tool_name,
            "request_id": request_id,
            "status": fixture["status"],
            "timestamp": datetime.now().isoformat(),
            "version": version,
            "processing_time_ms": self.delay_ms
        }

        if fixture["status"] != "error":
            # Customize payload based on input args
            payload = []
            finding_ids = args.get("finding_ids", [])
            composite_hashes = args.get("composite_hashes", [])

            for i, (finding_id, composite_hash) in enumerate(zip(finding_ids, composite_hashes)):
                result = fixture["payload"][i % len(fixture["payload"])].copy()
                result["finding_id"] = finding_id
                result["composite_hash"] = composite_hash
                payload.append(result)

            response["payload"] = payload
        else:
            response["error_msg"] = fixture["error_msg"]

        logger.debug(f"Mock batch_baseline_query response: {response}")
        return response

    def _determine_fixture_key(self, args: Dict[str, Any]) -> str:
        """Determine which fixture to use based on input arguments."""
        finding_id = args.get("finding_id", "")

        # Use hash of finding_id to deterministically choose fixtures
        if finding_id:
            hash_value = int(hashlib.md5(finding_id.encode()).hexdigest(), 16)
            if hash_value % 10 == 0:  # 10% chance
                return "new_finding"

        return "default"

    def _determine_batch_fixture_key(self, args: Dict[str, Any]) -> str:
        """Determine which batch fixture to use based on input arguments."""
        finding_ids = args.get("finding_ids", [])

        # Use mixed results if we have multiple findings
        if len(finding_ids) > 1:
            return "mixed_results"

        return "default"

    def get_available_tools(self) -> List[str]:
        """Get list of available mock tools."""
        return list(self.fixtures.keys())

    def get_fixture_stats(self) -> Dict[str, Any]:
        """Get statistics about loaded fixtures."""
        stats = {}
        for tool_name, tool_fixtures in self.fixtures.items():
            stats[tool_name] = {
                "fixture_count": len(tool_fixtures),
                "fixture_names": list(tool_fixtures.keys())
            }
        return stats

# Global mock server instance
_mock_server: Optional[MockToolServer] = None

def get_mock_server(fixture_path: Optional[str] = None) -> MockToolServer:
    """Get the global mock server instance."""
    global _mock_server
    if _mock_server is None:
        _mock_server = MockToolServer(fixture_path)
    return _mock_server

def create_mock_fixtures_file(output_path: str):
    """Create a sample fixtures file for customization."""
    sample_fixtures = {
        "query_baseline": {
            "custom_scenario": {
                "status": "existing",
                "payload": {
                    "finding_id": "custom-finding-001",
                    "composite_hash": "custom123hash456",
                    "baseline_status": "flagged",
                    "confidence_score": 0.78,
                    "last_seen": "2024-01-10T08:30:00Z",
                    "occurrences": 15
                }
            }
        },
        "batch_baseline_query": {
            "custom_batch": {
                "status": "existing",
                "payload": [
                    {
                        "finding_id": "custom-batch-001",
                        "composite_hash": "custombatch123",
                        "baseline_status": "known_good",
                        "confidence_score": 0.91,
                        "last_seen": "2024-01-09T16:45:00Z",
                        "occurrences": 33
                    }
                ]
            }
        }
    }

    try:
        with open(output_path, 'w') as f:
            json.dump(sample_fixtures, f, indent=2)
        logger.info(f"Created sample fixtures file: {output_path}")
    except Exception as e:
        logger.error(f"Failed to create fixtures file: {e}")

__all__ = [
    'MockToolServer',
    'get_mock_server',
    'create_mock_fixtures_file'
]