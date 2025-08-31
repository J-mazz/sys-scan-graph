# Tool Contract Specification

## Overview

This document defines the standardized contract for tool calls within the sys-scan-graph system. All tools must adhere to this contract to ensure deterministic behavior, proper error handling, and consistent integration with the LangGraph workflow.

## Contract Schema

### Input Schema

All tool calls must receive input in the following format:

```json
{
  "tool_name": "string",
  "args": {
    "finding_id": "string",
    "composite_hash": "string",
    "query_type": "string",
    "additional_params": {}
  },
  "request_id": "string",
  "timestamp": "ISO8601 string",
  "version": "string"
}
```

#### Field Definitions

- **tool_name**: The name of the tool being called (e.g., "query_baseline", "batch_baseline_query")
- **args**: Tool-specific arguments object
  - **finding_id**: Unique identifier for the finding being processed
  - **composite_hash**: SHA256 hash of the finding content for deduplication
  - **query_type**: Type of query ("baseline_check", "first_seen", "frequency_count")
  - **additional_params**: Tool-specific parameters
- **request_id**: Unique identifier for this tool call (UUID format)
- **timestamp**: ISO8601 timestamp when the call was initiated
- **version**: Contract version (currently "1.0")

### Output Schema

All tool calls must return output in the following format:

```json
{
  "tool_name": "string",
  "request_id": "string",
  "status": "new|existing|error",
  "payload": {
    "finding_id": "string",
    "composite_hash": "string",
    "first_seen_ts": "ISO8601 string|null",
    "seen_count": "integer",
    "baseline_status": "string",
    "confidence_score": "float"
  },
  "error_msg": "string|null",
  "processing_time_ms": "integer",
  "timestamp": "ISO8601 string",
  "version": "string"
}
```

#### Field Definitions

- **tool_name**: Echo of the input tool_name
- **request_id**: Echo of the input request_id
- **status**: Result status
  - `"new"`: Finding is new (first time seen)
  - `"existing"`: Finding exists in baseline
  - `"error"`: Tool execution failed
- **payload**: Result data object
  - **finding_id**: Echo of the input finding_id
  - **composite_hash**: Echo of the input composite_hash
  - **first_seen_ts**: ISO8601 timestamp when finding was first seen (null for new findings)
  - **seen_count**: Number of times this finding has been observed
  - **baseline_status**: Status classification ("new", "recurring", "resolved")
  - **confidence_score**: Confidence in the result (0.0 to 1.0)
- **error_msg**: Error message if status is "error", null otherwise
- **processing_time_ms**: Time taken to process the request in milliseconds
- **timestamp**: ISO8601 timestamp when the response was generated
- **version**: Contract version (currently "1.0")

## Tool Implementations

### query_baseline

**Purpose**: Query the baseline database for a single finding.

**Input Args**:

```json
{
  "finding_id": "string",
  "composite_hash": "string",
  "query_type": "baseline_check"
}
```

**Expected Behavior**:

1. Query baseline database for the composite_hash
2. Return status "existing" if found, "new" if not found
3. Include first_seen_ts and seen_count if existing

### batch_baseline_query

**Purpose**: Query the baseline database for multiple findings in a batch.

**Input Args**:

```json
{
  "finding_ids": ["string"],
  "composite_hashes": ["string"],
  "query_type": "batch_baseline_check",
  "batch_size": 100
}
```

**Expected Behavior**:

1. Process findings in batches to optimize database queries
2. Return results for all findings in the batch
3. Maintain deterministic ordering of results

## Error Handling

### Contract Violations

If a tool returns output that doesn't conform to the schema:

1. The tool wrapper will log a contract violation error
2. The request will be retried up to 3 times
3. If all retries fail, the tool call will be marked as failed
4. The workflow will continue with fallback behavior

### Tool Failures

If a tool encounters an internal error:

1. Return status "error"
2. Include a descriptive error_msg
3. The workflow will handle the error according to the error handling node

## Validation Rules

### Input Validation

1. **tool_name**: Must be a non-empty string, max 100 characters
2. **request_id**: Must be a valid UUID format
3. **timestamp**: Must be a valid ISO8601 timestamp
4. **args**: Must contain required fields based on tool_name

### Output Validation

1. **status**: Must be one of ["new", "existing", "error"]
2. **payload**: Must be present unless status is "error"
3. **error_msg**: Must be present if status is "error", null otherwise
4. **processing_time_ms**: Must be a positive integer
5. **timestamp**: Must be a valid ISO8601 timestamp after input timestamp

## Testing

### Contract Compliance Tests

All tools must pass the following tests:

1. **Schema Validation**: Output matches the JSON schema
2. **Deterministic Behavior**: Same input produces same output
3. **Error Handling**: Proper error responses for invalid inputs
4. **Performance**: Response time within acceptable limits
5. **Ordering**: Batch operations maintain deterministic ordering

### Mock Implementation

A mock tool server is provided for testing that implements this contract with deterministic responses based on fixtures.

## Version History

- **v1.0**: Initial contract specification
  - Basic tool call schema
  - Error handling framework
  - Validation rules

## Future Extensions

- **v1.1**: Planned additions
  - Streaming responses for long-running tools
  - Progress callbacks
  - Tool chaining support
