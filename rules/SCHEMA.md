# Rule Schema (Version 1)

The rule engine supports simple, deterministic enrichment rules applied to scanner findings.

## File Format

Each `*.rule` file is a set of `key=value` lines. `#` starts a comment. Blank lines ignored.

Required keys:
- `id` : unique rule identifier string.

Optional keys:
- `rule_version` : integer schema version. Currently only `1` is supported (default if absent).
- `scope` : Scanner name to restrict the rule to (e.g. `world_writable`, `network`) or `*` for all.
- `logic` : `any` for OR semantics across conditions. Omit (default) for AND (all conditions must match).
- `severity` or `severity_override` : Set/override finding severity (`info|low|medium|high|critical`).
- `mitre` : Comma separated MITRE ATT&CK technique IDs (e.g. `T1059.001,T1027`). These are appended (deduplicated externally not yet implemented).

## Conditions

Two styles:

1. Legacy single-condition keys:
```
field=title
contains=World Writable
# or equals=Exact Title
```
If any of `field`, `contains`, `equals` are present (legacy style) they form a single implicit condition.

2. Multi-condition numbered keys:
```
condition0.field=title
condition0.contains=World Writable
condition1.field=description
condition1.regex=.*tmp.*
```
Number suffix after `condition` defines ordering (deterministic). Missing numbers are allowed. Attributes per condition:
- `field` : One of `id`, `title`, `description`, or a metadata key.
- `contains` : Substring must appear.
- `equals` : Exact match (string equality).
- `regex` : ECMAScript regular expression; must compile.

All specified attributes in a condition must be satisfied (logical AND inside condition). Conditions are combined either:
- AND (default): all conditions true.
- OR (`logic=any`): at least one condition true.

If `field` omitted, the finding `description` is used.

## Matching Semantics

Evaluation order is file order; each rule is applied independently (no short-circuit across rules). Matching rules may overwrite severity (last matching rule wins) and append MITRE technique IDs (comma separated). Regex compile failures or empty condition sets produce warnings and rule still loads (but may not match).

## Warnings

During load, aggregated warnings string contains segments of form:
```
<rule_id>:unsupported_version=<v>; <rule_id>:no_conditions; <rule_id>:bad_regex;
```
Use for debugging, logging at WARN level.

## Versioning

`rule_version=1` is the current schema. Future versions may add:
- Negative predicates (e.g., `not_contains`)
- Metadata set operations
- Technique ID de-duplication
- Performance guardrails (condition limits, regex disable flag)

Rules without `rule_version` are treated as version 1.

## Example
```
id=ww_tmp_high
rule_version=1
scope=world_writable
condition0.field=title
condition0.contains=World Writable
condition1.field=description
condition1.regex=dir\s+/tmp
severity=high
mitre=T1000,T1059.001
```
