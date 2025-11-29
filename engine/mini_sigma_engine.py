"""Very simplified Sigma engine for learning purposes only.

Loads a JSON-lines log file and a minimal Sigma rule, then applies the rule's
selection criteria using exact and substring matching. This is not production-grade
detection logic.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Union


def parse_yaml(text: str) -> dict:
    """Minimal YAML parser supporting nested dicts, lists, and basic values."""

    def parse_value(value: str) -> str:
        if value.startswith('"') and value.endswith('"'):
            return value[1:-1]
        if value.startswith("'") and value.endswith("'"):
            return value[1:-1]
        return value

    root: Dict = {}
    stack: List[Tuple[int, Union[Dict, List]]] = [(-1, root)]

    lines = text.splitlines()
    i = 0
    while i < len(lines):
        raw_line = lines[i]
        line = raw_line.rstrip()
        i += 1

        if not line or line.lstrip().startswith('#'):
            continue

        indent = len(line) - len(line.lstrip(' '))

        while stack and indent <= stack[-1][0]:
            stack.pop()

        if not stack:
            raise ValueError('Invalid YAML indentation')

        parent = stack[-1][1]
        stripped = line.lstrip(' ')

        # Handle list items
        if stripped.startswith('- '):
            if not isinstance(parent, list):
                raise ValueError(f'Unexpected list item outside list context: {line}')
            rest = stripped[2:].strip()
            if not rest:
                new_dict: Dict = {}
                parent.append(new_dict)
                stack.append((indent + 2, new_dict))
            else:
                parent.append(parse_value(rest))
            continue

        if ':' not in stripped:
            raise ValueError(f'Invalid line in YAML: {line}')

        key, val = stripped.split(':', 1)
        key = key.strip()
        val = val.strip()

        if val == '':
            # Peek ahead to determine if next line is a list item
            next_indent = -1
            next_is_list = False
            for j in range(i, len(lines)):
                peek_line = lines[j].rstrip()
                if not peek_line or peek_line.lstrip().startswith('#'):
                    continue
                next_indent = len(peek_line) - len(peek_line.lstrip(' '))
                next_is_list = peek_line.lstrip().startswith('- ')
                break

            if next_is_list and next_indent > indent:
                new_container: Union[Dict, List] = []
            else:
                new_container = {}

            if isinstance(parent, list):
                parent.append({key: new_container})
            else:
                parent[key] = new_container
            stack.append((indent, new_container))
        else:
            # Value on same line
            value = parse_value(val)
            if isinstance(parent, list):
                parent.append({key: value})
            else:
                parent[key] = value

    return root


def load_rule(path: Path) -> dict:
    """Load and parse a Sigma YAML rule file."""
    text = path.read_text(encoding='utf-8')
    rule = parse_yaml(text)
    if not rule:
        raise ValueError('Empty rule file')
    return rule


def load_events(path: Path) -> List[dict]:
    """Load JSON-lines log file, skipping comments and blank lines."""
    events: List[dict] = []

    for lineno, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise ValueError(f'Invalid JSON on line {lineno}: {exc}') from exc

    return events


def matches_selection(event: dict, selection: dict) -> bool:
    """Check if a log event matches all fields in a selection block."""

    def is_wildcard_pattern(value: str) -> bool:
        return isinstance(value, str) and value.startswith('*') and value.endswith('*')

    for raw_key, raw_value in selection.items():
        # Handle modifiers like field|contains
        if '|' in raw_key:
            key, operator = raw_key.split('|', 1)
        else:
            key, operator = raw_key, 'equals'

        event_value = event.get(key)
        if event_value is None:
            return False

        if operator == 'contains':
            patterns = raw_value if isinstance(raw_value, list) else [raw_value]
            if not any(str(pattern) in str(event_value) for pattern in patterns):
                return False
        else:
            # Exact or wildcard match
            if is_wildcard_pattern(raw_value):
                pattern = raw_value.strip('*')
                if pattern not in str(event_value):
                    return False
            elif str(event_value) != str(raw_value):
                return False

    return True


def find_matches(rule: dict, events: List[dict]) -> List[dict]:
    """Return all events that match any selection block in the rule."""
    detection = rule.get('detection', {})

    # Gather all selection blocks (selection, selection1, selection2, etc.)
    selections: List[dict] = []
    for key, value in detection.items():
        if key.startswith('selection') and isinstance(value, dict):
            selections.append(value)

    matches: List[dict] = []
    for event in events:
        if any(matches_selection(event, sel) for sel in selections):
            matches.append(event)

    return matches


def format_event(event: dict) -> str:
    """Return a short summary of identifying fields for display."""
    pieces: List[str] = []

    for key in ('user', 'process_name', 'url', 'src_ip', 'client_ip'):
        if key in event:
            pieces.append(f"{key}={event[key]}")

    if not pieces:
        pieces.append(f"event_id={event.get('event_id', 'unknown')}")

    return ', '.join(pieces)


def apply_rule_to_logs(
    rule_path: Union[str, Path],
    events: List[dict]
) -> Tuple[str, List[dict]]:
    """Apply a rule to events and return (title, matched_events)."""
    resolved = Path(rule_path)
    rule = load_rule(resolved)
    matches = find_matches(rule, events)
    title = rule.get('title', 'Unnamed rule')
    return title, matches


def main() -> None:
    """CLI entry point for running a single rule against logs."""
    parser = argparse.ArgumentParser(
        description='Run a toy Sigma rule against JSON logs'
    )
    parser.add_argument(
        '--logs', required=True, type=Path, help='JSON-lines log file'
    )
    parser.add_argument(
        '--rule', required=True, type=Path, help='Sigma YAML rule file'
    )
    args = parser.parse_args()

    if not args.logs.exists():
        print(f'Log file not found: {args.logs}', file=sys.stderr)
        sys.exit(1)

    if not args.rule.exists():
        print(f'Rule file not found: {args.rule}', file=sys.stderr)
        sys.exit(1)

    try:
        events = load_events(args.logs)
        title, matches = apply_rule_to_logs(args.rule, events)
    except Exception as exc:
        print(f'Error loading inputs: {exc}', file=sys.stderr)
        sys.exit(1)

    for event in matches:
        summary = format_event(event)
        print(f"Matched rule '{title}' on event: {summary}")

    print(f"\n{len(matches)} events matched rule '{title}'")


if __name__ == '__main__':
    main()
