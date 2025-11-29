"""Helper script that applies every Sigma rule in a directory to a shared log file.

Usage:
    python run_all_rules.py --logs logs/sample.json --rules-dir rules/
"""

import argparse
import sys
from pathlib import Path

# Allow importing from engine/ when run from repo root
sys.path.insert(0, str(Path(__file__).parent))

from engine.mini_sigma_engine import apply_rule_to_logs, load_events


def main() -> None:
    """CLI entry point for batch rule execution."""
    parser = argparse.ArgumentParser(
        description='Run all Sigma rules against a log file'
    )
    parser.add_argument(
        '--logs', required=True, type=Path, help='JSON-lines log file'
    )
    parser.add_argument(
        '--rules-dir', required=True, type=Path, help='Directory with YAML rules'
    )
    args = parser.parse_args()

    if not args.logs.exists():
        print(f'Log file not found: {args.logs}', file=sys.stderr)
        sys.exit(1)

    if not args.rules_dir.is_dir():
        print(f'Rules directory not found: {args.rules_dir}', file=sys.stderr)
        sys.exit(1)

    try:
        events = load_events(args.logs)
    except Exception as exc:
        print(f'Error reading logs: {exc}', file=sys.stderr)
        sys.exit(1)

    # Gather all rule files
    rule_files = sorted(args.rules_dir.glob('*.yml')) + sorted(args.rules_dir.glob('*.yaml'))

    if not rule_files:
        print(f'No .yml or .yaml files found in {args.rules_dir}')
        sys.exit(0)

    report = []
    for rule_path in rule_files:
        try:
            title, matches = apply_rule_to_logs(rule_path, events)
            report.append((rule_path.name, title, len(matches)))
        except Exception as exc:
            print(f'Skipping {rule_path.name}: {exc}', file=sys.stderr)
            continue

    if not report:
        print('No rules were successfully applied.')
        return

    print('\n' + '=' * 60)
    print('RULE EXECUTION SUMMARY')
    print('=' * 60)
    print(f'Log file: {args.logs}')
    print(f'Total events: {len(events)}')
    print('-' * 60)

    total_matches = 0
    for filename, title, count in report:
        status = f'{count} matches' if count > 0 else 'no matches'
        print(f'[{filename}] {title}: {status}')
        total_matches += count

    print('-' * 60)
    print(f'Total: {len(report)} rules applied, {total_matches} total matches')
    print('=' * 60)


if __name__ == '__main__':
    main()
