"""Mini SIEM detection engine package."""

from .mini_sigma_engine import (
    apply_rule_to_logs,
    find_matches,
    load_events,
    load_rule,
    matches_selection,
    parse_yaml,
)

__all__ = [
    'apply_rule_to_logs',
    'find_matches',
    'load_events',
    'load_rule',
    'matches_selection',
    'parse_yaml',
]
