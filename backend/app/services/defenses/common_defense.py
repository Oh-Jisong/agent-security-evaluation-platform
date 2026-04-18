import re
from typing import Dict, List, Tuple


def match_patterns(text: str, patterns: List[str]) -> List[str]:
    lowered = text.lower()
    return [pattern for pattern in patterns if pattern.lower() in lowered]


def sanitize_text(text: str, patterns: List[str]) -> Tuple[str, List[str]]:
    sanitized = text
    removed = []

    for pattern in patterns:
        if pattern in sanitized:
            sanitized = sanitized.replace(pattern, "[REMOVED]")
            removed.append(pattern)

    return sanitized, removed


def block_terms_in_output(response: str, terms: List[str]) -> List[str]:
    lowered = response.lower()
    return [term for term in terms if term.lower() in lowered]


def detect_sensitive_data(response: str) -> List[str]:
    findings = []

    email_pattern = r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    if re.search(email_pattern, response):
        findings.append("email")

    phone_pattern = r"\b01[0-9]-?\d{3,4}-?\d{4}\b"
    if re.search(phone_pattern, response):
        findings.append("phone")

    return findings


def detect_risky_actions(response: str, action_terms: List[str]) -> List[str]:
    lowered = response.lower()
    return [term for term in action_terms if term.lower() in lowered]


def simple_risk_score(text: str, weighted_patterns: Dict[str, int]) -> int:
    lowered = text.lower()
    score = 0

    for pattern, weight in weighted_patterns.items():
        if pattern.lower() in lowered:
            score += weight

    return min(score, 5)