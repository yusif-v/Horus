"""MITRE ATT&CK technique mapping for attack tags.

Provides a static lookup from Horus attack tags to MITRE ATT&CK technique
IDs, plus helper functions to resolve techniques for a CVE's tag list.
"""

from __future__ import annotations

TAG_TO_ATTACK: dict[str, list[dict[str, str]]] = {
    "rce": [
        {"id": "T1190", "name": "Exploit Public-Facing Application"},
        {"id": "T1059", "name": "Command and Scripting Interpreter"},
    ],
    "lpe": [
        {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
    ],
    "xss": [
        {"id": "T1059.007", "name": "JavaScript"},
        {"id": "T1189", "name": "Drive-By Compromise"},
    ],
    "sql-injection": [
        {"id": "T1190", "name": "Exploit Public-Facing Application"},
    ],
    "auth-bypass": [
        {"id": "T1078", "name": "Valid Accounts"},
        {"id": "T1556", "name": "Modify Authentication Process"},
    ],
    "path-traversal": [
        {"id": "T1083", "name": "File and Directory Discovery"},
        {"id": "T1006", "name": "File System Logical Offsets"},
    ],
    "command-injection": [
        {"id": "T1059", "name": "Command and Scripting Interpreter"},
    ],
    "deserialization": [
        {"id": "T1203", "name": "Exploitation for Client Execution"},
        {"id": "T1059", "name": "Command and Scripting Interpreter"},
    ],
    "info-disclosure": [
        {"id": "T1552", "name": "Unsecured Credentials"},
        {"id": "T1040", "name": "Network Sniffing"},
    ],
    "dos": [
        {"id": "T1498", "name": "Network Denial of Service"},
        {"id": "T1499", "name": "Endpoint Denial of Service"},
    ],
    "csrf": [
        {"id": "T1059.007", "name": "JavaScript"},
        {"id": "T1189", "name": "Drive-By Compromise"},
    ],
    "ssrf": [
        {"id": "T1190", "name": "Exploit Public-Facing Application"},
        {"id": "T1059.007", "name": "JavaScript"},
    ],
    "xxe": [
        {"id": "T1190", "name": "Exploit Public-Facing Application"},
        {"id": "T1221", "name": "Exploitation for Defense Evasion"},
    ],
    "buffer-overflow": [
        {"id": "T1203", "name": "Exploitation for Client Execution"},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
    ],
    "use-after-free": [
        {"id": "T1495", "name": "Firmware Corruption"},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
    ],
    "heap-overflow": [
        {"id": "T1495", "name": "Firmware Corruption"},
        {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
    ],
    "race-condition": [
        {"id": "T1203", "name": "Exploitation for Client Execution"},
    ],
    "sandbox-escape": [
        {"id": "T1068", "name": "Exploitation for Privilege Escalation"},
        {"id": "T1499", "name": "Endpoint Denial of Service"},
    ],
    "file-inclusion": [
        {"id": "T1190", "name": "Exploit Public-Facing Application"},
        {"id": "T1059", "name": "Command and Scripting Interpreter"},
    ],
    "supply-chain": [
        {"id": "T1195", "name": "Supply Chain Compromise"},
    ],
    "crypto-weakness": [
        {"id": "T1557", "name": "Adversary-in-the-Middle"},
        {"id": "T1040", "name": "Network Sniffing"},
    ],
}

# Reverse lookup: technique_id → list of tags that map to it
ATTACK_TO_TAGS: dict[str, list[str]] = {}
for _tag, _techniques in TAG_TO_ATTACK.items():
    for _t in _techniques:
        _tid = _t["id"]
        if _tid not in ATTACK_TO_TAGS:
            ATTACK_TO_TAGS[_tid] = []
        if _tag not in ATTACK_TO_TAGS[_tid]:
            ATTACK_TO_TAGS[_tid].append(_tag)


def get_attck_for_tag(tag: str) -> list[dict[str, str]]:
    """Return the list of ATT&CK technique dicts for a single attack tag."""
    return TAG_TO_ATTACK.get(tag, [])


def get_attck_for_cve(tags: list[str]) -> list[dict[str, str]]:
    """Return de-duplicated ATT&CK techniques for a list of attack tags.

    Preserves first-seen order; if the same technique is reachable from
    multiple tags, only the first occurrence is kept.
    """
    seen: set[str] = set()
    result: list[dict[str, str]] = []
    for tag in tags:
        for technique in TAG_TO_ATTACK.get(tag, []):
            tid = technique["id"]
            if tid not in seen:
                seen.add(tid)
                result.append(technique)
    return result


def get_all_techniques() -> list[dict[str, str]]:
    """Return every unique ATT&CK technique across all tags, sorted by ID."""
    seen: set[str] = set()
    result: list[dict[str, str]] = []
    for techniques in TAG_TO_ATTACK.values():
        for t in techniques:
            if t["id"] not in seen:
                seen.add(t["id"])
                result.append(t)
    return sorted(result, key=lambda x: x["id"])
