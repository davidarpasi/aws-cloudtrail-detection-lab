"""Small CloudTrail detection rules and a local JSON command-line interface."""

import argparse
import gzip
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path


def event_time(record):
    value = record.get("eventTime")
    if not isinstance(value, str):
        raise ValueError("eventTime must be an ISO 8601 timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("eventTime must include a timezone")
    return parsed


def actor(record):
    identity = record.get("userIdentity") or {}
    for field in ("arn", "principalId", "userName"):
        if identity.get(field):
            return str(identity[field])
    return None


def parameters(record, field="requestParameters"):
    return record.get(field) or {}


def finding(record, rule, **details):
    return {"rule": rule, "actor": actor(record) or "unknown", "time": record["eventTime"], **details}


def rule_console_login_no_mfa(records):
    return [
        finding(r, "ConsoleLogin without MFA", ip=r.get("sourceIPAddress"))
        for r in records
        if r["eventName"] == "ConsoleLogin"
        and not r.get("errorCode")
        and parameters(r, "responseElements").get("ConsoleLogin") == "Success"
        and parameters(r, "additionalEventData").get("MFAUsed") == "No"
    ]


def rule_iam_user_created(records):
    return [
        finding(r, "New IAM User Created", new_user=parameters(r).get("userName"))
        for r in records if r["eventName"] == "CreateUser" and not r.get("errorCode")
    ]


def rule_admin_policy_attached(records):
    return [
        finding(r, "AdministratorAccess Policy Attached", target_user=parameters(r).get("userName"))
        for r in records
        if r["eventName"] == "AttachUserPolicy" and not r.get("errorCode")
        and parameters(r).get("policyArn") == "arn:aws:iam::aws:policy/AdministratorAccess"
    ]


def rule_access_key_created(records):
    return [
        finding(r, "Access Key Created", target_user=parameters(r).get("userName"))
        for r in records if r["eventName"] == "CreateAccessKey" and not r.get("errorCode")
    ]


def window_findings(records, rule, threshold=3, seconds=300):
    grouped = defaultdict(list)
    for record in records:
        identity = actor(record)
        if identity is not None:
            grouped[identity].append(record)
    findings = []
    for identity, events in sorted(grouped.items()):
        events.sort(key=event_time)
        left = 0
        for right, record in enumerate(events):
            while event_time(record) - event_time(events[left]) > timedelta(seconds=seconds):
                left += 1
            if right - left + 1 >= threshold:
                findings.append({
                    "rule": rule, "actor": identity, "count": right - left + 1,
                    "window_seconds": seconds, "start": events[left]["eventTime"],
                    "end": record["eventTime"],
                })
                break
    return findings


def rule_access_denied_spike(records):
    denied = [r for r in records if r.get("errorCode") in (
        "AccessDenied", "AccessDeniedException", "Client.UnauthorizedOperation",
    )]
    return window_findings(denied, "Access Denied Spike")


def rule_recon_pattern(records):
    names = {"DescribeInstances", "DescribeSecurityGroups", "ListUsers", "ListRoles", "GetCallerIdentity"}
    return window_findings([r for r in records if r["eventName"] in names], "Reconnaissance Pattern")


RULES = (
    rule_console_login_no_mfa, rule_iam_user_created, rule_admin_policy_attached,
    rule_access_key_created, rule_access_denied_spike, rule_recon_pattern,
)


def load_records(source):
    source = Path(source)
    files = sorted(p for p in source.rglob("*") if p.is_file() and (
        p.name.endswith(".json") or p.name.endswith(".json.gz")
    )) if source.is_dir() else [source]
    if not files:
        raise ValueError("No JSON or JSON.GZ files found")
    records = []
    seen = set()
    for path in files:
        opener = gzip.open if path.name.endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8") as handle:
            document = json.load(handle)
        if not isinstance(document, dict) or not isinstance(document.get("Records"), list):
            raise ValueError("Expected a CloudTrail object containing a Records array")
        for record in document["Records"]:
            if not isinstance(record, dict) or not isinstance(record.get("eventName"), str):
                raise ValueError("Each record must contain an eventName string")
            event_time(record)
            for field in ("userIdentity", "requestParameters", "responseElements", "additionalEventData"):
                if record.get(field) is not None and not isinstance(record[field], dict):
                    raise ValueError(f"{field} must be an object or null")
            marker = json.dumps(record, sort_keys=True)
            if marker not in seen:
                seen.add(marker)
                records.append(record)
    if not records:
        raise ValueError("No events found")
    return records


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", default="sample_events.json", help="CloudTrail JSON file or directory")
    parser.add_argument("--json", action="store_true", help="Print a JSON report")
    args = parser.parse_args(argv)
    try:
        records = load_records(args.input)
    except (OSError, ValueError, EOFError):
        print("Could not read events. Check the path, JSON structure and timestamp fields.", file=sys.stderr)
        return 2
    findings = [item for rule in RULES for item in rule(records)]
    if args.json:
        print(json.dumps({"events": len(records), "findings": findings}, indent=2))
    else:
        print(f"Loaded {len(records)} events")
        for item in findings:
            print(json.dumps(item, sort_keys=True))
        print(f"Findings: {len(findings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
