import json
import glob
from collections import defaultdict

# === LOAD ALL LOGS ===
files = glob.glob("logs/**/*.json", recursive=True)
all_records = []
for f in files:
    data = json.load(open(f))
    all_records.extend(data['Records'])

print(f"Loaded {len(all_records)} events\n")

# === RULE 1: Console Login without MFA ===
def rule_console_login_no_mfa(records):
    findings = []
    for r in records:
        if r['eventName'] == 'ConsoleLogin':
            mfa = r.get('additionalEventData', {}).get('MFAUsed', 'No')
            if mfa == 'No':
                findings.append({
                    'rule': 'ConsoleLogin without MFA',
                    'user': r['userIdentity'].get('userName', 'N/A'),
                    'time': r['eventTime'],
                    'ip':   r.get('sourceIPAddress')
                })
    return findings

# === RULE 2: New IAM User Created ===
def rule_iam_user_created(records):
    findings = []
    for r in records:
        if r['eventName'] == 'CreateUser':
            findings.append({
                'rule': 'New IAM User Created',
                'user': r['userIdentity'].get('userName', 'N/A'),
                'time': r['eventTime'],
                'new_user': r.get('requestParameters', {}).get('userName')
            })
    return findings

# === RULE 3: Admin Policy Attached ===
def rule_admin_policy_attached(records):
    findings = []
    for r in records:
        if r['eventName'] == 'AttachUserPolicy':
            policy = r.get('requestParameters', {}).get('policyArn', '')
            if 'AdministratorAccess' in policy:
                findings.append({
                    'rule': 'AdministratorAccess Policy Attached',
                    'user': r['userIdentity'].get('userName', 'N/A'),
                    'time': r['eventTime'],
                    'target_user': r.get('requestParameters', {}).get('userName')
                })
    return findings

# === RULE 4: Access Key Created ===
def rule_access_key_created(records):
    findings = []
    for r in records:
        if r['eventName'] == 'CreateAccessKey':
            findings.append({
                'rule': 'Access Key Created',
                'user': r['userIdentity'].get('userName', 'N/A'),
                'time': r['eventTime'],
                'target_user': r.get('requestParameters', {}).get('userName')
            })
    return findings

# === RULE 5: Access Denied Spike (3+ in same session) ===
def rule_access_denied_spike(records):
    denied = defaultdict(list)
    for r in records:
        if r.get('errorCode') in ('AccessDenied', 'Client.UnauthorizedOperation'):
            user = r['userIdentity'].get('userName', 'N/A')
            denied[user].append(r['eventTime'])
    findings = []
    for user, times in denied.items():
        if len(times) >= 2:
            findings.append({
                'rule': 'Access Denied Spike',
                'user': user,
                'count': len(times),
                'times': times
            })
    return findings

# === RULE 6: Reconnaissance Pattern (3+ Describe/List in 5 min) ===
def rule_recon_pattern(records):
    from datetime import datetime, timezone
    recon_events = ['DescribeInstances', 'DescribeSecurityGroups',
                    'ListUsers', 'ListRoles', 'GetCallerIdentity']
    user_events = defaultdict(list)
    for r in records:
        if r['eventName'] in recon_events:
            user = r['userIdentity'].get('userName', 'N/A')
            t = datetime.fromisoformat(r['eventTime'].replace('Z', '+00:00'))
            user_events[user].append(t)

    findings = []
    for user, times in user_events.items():
        times.sort()
        for i in range(len(times)):
            window = [t for t in times if (t - times[i]).total_seconds() <= 300]
            if len(window) >= 3:
                findings.append({
                    'rule': 'Reconnaissance Pattern Detected',
                    'user': user,
                    'count': len(window),
                    'window': '5 minutes'
                })
                break
    return findings

# === RUN ALL RULES ===
rules = [
    rule_console_login_no_mfa,
    rule_iam_user_created,
    rule_admin_policy_attached,
    rule_access_key_created,
    rule_access_denied_spike,
    rule_recon_pattern,
]

for rule in rules:
    findings = rule(all_records)
    if findings:
        print(f"ALERT: {findings[0]['rule']} — {len(findings)} finding(s)")
        for f in findings:
            print(f"   {f}")
        print()