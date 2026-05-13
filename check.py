import json
import glob

files = glob.glob("logs/**/*.json", recursive=True)
all_records = []

for f in files:
    data = json.load(open(f))
    all_records.extend(data['Records'])

print(f"Total events found: {len(all_records)}")
print()

# Érdekes eventek szűrése
interesting = [
    "CreateUser", "DeleteUser",
    "CreateAccessKey", "DeleteAccessKey",
    "AttachUserPolicy", "DetachUserPolicy",
    "ConsoleLogin",
    "DescribeInstances", "DescribeSecurityGroups",
    "GetCallerIdentity",
    "ListUsers", "ListRoles",
]

print("=== INTERESTING EVENTS ===")
for record in all_records:
    if record['eventName'] in interesting:
        user = record['userIdentity'].get('userName', 'N/A')
        error = record.get('errorCode', '')
        print(f"{record['eventName']} | {user} | {record['eventTime']} | {error}")