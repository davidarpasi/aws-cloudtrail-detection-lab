import json
import glob
import re

files = glob.glob("logs/**/*.json", recursive=True)
all_records = []
for f in files:
    data = json.load(open(f))
    all_records.extend(data['Records'])

interesting = [
    'CreateUser', 'CreateAccessKey', 'AttachUserPolicy',
    'DetachUserPolicy', 'ConsoleLogin', 'GetCallerIdentity',
    'ListUsers', 'ListRoles', 'DescribeInstances',
    'DescribeSecurityGroups'
]

filtered = [r for r in all_records if r['eventName'] in interesting]

for r in filtered:
    if 'userIdentity' in r:
        if 'accountId' in r['userIdentity']:
            r['userIdentity']['accountId'] = '123456789012'
        if 'arn' in r['userIdentity']:
            r['userIdentity']['arn'] = r['userIdentity']['arn'].replace('122610489383', '123456789012')
        if 'principalId' in r['userIdentity']:
            r['userIdentity']['principalId'] = 'ANONYMIZED'
        if 'accessKeyId' in r['userIdentity']:
            r['userIdentity']['accessKeyId'] = 'ASIAXXXXXXXXXXXXXXXX'
    if 'accessKeyId' in r:
        r['accessKeyId'] = 'ASIAXXXXXXXXXXXXXXXX'
    if 'sourceIPAddress' in r:
        r['sourceIPAddress'] = '203.0.113.42'
    if 'recipientAccountId' in r:
        r['recipientAccountId'] = '123456789012'

json.dump({'Records': filtered}, open('sample_events.json', 'w'), indent=2)
print(f'Saved {len(filtered)} anonymized events')