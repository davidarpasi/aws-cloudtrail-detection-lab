# aws-cloudtrail-detection-lab

Detection engineering lab using real AWS CloudTrail logs.

I wanted a hands-on way to learn CloudTrail and IAM event patterns, so I set up a trail on my own AWS account, performed a series of actions (some intentionally suspicious), and wrote Python rules to flag them.

## What I did

- Enabled CloudTrail with S3 delivery (eu-north-1)
- Created an IAM user, issued access keys, attached AdministratorAccess
- Triggered AccessDenied errors intentionally to simulate permission probing
- Downloaded and parsed 5000+ real events from S3

## Detection rules

- Console login without MFA
- New IAM user created
- AdministratorAccess policy attached
- Access key created for a user
- Access denied spike (3+ failures, same user)
- Recon pattern (3+ Describe/List calls within 5 min)

## Files

- `detect.py` — runs all detection rules against a log directory
- `sample_events.json` — 35 anonymized real events for testing

## Stack

AWS Free Tier · CloudTrail · Python 3 · AWS CLI