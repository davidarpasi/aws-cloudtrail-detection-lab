# AWS CloudTrail Detection Lab

I built this to get more comfortable with CloudTrail and IAM. I enabled a trail in my own AWS account, generated IAM and EC2 activity, then wrote Python rules to investigate the events.

The original experiment covered more than 5,000 events. The public demo now uses a small synthetic dataset, so it runs locally without an AWS account or credentials.

## Run it

Python 3.12 or newer is enough. There are no third-party dependencies.

```bash
git clone https://github.com/davidarpasi/aws-cloudtrail-detection-lab.git
cd aws-cloudtrail-detection-lab
python detect.py sample_events.json
python detect.py sample_events.json --json
python -m unittest discover -s tests -v
```

The included sample produces six findings across twelve events. See [the example report](docs/example-output.json).

You can also pass a local directory containing CloudTrail `.json` or `.json.gz` files. Invalid input exits with code 2. A successful analysis exits with code 0, including when it finds suspicious activity. Exact duplicate records are counted once.

## What the rules look for

| Rule | Condition |
| --- | --- |
| Login without MFA | A successful console login with `MFAUsed` explicitly set to `No` |
| IAM user created | A successful `CreateUser` event |
| Admin policy attached | A successful attachment of the AWS managed `AdministratorAccess` policy |
| Access key created | A successful `CreateAccessKey` event |
| Access denied spike | At least three denied calls from the same actor within five minutes |
| Recon pattern | At least three calls from a small list of IAM/EC2 discovery APIs within five minutes |

The five-minute boundary is inclusive. Window rules report the first matching window for each actor. Actor grouping uses the identity ARN, then principal ID, then username. Records without any of those fields are excluded from grouped rules rather than combined into one unknown user.

These are investigation signals. Creating a user, attaching a policy or listing instances can be normal administration. The recon rule also counts denied discovery calls. This is a local learning lab, not a complete detection system.

## Data handling

The committed events and example report are fictional. I removed the original screenshots from the current version because they included account and host details. Older commits may still contain them.

For local logs, `python anonym.py INPUT NEW_OUTPUT.json` exports only the fields used by these rules. It replaces identities, uses a documentation IP address, and drops arbitrary nested payloads, access-key fields and free text. This is a reduced example export, not a faithful anonymized copy. Review its output before sharing it. Detection output from your own logs can still contain real identities and source addresses.

## How it fits together

```text
CloudTrail JSON / JSON.GZ
        |
        v
load and validate -> remove exact duplicates -> six rules -> text / JSON report
```

The original AWS setup used CloudTrail delivery to S3 in `eu-north-1`. That setup was created manually; there is no Terraform deployment in this repository yet.

If you repeat the AWS experiment, use a disposable account, restrict access to the log bucket, and check the costs of the services you enable. Afterwards remove test policy attachments, disable and delete lab access keys, delete test identities and EC2 resources, and remove the trail and stored logs when no longer needed. The local demo creates no AWS resources.

## Next

My next step is to make the AWS setup reproducible with Terraform and document the IAM permissions and teardown. I am keeping the detection rules small enough to test and explain first.

MIT license.
