"""Export a minimal CloudTrail example without copying arbitrary log payloads."""

import argparse
import json
from pathlib import Path

from detect import actor, event_time, load_records, parameters


def sanitize(records):
    identities = {}

    def alias(value):
        if value not in identities:
            identities[value] = f"example-user-{len(identities) + 1:03d}"
        return identities[value]

    result = []
    allowed_names = {
        "ConsoleLogin", "CreateUser", "CreateAccessKey", "AttachUserPolicy",
        "DescribeInstances", "DescribeSecurityGroups", "ListUsers", "ListRoles", "GetCallerIdentity",
    }
    for record in records:
        if record["eventName"] not in allowed_names:
            continue
        name = alias(actor(record) or "unknown")
        clean = {
            "eventName": record["eventName"], "eventTime": event_time(record).isoformat(),
            "userIdentity": {
                "type": "IAMUser", "userName": name, "accountId": "123456789012",
                "arn": f"arn:aws:iam::123456789012:user/{name}",
            },
            "sourceIPAddress": "203.0.113.42",
        }
        if actor(record) is None:
            clean["userIdentity"] = {}
        if record.get("errorCode"):
            clean["errorCode"] = record["errorCode"] if record["errorCode"] in {
                "AccessDenied", "AccessDeniedException", "Client.UnauthorizedOperation",
            } else "OtherError"
        request = parameters(record)
        if request.get("userName"):
            clean.setdefault("requestParameters", {})["userName"] = alias(str(request["userName"]))
        if request.get("policyArn") == "arn:aws:iam::aws:policy/AdministratorAccess":
            clean.setdefault("requestParameters", {})["policyArn"] = request["policyArn"]
        mfa = parameters(record, "additionalEventData").get("MFAUsed")
        if mfa in ("Yes", "No"):
            clean["additionalEventData"] = {"MFAUsed": mfa}
        status = parameters(record, "responseElements").get("ConsoleLogin")
        if status in ("Success", "Failure"):
            clean["responseElements"] = {"ConsoleLogin": status}
        result.append(clean)
    return {"Records": result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="Local CloudTrail JSON file or directory")
    parser.add_argument("output", help="New output JSON file")
    args = parser.parse_args()
    try:
        document = sanitize(load_records(args.input))
        with Path(args.output).open("x", encoding="utf-8") as handle:
            json.dump(document, handle, indent=2)
            handle.write("\n")
    except (OSError, ValueError, EOFError):
        parser.exit(2, "Could not export events. Check the input and use a new output path.\n")


if __name__ == "__main__":
    main()
