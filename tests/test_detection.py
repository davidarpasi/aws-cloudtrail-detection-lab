import contextlib
import copy
import gzip
import io
import json
import tempfile
import unittest
from pathlib import Path

import detect
from anonym import sanitize


def event(name="ListUsers", time="2026-01-01T00:00:00Z", identity=None, **fields):
    return {"eventName": name, "eventTime": time,
            "userIdentity": {"arn": "arn:aws:iam::123456789012:user/example"} if identity is None else identity,
            **fields}


class DetectionTests(unittest.TestCase):
    def test_recon_does_not_combine_events_hours_apart(self):
        records = [event(time=f"2026-01-01T0{hour}:00:00Z") for hour in range(3)]
        self.assertEqual(detect.rule_recon_pattern(records), [])

    def test_window_accepts_boundary_and_unsorted_input(self):
        records = [event(time=t) for t in ["2026-01-01T00:05:00Z", "2026-01-01T00:00:00Z", "2026-01-01T00:02:00Z"]]
        self.assertEqual(detect.rule_recon_pattern(records)[0]["count"], 3)
        records[0]["eventTime"] = "2026-01-01T00:05:01Z"
        self.assertEqual(detect.rule_recon_pattern(records), [])

    def test_denied_threshold_and_window(self):
        records = [event(time=f"2026-01-01T00:0{i}:00Z", errorCode="AccessDenied") for i in range(3)]
        self.assertEqual(detect.rule_access_denied_spike(records[:2]), [])
        self.assertEqual(len(detect.rule_access_denied_spike(records)), 1)
        records[-1]["eventTime"] = "2026-01-01T01:00:00Z"
        self.assertEqual(detect.rule_access_denied_spike(records), [])

    def test_roles_and_unknown_identities_are_not_combined(self):
        records = [event(identity={"arn": f"arn:aws:sts::123456789012:assumed-role/example/session-{i}"}) for i in range(3)]
        self.assertEqual(detect.rule_recon_pattern(records), [])
        self.assertEqual(detect.rule_recon_pattern([event(identity={}) for _ in range(3)]), [])

    def test_login_requires_success_and_explicit_no_mfa(self):
        record = event("ConsoleLogin", responseElements={"ConsoleLogin": "Success"}, additionalEventData={"MFAUsed": "No"})
        self.assertEqual(len(detect.rule_console_login_no_mfa([record])), 1)
        for response, mfa in [({"ConsoleLogin": "Failure"}, {"MFAUsed": "No"}), ({"ConsoleLogin": "Success"}, {}), (None, None), ({"ConsoleLogin": "Success"}, {"MFAUsed": "Yes"})]:
            record.update(responseElements=response, additionalEventData=mfa)
            self.assertEqual(detect.rule_console_login_no_mfa([record]), [])

    def test_failed_mutations_and_null_parameters(self):
        for name, rule in [("CreateUser", detect.rule_iam_user_created), ("CreateAccessKey", detect.rule_access_key_created), ("AttachUserPolicy", detect.rule_admin_policy_attached)]:
            self.assertEqual(rule([event(name, errorCode="AccessDenied", requestParameters=None)]), [])
        self.assertEqual(detect.rule_admin_policy_attached([event("AttachUserPolicy", requestParameters=None)]), [])

    def test_admin_policy_requires_exact_aws_managed_policy(self):
        record = event("AttachUserPolicy", requestParameters={"policyArn": "arn:aws:iam::123456789012:policy/NotAdministratorAccess"})
        self.assertEqual(detect.rule_admin_policy_attached([record]), [])
        record["requestParameters"]["policyArn"] = "arn:aws:iam::aws:policy/AdministratorAccess"
        self.assertEqual(len(detect.rule_admin_policy_attached([record])), 1)

    def test_export_drops_nested_identifiers_secrets_and_embedded_text(self):
        record = event(identity={"arn": "private-actor", "sessionContext": {"sessionIssuer": {"accountId": "999999999999"}}}, responseElements={"accessKey": {"accessKeyId": "sensitive-id", "secretAccessKey": "sensitive-secret"}}, extra={"text": "private text sensitive-id"})
        original = copy.deepcopy(record)
        output = json.dumps(sanitize([record]))
        for value in ["private-actor", "999999999999", "sensitive-id", "sensitive-secret", "private text"]:
            self.assertNotIn(value, output)
        self.assertEqual(record, original)

    def test_loading_gzip_duplicates_and_malformed_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.json.gz"
            with gzip.open(path, "wt") as handle:
                json.dump({"Records": [event(), event()]}, handle)
            self.assertEqual(len(detect.load_records(directory)), 1)
            bad = Path(directory) / "bad.json"
            for document in [{}, {"Records": []}, {"Records": [{"eventName": "ListUsers"}]}, {"Records": [event(userIdentity="invalid")]}]:
                bad.write_text(json.dumps(document))
                with self.assertRaises(ValueError):
                    detect.load_records(bad)

    def test_cli_sample_and_bad_input(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(detect.main([str(Path(__file__).resolve().parents[1] / "sample_events.json"), "--json"]), 0)
        report = json.loads(out.getvalue())
        self.assertEqual(report["events"], 12)
        self.assertEqual(len(report["findings"]), 6)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(detect.main(["does-not-exist.json"]), 2)


if __name__ == "__main__":
    unittest.main()
