"""List event names and counts without printing identities or event payloads."""

import argparse
from collections import Counter

from detect import load_records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", default="sample_events.json")
    args = parser.parse_args()
    try:
        records = load_records(args.input)
    except (OSError, ValueError, EOFError):
        parser.exit(2, "Could not read CloudTrail events.\n")
    print(f"Total events: {len(records)}")
    for name, count in sorted(Counter(r["eventName"] for r in records).items()):
        print(f"{name}: {count}")


if __name__ == "__main__":
    main()
