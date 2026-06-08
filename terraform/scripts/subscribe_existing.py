#!/usr/bin/env python3
"""
Subscribe all existing CloudWatch Log Groups to the LogSentry Kinesis stream.
Run once on first deploy to catch log groups that already exist.
Future log groups are handled automatically by the auto-subscribe Lambda.
"""
import argparse
import boto3


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stream-arn", required=True)
    parser.add_argument("--role-arn", required=True)
    parser.add_argument("--exclude", default="")
    parser.add_argument("--region", default="us-east-1")
    args = parser.parse_args()

    exclude_prefixes = [p.strip() for p in args.exclude.split(",") if p.strip()]
    logs = boto3.client("logs", region_name=args.region)

    print(f"LogSentry: Subscribing existing log groups to Kinesis...")
    print(f"  Stream: {args.stream_arn}")
    print(f"  Exclude: {exclude_prefixes}")

    paginator = logs.get_paginator("describe_log_groups")
    subscribed = 0
    skipped = 0

    for page in paginator.paginate():
        for lg in page["logGroups"]:
            name = lg["logGroupName"]

            # Check exclusions
            if any(name.startswith(prefix) for prefix in exclude_prefixes):
                skipped += 1
                continue

            # Check if already subscribed
            existing = logs.describe_subscription_filters(logGroupName=name)
            filters = existing.get("subscriptionFilters", [])
            if any(f["filterName"].startswith("logsentry") for f in filters):
                skipped += 1
                continue

            # CloudWatch allows max 2 subscription filters per log group
            if len(filters) >= 2:
                print(f"  SKIP (max filters): {name}")
                skipped += 1
                continue

            try:
                logs.put_subscription_filter(
                    logGroupName=name,
                    filterName="logsentry-auto",
                    filterPattern="",
                    destinationArn=args.stream_arn,
                    roleArn=args.role_arn,
                )
                print(f"  ✓ {name}")
                subscribed += 1
            except Exception as e:
                print(f"  ✗ {name}: {e}")

    print(f"\nDone. Subscribed: {subscribed}, Skipped: {skipped}")


if __name__ == "__main__":
    main()
