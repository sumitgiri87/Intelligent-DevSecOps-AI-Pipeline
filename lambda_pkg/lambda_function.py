import os
import json
import boto3
import requests

SSM = boto3.client("ssm", region_name="ca-central-1")
S3 = boto3.client("s3", region_name="ca-central-1")

def get_slack_webhook():
    """Fetch Slack webhook from SSM."""
    name = os.environ.get("SLACK_SSM_PARAM", "/devsecops/slack_webhook")
    res = SSM.get_parameter(Name=name, WithDecryption=True)
    return res["Parameter"]["Value"]

def post_slack(text):
    """Send message to Slack."""
    webhook = get_slack_webhook()
    requests.post(webhook, json={"text": text})

def parse_bandit(bandit_json):
    """Parse Bandit report JSON and return top finding."""
    try:
        data = json.loads(bandit_json)
        results = data.get("results", [])
        if not results:
            return None
        top = results[0]
        return {
            "issue_text": top.get("issue_text", "Unknown issue"),
            "filename": top.get("filename", "<unknown>"),
            "line": top.get("line_number", 0),
            "test": top.get("test", "")
        }
    except Exception as e:
        return {"error": str(e)}

def parse_trivy(trivy_json):
    """Parse Trivy report JSON and summarize vulnerabilities."""
    try:
        data = json.loads(trivy_json)
        vulnerabilities = []
        for result in data.get("Results", []):
            for vuln in result.get("Vulnerabilities", []):
                vulnerabilities.append({
                    "pkg": vuln.get("PkgName", ""),
                    "severity": vuln.get("Severity", ""),
                    "title": vuln.get("Title", ""),
                    "version": vuln.get("InstalledVersion", "")
                })
        return vulnerabilities if vulnerabilities else None
    except Exception as e:
        return {"error": str(e)}

def lambda_handler(event, context):
    bucket = event.get("bucket")
    prefix = "intelligent-devsecop/BuildArtif/"

    if not bucket:
        post_slack(":warning: ai-suggester invoked without bucket")
        return {"status": "bad-request"}

    # List all folders in BuildArtif/
    resp = S3.list_objects_v2(Bucket=bucket, Prefix=prefix, Delimiter='/')
    folders = [x['Prefix'] for x in resp.get('CommonPrefixes', [])]

    if not folders:
        post_slack(":warning: No folders found in BuildArtif/")
        return {"status": "no-folders"}

    # Pick the latest folder
    latest_folder = sorted(folders, reverse=True)[0]

    # Construct keys for reports
    bandit_key = f"{latest_folder}bandit-report.json"
    trivy_key = f"{latest_folder}trivy-report.json"

    # Fetch Bandit report
    try:
        obj = S3.get_object(Bucket=bucket, Key=bandit_key)
        bandit_json = obj["Body"].read().decode("utf-8")
        bandit_parsed = parse_bandit(bandit_json)
    except S3.exceptions.NoSuchKey:
        bandit_parsed = None

    # Fetch Trivy report
    try:
        obj = S3.get_object(Bucket=bucket, Key=trivy_key)
        trivy_json = obj["Body"].read().decode("utf-8")
        trivy_parsed = parse_trivy(trivy_json)
    except S3.exceptions.NoSuchKey:
        trivy_parsed = None

    # Build Slack message
    slack_msg = f"*Latest Build Folder*: {latest_folder}\n"

    if bandit_parsed:
        slack_msg += (
            f"\n*Bandit Findings*\n"
            f"Vulnerability: {bandit_parsed.get('issue_text')}\n"
            f"File: {bandit_parsed.get('filename')}:{bandit_parsed.get('line')}\n"
        )
        if "SQL" in bandit_parsed.get('issue_text', ""):
            slack_msg += "Suggestion: Use parameterized queries; avoid formatting SQL strings with user input.\n"
        else:
            slack_msg += f"Suggestion: Review finding.\n"
    else:
        slack_msg += "\n:white_check_mark: No Bandit findings\n"

    if trivy_parsed:
        slack_msg += "\n*Trivy Findings*\n"
        for vuln in trivy_parsed[:5]:  # limit to top 5 for Slack
            slack_msg += (
                f"{vuln.get('pkg')} ({vuln.get('version')}): {vuln.get('severity')} - {vuln.get('title')}\n"
            )
        if len(trivy_parsed) > 5:
            slack_msg += f"...and {len(trivy_parsed)-5} more vulnerabilities\n"
    else:
        slack_msg += "\n:white_check_mark: No Trivy findings\n"

    post_slack(slack_msg)

    return {"status": "notified", "folder": latest_folder}


