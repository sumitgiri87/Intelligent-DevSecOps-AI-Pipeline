import os
import io
import json
import boto3
import requests
import zipfile

SSM = boto3.client("ssm", region_name="ca-central-1")
S3 = boto3.client("s3", region_name="ca-central-1")

# Hardcoded bucket (safe for demo)
bucket = "codepipeline-ca-central-1-aba92722848d-4a2c-90d2-bc52c59a32aa"

def get_slack_webhook():
    name = os.environ.get("SLACK_SSM_PARAM", "/devsecops/slack_webhook")
    res = SSM.get_parameter(Name=name, WithDecryption=True)
    return res["Parameter"]["Value"]

def post_slack(text):
    webhook = get_slack_webhook()
    requests.post(webhook, json={"text": text})

def parse_bandit(bandit_json):
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
    try:
        data = json.loads(trivy_json)
        results = data.get("Results", [])
        findings = []
        for res in results:
            for vuln in res.get("Vulnerabilities", []):
                findings.append({
                    "Target": res.get("Target"),
                    "PkgName": vuln.get("PkgName"),
                    "VulnerabilityID": vuln.get("VulnerabilityID"),
                    "Severity": vuln.get("Severity"),
                    "Description": vuln.get("Description")
                })
        return findings if findings else None
    except Exception as e:
        return {"error": str(e)}

def lambda_handler(event, context):
#    bucket = event.get("bucket")
    if not bucket:
        post_slack(":warning: Lambda invoked without bucket")
        return {"status": "bad-request"}

    # List all objects under BuildArtif/
    resp = S3.list_objects_v2(Bucket=bucket, Prefix="intelligent-devsecop/BuildArtif/")
    objects = resp.get("Contents", [])

    if not objects:
        post_slack(":warning: No objects found in BuildArtif/")
        return {"status": "no-objects"}

    # Get the latest uploaded artifact
    latest_obj = sorted(objects, key=lambda x: x['LastModified'], reverse=True)[0]
    latest_key = latest_obj['Key']

    # Download the latest artifact
    obj = S3.get_object(Bucket=bucket, Key=latest_key)
    obj_bytes = io.BytesIO(obj['Body'].read())

    # Try to open as zip
    try:
        with zipfile.ZipFile(obj_bytes) as z:
            # Find Bandit or Trivy report inside zip
            report_file = None
            for f in z.namelist():
                if f.endswith(("bandit-report.json", "trivy-report.json")):
                    report_file = f
                    break

            if not report_file:
                post_slack(f":warning: No Bandit or Trivy reports found inside latest artifact {latest_key}")
                return {"status": "no-reports"}

            with z.open(report_file) as report:
                report_content = report.read().decode("utf-8")

    except zipfile.BadZipFile:
        post_slack(f":warning: Latest artifact {latest_key} is not a zip file")
        return {"status": "not-zip"}

    # Parse Bandit report
    if report_file.endswith("bandit-report.json"):
        parsed = parse_bandit(report_content)
        if not parsed:
            post_slack(":white_check_mark: No Bandit findings")
            return {"status": "no-findings"}

        issue = parsed.get('issue_text', '')
        suggestion = "Use parameterized queries if this is SQL-related." \
                     if "SQL" in issue or "sql" in issue else \
                     f"Review finding: {parsed.get('issue_text')} (File: {parsed.get('filename')}:{parsed.get('line')})"

        slack_text = (
            f"*[Bandit]* Vulnerability: {parsed.get('issue_text')}\n"
            f"File: {parsed.get('filename')}:{parsed.get('line')}\n"
            f"Suggestion: {suggestion}"
        )

    # Parse Trivy report
    elif report_file.endswith("trivy-report.json"):
        parsed = parse_trivy(report_content)
        if not parsed:
            post_slack(":white_check_mark: No Trivy findings")
            return {"status": "no-findings"}

        slack_text = "*[Trivy]* Vulnerabilities Found:\n"
        for v in parsed[:5]:  # Limit to first 5 for brevity
            slack_text += f"- {v['VulnerabilityID']} ({v['Severity']}) in {v['PkgName']} - Target: {v['Target']}\n"

    post_slack(slack_text)
    return {"status": "notified", "latest_report": latest_key}

