import os
import io
import json
import boto3
import requests
import zipfile
import openai
from openai import OpenAI
import anthropic

# Initialize AWS clients
SSM = boto3.client("ssm", region_name="ca-central-1")
S3 = boto3.client("s3", region_name="ca-central-1")
CODEPIPELINE = boto3.client("codepipeline", region_name="ca-central-1")

# Bucket where build artifacts are stored
bucket = "codepipeline-ca-central-1-aba92722848d-4a2c-90d2-bc52c59a32aa"

def get_slack_webhook():
#   """Retrieve Slack webhook URL securely from SSM Parameter Store."""
    name = os.environ.get("SLACK_SSM_PARAM", "/devsecops/slack_webhook")
    res = SSM.get_parameter(Name=name, WithDecryption=True)
    return res["Parameter"]["Value"]


def get_openai_key():
#   """Retrieve OpenAI API key from SSM Parameter Store."""
    name = os.environ.get("OPENAI_KEY_SSM", "/devsecops/openai_key")
    res = SSM.get_parameter(Name=name, WithDecryption=True)
    key = res["Parameter"]["Value"]
    print("Retrieved OpenAI key:", key[:5], "…")  # Only show first few chars
    return key

def get_anthropic_key():
#   """Retrieve Anthropic (Claude) API key from SSM Parameter Store."""
    name = os.environ.get("ANTHROPIC_KEY_SSM", "/devsecops/anthropic_key")
    res = SSM.get_parameter(Name=name, WithDecryption=True)
    key = res["Parameter"]["Value"]
    print("Retrieved Anthropic key:", key[:5], "…")  # only show first 5 chars
    return key

# Load API keys
openai_api_key = get_openai_key().strip()
anthropic_api_key = get_anthropic_key().strip()
print(f"Got key length: {len(openai_api_key)}")
print(f"Got key length: {len(anthropic_api_key)}")

# Initialize OpenAI client
openapi_client = OpenAI(api_key=openai_api_key)

# Initialize Anthropic client
anthropic_client = anthropic.Anthropic(api_key=anthropic_api_key)

def post_slack(text):
#   """Post a message to Slack via the webhook URL."""
    try:
        webhook = get_slack_webhook()
        requests.post(webhook, json={"text": text}, timeout=5)
    except Exception as e:
        print(f"Slack post failed: {e}")

def parse_bandit(bandit_json):
#   """Extract the top finding from a Bandit JSON report."""    
    try:
        data = json.loads(bandit_json)
        results = data.get("results", [])
        if not results:
            return None
        top = results[0]
        return {
            "issue_text": top.get("issue_text", "Unknown issue"),
            "filename": top.get("filename", "<unknown>"),
            "line": top.get("line_number", 0)
        }
    except Exception as e:
        return {"error": str(e)}

def parse_trivy(trivy_json):
    """
    Extract all vulnerabilities from a Trivy JSON report.
    Handles both image scans with or without "Results" key.
    """
    try:
        data = json.loads(trivy_json)
        
        # Case 1: Output is list (common for empty scans)
        if isinstance(data, list):
            findings = []
            for item in data:
                vulns = item.get("Vulnerabilities", [])
                for v in vulns:
                    findings.append({
                        "Target": item.get("Target"),
                        "PkgName": v.get("PkgName"),
                        "VulnerabilityID": v.get("VulnerabilityID"),
                        "Severity": v.get("Severity"),
                        "Description": v.get("Description")
                    })
            return findings

        # Case 2: Output is dict (legacy Trivy JSON with "Results")
        if isinstance(data, dict):
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
            return findings

        # Fallback: empty
        return None
    except Exception as e:
        return {"error": str(e)}

    
# ----------------------
# AI Summarization Functions
# ----------------------

def summarize_vulnerabilities_with_gpt(report_json):
#   """ Summarize a vulnerability report using OpenAI GPT. Returns a message with a GPT-3.5-turbo heading."""
    prompt = f"""
    You are a cybersecurity assistant.
    Here is a JSON security scan report: {report_json}
    Summarize the top 5 issues, explain the risk, and give actionable remediation steps for a developer.
    Provide a concise response suitable for Slack.
    """
    response = openapi_client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=500
    )
    # Access the text like this in v1.0+
    text = response.choices[0].message.content
    return f"*GPT-3.5-turbo summary:*\n{text}"

def summarize_vulnerabilities_with_claude(report_json):
#   """Summarize a vulnerability report using Anthropic Claude. Returns a message with a Claude heading."""
    prompt = f"""
    You are a cybersecurity assistant.
    Here is a JSON security scan report: {report_json}
    Summarize the top 5 issues, explain the risk, and give actionable remediation steps for a developer.
    Provide a concise response suitable for Slack.
    """
    try:
        response = anthropic_client.messages.create(
            model="claude-sonnet-4-20250514",  # use a model your account can access
            messages=[{"role": "user", "content": prompt}],
            max_tokens=500
        )
        # Extract plain text from the first TextBlock
        text = response.content[0].text
        return f"*Claude summary:*\n{text}"
    except Exception as e:
        return f"Error summarizing report via Claude: {e}"

# ----------------------
# Lambda Handler
# ----------------------

def lambda_handler(event, context):
#   """AWS Lambda handler to process security scan reports from S3, summarize findings using GPT and Claude, and post to Slack. 
#   """Also reports success/failure to CodePipeline if triggered."""
    job_id = event.get("CodePipeline.job", {}).get("id")

    try:
        # List build artifacts in S3
        resp = S3.list_objects_v2(Bucket=bucket, Prefix="intelligent-devsecop/BuildArtif/")
        objects = resp.get("Contents", [])
        if not objects:
            post_slack(":warning: No objects found in BuildArtif/")
            if job_id:
                CODEPIPELINE.put_job_failure_result(jobId=job_id,
                    failureDetails={"message": "No objects found", "type": "JobFailed"})
            return {"status": "no-objects"}

        # Get the most recent artifact
        latest_obj = sorted(objects, key=lambda x: x['LastModified'], reverse=True)[0]
        latest_key = latest_obj['Key']

        obj = S3.get_object(Bucket=bucket, Key=latest_key)
        obj_bytes = io.BytesIO(obj['Body'].read())

        # Open the zip and find all report files
        with zipfile.ZipFile(obj_bytes) as z:
            report_files = [f for f in z.namelist() if f.endswith(("bandit-report.json", "trivy-report.json"))]

            if not report_files:
                post_slack(f":warning: No Bandit or Trivy reports found in {latest_key}")
                if job_id:
                    CODEPIPELINE.put_job_failure_result(jobId=job_id,
                        failureDetails={"message": "No reports found", "type": "JobFailed"})
                return {"status": "no-reports"}

            # Iterate over all reports
            for report_file in report_files:
                with z.open(report_file) as report:
                    report_content = report.read().decode("utf-8")

                # Deterministically parse report and format Slack message
                slack_text = ""
                if report_file.endswith("bandit-report.json"):
                    parsed = parse_bandit(report_content)
                    if not parsed:
                        slack_text = ":white_check_mark: No Bandit findings"
                    else:

                        issue = parsed.get('issue_text', '')
                        suggestion = ("Use parameterized queries if this is SQL-related."
                                      if "SQL" in issue or "sql" in issue else
                                      f"Review finding: {issue} (File: {parsed.get('filename')}:{parsed.get('line')})")
                        slack_text = f"*[Bandit]* Vulnerability: {issue}\nFile: {parsed.get('filename')}:{parsed.get('line')}\nSuggestion: {suggestion}"

                    # Summarize using GPT
                        try:
                            summary = summarize_vulnerabilities_with_gpt(parsed)
                            post_slack(summary)
                        except openai.RateLimitError:
                            post_slack(":warning: GPT summarization skipped due to insufficient quota.")
                        except openai.InvalidRequestError as e:
                            post_slack(f":x: GPT summarization invalid request: {e}")
                        except Exception as e:
                            post_slack(f":x: GPT summarization failed: {e}")

                #  # Summarize using Claude
                        try:
                            summary = summarize_vulnerabilities_with_claude(parsed)
                            post_slack(summary)
                        except Exception as e:
                            post_slack(f":x: Summarization failed: {e}")

                elif report_file.endswith("trivy-report.json"):
                    parsed = parse_trivy(report_content)

                    # Handle: None, {}, [], {"error": "..."}
                    if not parsed or isinstance(parsed, dict):
                        slack_text = ":white_check_mark: No Trivy findings"
                    else:
                        slack_text = "*[Trivy]* Vulnerabilities Found:\n"
                        top5 = parsed[:5]
                        for v in top5:
                            slack_text += (
                                f"- {v.get('VulnerabilityID')} ({v.get('Severity')}) "
                                f"in {v.get('PkgName')} - Target: {v.get('Target')}\n"
                            )

                        # Summarize using GPT
                        try:
                            summary = summarize_vulnerabilities_with_gpt(parsed)
                            post_slack(summary)
                        except openai.RateLimitError:
                            post_slack(":warning: GPT summarization skipped due to insufficient quota.")
                        except openai.InvalidRequestError as e:
                            post_slack(f":x: GPT summarization invalid request: {e}")
                        except Exception as e:
                            post_slack(f":x: GPT summarization failed: {e}")


                # Post raw findings to Slack
                post_slack(slack_text)

        # Report success to CodePipeline
        if job_id:
            CODEPIPELINE.put_job_success_result(jobId=job_id)

        return {"status": "notified", "latest_report": latest_key}

    except Exception as e:
        post_slack(f":x: Lambda failed: {str(e)}")
        if job_id:
            CODEPIPELINE.put_job_failure_result(jobId=job_id,
                failureDetails={"message": str(e), "type": "JobFailed"})
        raise
