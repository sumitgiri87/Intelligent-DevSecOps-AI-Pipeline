# Intelligent DevSecOps AI Pipeline (AWS | Slack | GPT | Claude)

A reproducible, end-to-end DevSecOps pipeline that builds your app, runs security scans (Bandit & Trivy), stores reports in S3, and uses a Lambda function to summarize findings via OpenAI (GPT-3.5) and Anthropic Claude — then posts results to Slack. This README is written as a practical developer guide so you (or another engineer) can reproduce the whole setup.

---

## Repository layout (root)

```
Intelligent-DevSecOps-AI-Pipeline/
├── README.md                   # THIS FILE
├── app.py                      # Vulnerable demo app (login example)
├── demo.db                     # Local sqlite DB used by the demo app
├── Dockerfile                  # Container build for CodeBuild + Trivy
├── buildspec.yml               # CodeBuild commands: install tools, run scans, upload artifacts
├── requirements.txt            # Local python dependencies for testing
├── lambda_pkg/
│   ├── lambda_function.py      # Lambda handler (AI summarizer)
│   ├── package/                # Dependencies installed with `pip -t`
│   └── ai-suggester.zip        # Deployable zip (package contents at zip root)
└── venv/                       # Local virtualenv (ignored in git)
```

---

## What this project does (summary)

- Push code to GitHub → CodePipeline triggers.
- CodeBuild builds the project and runs Bandit + Trivy.
- JSON scan reports are uploaded to S3.
- A Lambda function (`ai-suggester`) is invoked by CodePipeline to:
  - fetch the latest artifact from S3,
  - read secrets (Slack webhook, OpenAI key, Anthropic key) from SSM,
  - parse Bandit & Trivy reports,
  - summarize findings using GPT-3.5 and Claude,
  - post summaries and raw findings to Slack,
  - report success/failure back to CodePipeline.

Why this? Quick automated security feedback for developers with actionable remediation steps.

---

## Quick start (reproducible steps)

> Replace placeholders like `<ACCOUNT_ID>`, `<USERNAME>`, `<REGION>`, and secret values before running commands.

### 1) Prerequisites (local)
- Git + Git Bash (or equivalent)
- Python 3.10+ (match Lambda runtime)
- Docker (for local packaging / testing)
- AWS CLI configured (`aws configure`)
- AWS account with IAM permissions to create the resources below
- Slack workspace with Incoming Webhook URL
- OpenAI account (API key) and/or Anthropic account (API key)

### 2) Initial repository bootstrap (if not already)
```bash
git init
git add .
git commit -m "bootstrap: initial project"
git branch -M main
git remote add origin git@github.com:<USERNAME>/Intelligent-DevSecOps-AI-Pipeline.git
git push -u origin main
```

### 3) Store secrets in SSM (SecureString)
```bash
aws ssm put-parameter --name "/devsecops/slack_webhook"   --value "https://hooks.slack.com/services/AAA/BBB/CCC"   --type "SecureString" --region <REGION>

aws ssm put-parameter --name "/devsecops/openai_key"   --value "sk-REPLACE" --type "SecureString" --region <REGION>

aws ssm put-parameter --name "/devsecops/anthropic_key"   --value "anthropic-REPLACE" --type "SecureString" --region <REGION>
```

### 4) Buildspec (CodeBuild) — example
Ensure `buildspec.yml` contains commands to produce `bandit-report.json` and `trivy-report.json`. Example snippet:

```yaml
version: 0.2

phases:
  install:
    runtime-versions:
      python: 3.10
    commands:
      - echo "Installing tools"
      - pip install bandit==1.8.6 pytest
      - echo "Installing Trivy"
      - curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.18.3

  pre_build:
    commands:
      - echo "Starting build"

  build:
    commands:
      - echo "Running unit tests"
      - pytest -q || true
      - echo "Running Bandit static scan"
      - bandit -r . -f json -o bandit-report.json || true
      - echo "Building docker image"
      - docker build -t sample-app:latest .
      - echo "Scanning image with Trivy"
      - trivy image --format json --output trivy-report.json --no-progress sample-app:latest || true

artifacts:
  files:
    - bandit-report.json
    - trivy-report.json
  name: reports/$CODEBUILD_BUILD_NUMBER/
  discard-paths: yes

```

### 5) Prepare Lambda package (Linux-compatible)
Run locally (Windows instructions use Git Bash/WSL):

```bash
# from repo root
python -m venv venv
source venv/Scripts/activate    # Windows Git Bash: source venv/Scripts/activate
python -m pip install --upgrade pip
pip install -r requirements.txt -t lambda_pkg/package/
cp lambda_pkg/lambda_function.py lambda_pkg/package/
cd lambda_pkg/package
zip -r ../ai-suggester.zip .
cd ../..
```

**Verify zip**: `unzip -l lambda_pkg/ai-suggester.zip` — `lambda_function.py` should be at the zip root.

### 6) IAM Role for Lambda
Create role `lambda-ai-suggester-role` with trust policy for Lambda and attach `AWSLambdaBasicExecutionRole`. Add an inline policy (least privilege recommended) allowing:

- `ssm:GetParameter` for `/devsecops/*`
- `s3:GetObject` and `s3:ListBucket` for CodePipeline artifact buckets
- `codepipeline:PutJobSuccessResult` & `PutJobFailureResult`

Example inline policy JSON (adjust resource ARNs):

```json
{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Effect":"Allow",
      "Action":["ssm:GetParameter"],
      "Resource":"arn:aws:ssm:<REGION>:<ACCOUNT_ID>:parameter/devsecops/*"
    },
    {
      "Effect":"Allow",
      "Action":["s3:GetObject","s3:ListBucket"],
      "Resource":["arn:aws:s3:::codepipeline-*-*","arn:aws:s3:::codepipeline-*-*/*"]
    },
    {
      "Effect":"Allow",
      "Action":["codepipeline:PutJobSuccessResult","codepipeline:PutJobFailureResult"],
      "Resource":"*"
    }
  ]
}
```

### 7) Create/Update Lambda function
Create or update function with the ZIP uploaded:

```bash
aws lambda create-function   --function-name ai-suggester   --runtime python3.10   --role arn:aws:iam::<ACCOUNT_ID>:role/lambda-ai-suggester-role   --handler lambda_function.lambda_handler   --zip-file fileb://lambda_pkg/ai-suggester.zip   --timeout 120 --memory-size 512 --region <REGION>
```

Or update code:

```bash
aws lambda update-function-code --function-name ai-suggester --zip-file fileb://lambda_pkg/ai-suggester.zip --region <REGION>
```

### 8) Wire Lambda into CodePipeline
Edit your pipeline: add a stage "Notify" with an action of provider AWS Lambda that invokes `ai-suggester`. Use the build artifact that contains `bandit-report.json` and `trivy-report.json` as input.

### 9) Push code and test
```bash
git add .
git commit -m "feat: test pipeline"
git push origin main
```

Watch CodePipeline and CloudWatch Logs. Slack should receive messages:

- raw findings summary
- `*GPT-3.5-turbo summary:* ...`
- `*Claude summary:* ...`

---

## Lambda handler overview (what it does)

- Lists objects in S3 under the pipeline artifact prefix
- Downloads the latest artifact (zip)
- Opens the zip and searches for `bandit-report.json` or `trivy-report.json`
- Parses the report using `parse_bandit()` or `parse_trivy()`
- Posts a concise raw findings Slack message
- Calls either or both summarizers:
  - `summarize_vulnerabilities_with_gpt(report_content)` — uses OpenAI client
  - `summarize_vulnerabilities_with_claude(report_content)` — uses Anthropic client
- Posts summaries to Slack, each prefixed with the model name
- Sends success/failure back to CodePipeline via `put_job_success_result` / `put_job_failure_result`

---

## Summarizer function examples (snippets from lambda_function.py)

**OpenAI (GPT-3.5)**
```python
from openai import OpenAI
openapi_client = OpenAI(api_key=openai_api_key)

def summarize_vulnerabilities_with_gpt(report_json):
    prompt = f"You are a cybersecurity assistant. Here is a JSON security scan report: {report_json} ..."
    response = openapi_client.chat.completions.create(
        model="gpt-3.5-turbo",
        messages=[{"role":"user","content":prompt}],
        temperature=0.2,
        max_tokens=500
    )
    text = response.choices[0].message.content
    return f"*GPT-3.5-turbo summary:*\n{text}"
```

**Anthropic (Claude)**
```python
import anthropic
anthropic_client = anthropic.Anthropic(api_key=anthropic_api_key)

def summarize_vulnerabilities_with_claude(report_json):
    prompt = f"You are a cybersecurity assistant. Here is a JSON security scan report: {report_json} ..."
    response = anthropic_client.messages.create(
        model="claude-sonnet-4-20250514",
        messages=[{"role":"user","content":prompt}],
        max_tokens=500
    )
    text = response.content[0].text
    return f"*Claude summary:*\n{text}"
```

---

## Local testing tips

- Test the summarizers locally using saved JSON reports:

```bash
python -c "from lambda_pkg.package.lambda_function import summarize_vulnerabilities_with_claude; print(summarize_vulnerabilities_with_claude(open('bandit-report.json').read()))"
```

- Verify your local `app.py` demonstrates the insecure SQL behavior so Bandit flags it.

---

## Troubleshooting (common errors and fixes)

- **429 / insufficient_quota (OpenAI)**: Billing or free-trial exhausted — add a payment method or use a different account. Creating a new key on the same account won't help if the account has no quota.
- **404 model not found (Anthropic)**: Use the exact model id your account has access to (run `client.models.list()` or check console).
- **Lambda missing dependencies**: Ensure you installed libs into `lambda_pkg/package/` and zipped contents (not the parent folder).
- **Lambda in VPC can't reach internet**: Provide NAT gateway / egress so Lambda can call external APIs.
- **SSM permission denied**: Ensure Lambda role has `ssm:GetParameter` on the parameter ARNs.
- **Large ZIP**: Consider using Lambda Layers for common dependencies.

---

## Optional enhancements (next steps)

- Add GitHub Actions pre-commit tests and checks
- Add Snyk or Dependabot for dependency vulnerability monitoring
- Integrate AWS Inspector for runtime checks
- Store results in DynamoDB for historical analytics and trend detection
- Add cost alerts and usage dashboards for OpenAI/Anthropic API calls

---

## Architecture (Mermaid)

```mermaid
flowchart LR
  A[GitHub] -->|Push| B[CodePipeline]
  B --> C[CodeBuild]
  C -->|Upload| D[S3 (reports)]
  B -->|Invoke| E[Lambda ai-suggester]
  E --> F[OpenAI]
  E --> G[Anthropic]
  E --> H[Slack]
  C --> I[CloudWatch Logs]
```

---

## Security notes

- Never commit API keys or webhook URLs to git. Use SSM or Secrets Manager.
- Limit IAM permissions to least privilege.
- Rotate API keys periodically.
- Monitor billing on OpenAI/Anthropic.

---

## Resources & links

- OpenAI docs: https://platform.openai.com/docs
- Anthropic docs: https://docs.anthropic.com
- Trivy docs: https://aquasecurity.github.io/trivy/
- Bandit docs: https://bandit.readthedocs.io

---

## Contact / Author

Sumit Giri — use the repo issues to open questions or share improvements.

---

## License

This project is provided as-is for learning and internal use. Add your preferred open-source license if needed.
