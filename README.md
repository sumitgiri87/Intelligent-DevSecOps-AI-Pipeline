# Intelligent-DevSecOps-AI-Pipeline

## What
Minimal demo: push -> CodePipeline -> CodeBuild runs build (and later scans). App is a Flask app with an intentional SQL injection vulnerability.

## Quick run
1. `git clone ...`
2. `python -m venv venv && source venv/bin/activate`
3. `pip install -r requirements.txt`
4. `python app.py`
