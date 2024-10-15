# Get AWS Console tool
This script generate a Console URL from the current AWS Credentials.

## Install

```bash
python -m env env
source venv/bin/active
pip install boto3 requests
```

## Execute

Define valid AWS Access key (e.g. export)

### Get the Console URL from the current Access Key

```bash
python3 get-console-url.py
```

### Get the Console URL with the assumed role

```bash
python3 get-console-url.py arn:aws:iam::12345678910:role/test_access_role 
```