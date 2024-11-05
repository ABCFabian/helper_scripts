import boto3
import csv
import json
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def flatten_dict(d, parent_key='', sep='_'):
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            for i, item in enumerate(v):
                if isinstance(item, dict):
                    items.extend(flatten_dict(item, f"{new_key}{sep}{i}", sep=sep).items())
                else:
                    items.append((f"{new_key}{sep}{i}", str(item)))
        else:
            items.append((new_key, str(v)))
    return dict(items)

def lambda_handler(event, context):
    logger.info("Starting Security Hub findings export")

    # Initialize Security Hub client
    securityhub = boto3.client('securityhub')
    logger.info("Initialized Security Hub client")

    # Set maximum number of findings to retrieve per API call
    MAX_ITEMS = 100

    # Define the filter
    _filter = {
        'WorkflowStatus': [
            {'Value': 'NEW', 'Comparison': 'EQUALS'},
            {'Value': 'NOTIFIED', 'Comparison': 'EQUALS'}
        ],
        'RecordState': [
            {'Value': 'ACTIVE', 'Comparison': 'EQUALS'}
        ]
    }
    logger.info(f"Using filter: {json.dumps(_filter)}")

    # Generate a timestamp for the filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"security_hub_findings_{timestamp}.csv"
    logger.info(f"Generated filename: {filename}")

    # Initialize pagination
    next_token = None
    all_findings = []

    while True:
        # Get findings with filter
        if next_token:
            logger.debug(f"Retrieving next batch of findings with token: {next_token}")
            response = securityhub.get_findings(Filters=_filter, MaxResults=MAX_ITEMS, NextToken=next_token)
        else:
            logger.debug("Retrieving first batch of findings")
            response = securityhub.get_findings(Filters=_filter, MaxResults=MAX_ITEMS)

        findings = response['Findings']
        all_findings.extend(findings)
        logger.info(f"Retrieved {len(findings)} findings. Total: {len(all_findings)}")

        # Check if there are more findings to retrieve
        next_token = response.get('NextToken')
        if not next_token:
            logger.info("No more findings to retrieve")
            break

    logger.info(f"Total findings retrieved: {len(all_findings)}")

    # Flatten all findings
    logger.info("Flattening findings")
    flattened_findings = [flatten_dict(finding) for finding in all_findings]

    # Get all unique keys across all flattened findings
    all_keys = set()
    for finding in flattened_findings:
        all_keys.update(finding.keys())

    # Sort keys for consistent column order
    sorted_keys = sorted(all_keys)
    logger.info(f"Total unique keys in findings: {len(sorted_keys)}")

    # Write to CSV
    logger.info(f"Writing findings to CSV file: {filename}")
    with open(filename, "w", newline='', encoding='utf-8') as csvfile:
        csvwriter = csv.DictWriter(csvfile, fieldnames=sorted_keys)
        csvwriter.writeheader()
        for finding in flattened_findings:
            csvwriter.writerow(finding)

    logger.info(f"Successfully exported {len(all_findings)} findings to {filename}")

# If running the script locally (not as a Lambda function)
if __name__ == "__main__":
    lambda_handler(None, None)