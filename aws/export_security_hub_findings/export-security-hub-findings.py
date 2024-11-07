import boto3
import csv
import json
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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
        ],
        'SeverityLabel': [
            {'Value': 'CRITICAL', 'Comparison': 'EQUALS'},
            {'Value': 'HIGH', 'Comparison': 'EQUALS'},
            {'Value': 'MEDIUM', 'Comparison': 'EQUALS'}
        ],
        'ProductName': [
            {'Value': 'Inspector', 'Comparison': 'NOT_EQUALS'}
        ]
    }
    logger.info(f"Using filter: {json.dumps(_filter)}")

    # Generate a timestamp for the filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"security_hub_findings_{timestamp}.csv"
    logger.info(f"Generated filename: {filename}")

    # Define the fields we want to export
    fields = [
        'Title', 'Description', 'Severity_Label', 'Severity_Normalized', 
        'Types', 'ProductName', 'CompanyName', 'Region', 
        'ResourceType', 'ResourceId', 'AwsAccountId', 'Compliance_Status', 
        'Workflow_Status', 'FirstObservedAt', 'LastObservedAt',
        'Remediation_Recommendation_Text'
    ]
    logger.info(f"Fields to be exported: {', '.join(fields)}")

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

    # Write to CSV
    logger.info(f"Writing findings to CSV file: {filename}")
    with open(filename, "w", newline='', encoding='utf-8') as csvfile:
        csvwriter = csv.DictWriter(csvfile, fieldnames=fields)
        csvwriter.writeheader()
        for finding in all_findings:
            row = {
                'Title': finding.get('Title', ''),
                'Description': finding.get('Description', ''),
                'AwsAccountId': finding.get('AwsAccountId', ''),
                'Severity_Label': finding.get('Severity', {}).get('Label', ''),
                'Severity_Normalized': finding.get('Severity', {}).get('Normalized', ''),
                'Types': ', '.join(finding.get('Types', [])),
                'ProductName': finding.get('ProductName', ''),
                'CompanyName': finding.get('CompanyName', ''),
                'Region': finding.get('Region', ''),
                'ResourceType': finding.get('Resources', [{}])[0].get('Type', ''),
                'ResourceId': finding.get('Resources', [{}])[0].get('Id', ''),
                'Compliance_Status': finding.get('Compliance', {}).get('Status', ''),
                'Workflow_Status': finding.get('Workflow', {}).get('Status', ''),
                'FirstObservedAt': finding.get('FirstObservedAt', ''),
                'LastObservedAt': finding.get('LastObservedAt', ''),
                'Remediation_Recommendation_Text': finding.get('Remediation', {}).get('Recommendation', {}).get('Text', '')
            }
            csvwriter.writerow(row)

    logger.info(f"Successfully exported {len(all_findings)} findings to {filename}")

# If running the script locally (not as a Lambda function)
if __name__ == "__main__":
    lambda_handler(None, None)