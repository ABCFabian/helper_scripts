import boto3
import json
import os
import sys
import argparse
import tempfile
from botocore.exceptions import ClientError
from datetime import datetime

# Add the aws-list-resources directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'aws-list-resources'))

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

def assume_role(account_id, role_name):
    sts_client = boto3.client('sts')
    try:
        response = sts_client.assume_role(
            RoleArn=f'arn:aws:iam::{account_id}:role/{role_name}',
            RoleSessionName='ResourceExplorerSession'
        )
        return response['Credentials']
    except ClientError as e:
        print(f"Error assuming role for account {account_id}: {e}")
        return None

def get_aws_list_resources_data(credentials, regions):
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_creds:
        temp_creds.write(f"[temp]\n")
        temp_creds.write(f"aws_access_key_id = {credentials['AccessKeyId']}\n")
        temp_creds.write(f"aws_secret_access_key = {credentials['SecretAccessKey']}\n")
        temp_creds.write(f"aws_session_token = {credentials['SessionToken']}\n")
    
    temp_creds_path = temp_creds.name
    
    try:
        regions_arg = ','.join(regions) if regions else 'ALL'
        
        # Import the aws_list_resources module
        from aws_list_resources import aws_list_resources
        
        # Set up the arguments
        class Args:
            regions = regions_arg
            profile = 'temp'
            exclude_resource_types = ''
            include_resource_types = '*'
            only_show_counts = False

        # Run the aws_list_resources script
        aws_list_resources.args = Args()
        aws_list_resources.AWS_CONFIG_FILE = temp_creds_path
        aws_list_resources.main()
        
        # Read the output file
        output_file = 'aws-list-resources-output.json'
        with open(output_file, 'r') as f:
            return json.load(f)
    finally:
        os.unlink(temp_creds_path)

def main(accounts_file, role_name, regions):
    with open(accounts_file, 'r') as f:
        accounts = [line.strip() for line in f.readlines()]

    for account_id in accounts:
        print(f"Processing account: {account_id}")
        credentials = assume_role(account_id, role_name)
        if credentials:
            resources = get_aws_list_resources_data(credentials, regions)
            if resources:
                output_file = f'aws_list_resources_{account_id}.json'
                with open(output_file, 'w') as f:
                    json.dump(resources, f, indent=2, cls=DateTimeEncoder)
                print(f"Resources saved to {output_file}")
            else:
                print(f"No resources found for account {account_id}")
        else:
            print(f"Skipping account {account_id} due to role assumption failure")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AWS Resource listing using aws-list-resources")
    parser.add_argument("accounts_file", help="Path to the file containing AWS account IDs")
    parser.add_argument("role_name", help="Name of the IAM role to assume in each account")
    parser.add_argument("--regions", nargs='+', help="List of regions to search (default is ALL)")
    args = parser.parse_args()

    main(args.accounts_file, args.role_name, args.regions)