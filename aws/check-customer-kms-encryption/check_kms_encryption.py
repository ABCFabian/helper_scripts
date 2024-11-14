import boto3
import csv
import argparse
import os
from datetime import datetime, timezone
from botocore.exceptions import ClientError

def is_customer_managed_key(kms_client, key_id):
    try:
        key_info = kms_client.describe_key(KeyId=key_id)
        return key_info['KeyMetadata']['KeyManager'] == 'CUSTOMER'
    except ClientError:
        return False

def get_all_regions(session):
    ec2_client = session.client('ec2')
    regions = ec2_client.describe_regions()
    return [region['RegionName'] for region in regions['Regions']]

def check_encryption(aws_access_key_id=None, aws_secret_access_key=None, aws_session_token=None, region=None, scan_all_regions=False, report_dir='.'):
    # Create a session with the provided credentials
    session = boto3.Session(
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        aws_session_token=aws_session_token,
        region_name=region
    )

    # Determine regions to scan
    if scan_all_regions:
        regions = get_all_regions(session)
    else:
        regions = [session.region_name] if session.region_name else []

    findings = []
    
    for region in regions:
        print(f"Scanning region: {region}")
        regional_session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            region_name=region
        )

        # Create clients using the regional session
        ec2_client = regional_session.client('ec2')
        rds_client = regional_session.client('rds')
        sqs_client = regional_session.client('sqs')
        dynamodb_client = regional_session.client('dynamodb')
        redshift_client = regional_session.client('redshift')
        elasticache_client = regional_session.client('elasticache')
        secretsmanager_client = regional_session.client('secretsmanager')
        sns_client = regional_session.client('sns')
        efs_client = regional_session.client('efs')
        kms_client = regional_session.client('kms')
        sts_client = regional_session.client('sts')

        account_id = sts_client.get_caller_identity()['Account']
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-4]

        # Check EBS volumes
        print("Checking EBS volumes...")
        volumes_paginator = ec2_client.get_paginator('describe_volumes')
        for page in volumes_paginator.paginate():
            for volume in page['Volumes']:
                finding = create_finding(volume, 'EbsVolume', account_id, timestamp, kms_client, region)
                findings.append(finding)

        # Check EBS snapshots
        print("Checking EBS snapshots...")
        snapshots_paginator = ec2_client.get_paginator('describe_snapshots')
        for page in snapshots_paginator.paginate(OwnerIds=['self']):
            for snapshot in page['Snapshots']:
                finding = create_finding(snapshot, 'EbsSnapshot', account_id, timestamp, kms_client, region)
                findings.append(finding)

        # Check RDS instances
        print("Checking RDS instances...")
        rds_paginator = rds_client.get_paginator('describe_db_instances')
        for page in rds_paginator.paginate():
            for instance in page['DBInstances']:
                finding = create_finding(instance, 'RdsInstance', account_id, timestamp, kms_client, region)
                findings.append(finding)

        # Check SQS queues
        print("Checking SQS queues...")
        queues = sqs_client.list_queues()
        for queue_url in queues.get('QueueUrls', []):
            queue_attrs = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['All'])
            queue_info = {'QueueUrl': queue_url, 'Attributes': queue_attrs['Attributes']}
            finding = create_finding(queue_info, 'SqsQueue', account_id, timestamp, kms_client, region)
            findings.append(finding)

        # Check DynamoDB tables
        print("Checking DynamoDB tables...")
        tables = dynamodb_client.list_tables()['TableNames']
        for table_name in tables:
            table_info = dynamodb_client.describe_table(TableName=table_name)['Table']
            if 'SSEDescription' in table_info:
                finding = create_finding(table_info, 'DynamoDBTable', account_id, timestamp, kms_client, region)
                findings.append(finding)

        # Check Redshift clusters
        print("Checking Redshift clusters...")
        clusters = redshift_client.describe_clusters()['Clusters']
        for cluster in clusters:
            finding = create_finding(cluster, 'RedshiftCluster', account_id, timestamp, kms_client, region)
            findings.append(finding)

        # Check ElastiCache clusters
        print("Checking ElastiCache clusters...")
        cache_clusters = elasticache_client.describe_cache_clusters()['CacheClusters']
        for cluster in cache_clusters:
            finding = create_finding(cluster, 'ElastiCacheCluster', account_id, timestamp, kms_client, region)
            findings.append(finding)

        # Check Secrets Manager secrets
        print("Checking Secrets Manager secrets...")
        secrets = secretsmanager_client.list_secrets()['SecretList']
        for secret in secrets:
            finding = create_finding(secret, 'SecretsManagerSecret', account_id, timestamp, kms_client, region)
            findings.append(finding)

        # Check SNS topics
        print("Checking SNS topics...")
        topics = sns_client.list_topics()['Topics']
        for topic in topics:
            topic_attributes = sns_client.get_topic_attributes(TopicArn=topic['TopicArn'])['Attributes']
            finding = create_finding(topic_attributes, 'SNSTopic', account_id, timestamp, kms_client, region)
            findings.append(finding)

        # Check EFS file systems
        print("Checking EFS file systems...")
        file_systems = efs_client.describe_file_systems()['FileSystems']
        for fs in file_systems:
            finding = create_finding(fs, 'EFSFileSystem', account_id, timestamp, kms_client, region)
            findings.append(finding)

    output_csv(findings, report_dir)

def create_finding(resource, resource_type, account_id, timestamp, kms_client, region):
    is_encrypted = False
    kms_key_id = None
    resource_id = None
    resource_arn = None

    if resource_type == 'EbsVolume':
        is_encrypted = resource['Encrypted']
        kms_key_id = resource.get('KmsKeyId')
        resource_id = resource['VolumeId']
        resource_arn = f"arn:aws:ec2:{region}:{account_id}:volume/{resource_id}"
    elif resource_type == 'EbsSnapshot':
        is_encrypted = resource['Encrypted']
        kms_key_id = resource.get('KmsKeyId')
        resource_id = resource['SnapshotId']
        resource_arn = f"arn:aws:ec2:{region}:{account_id}:snapshot/{resource_id}"
    elif resource_type == 'RdsInstance':
        is_encrypted = resource['StorageEncrypted']
        kms_key_id = resource.get('KmsKeyId')
        resource_id = resource['DBInstanceIdentifier']
        resource_arn = f"arn:aws:rds:{region}:{account_id}:db:{resource_id}"
    elif resource_type == 'SqsQueue':
        is_encrypted = 'KmsMasterKeyId' in resource['Attributes']
        kms_key_id = resource['Attributes'].get('KmsMasterKeyId')
        resource_id = resource['QueueUrl'].split('/')[-1]
        resource_arn = f"arn:aws:sqs:{region}:{account_id}:{resource_id}"
    elif resource_type == 'DynamoDBTable':
        is_encrypted = 'SSEDescription' in resource
        kms_key_id = resource.get('SSEDescription', {}).get('KMSMasterKeyArn')
        resource_id = resource['TableName']
        resource_arn = f"arn:aws:dynamodb:{region}:{account_id}:table/{resource_id}"
    elif resource_type == 'RedshiftCluster':
        is_encrypted = resource['Encrypted']
        kms_key_id = resource.get('KmsKeyId')
        resource_id = resource['ClusterIdentifier']
        resource_arn = f"arn:aws:redshift:{region}:{account_id}:cluster:{resource_id}"
    elif resource_type == 'ElastiCacheCluster':
        is_encrypted = resource.get('AtRestEncryptionEnabled', False)
        kms_key_id = resource.get('KmsKeyId')
        resource_id = resource['CacheClusterId']
        resource_arn = f"arn:aws:elasticache:{region}:{account_id}:cluster:{resource_id}"
    elif resource_type == 'SecretsManagerSecret':
        is_encrypted = True  # Secrets are always encrypted
        kms_key_id = resource.get('KmsKeyId')
        resource_id = resource['Name']
        resource_arn = f"arn:aws:secretsmanager:{region}:{account_id}:secret:{resource_id}"
    elif resource_type == 'SNSTopic':
        is_encrypted = 'KmsMasterKeyId' in resource
        kms_key_id = resource.get('KmsMasterKeyId')
        resource_id = resource['TopicArn'].split(':')[-1]
        resource_arn = resource['TopicArn']
    elif resource_type == 'EFSFileSystem':
        is_encrypted = resource['Encrypted']
        kms_key_id = resource.get('KmsKeyId')
        resource_id = resource['FileSystemId']
        resource_arn = f"arn:aws:elasticfilesystem:{region}:{account_id}:file-system/{resource_id}"

    if is_encrypted and kms_key_id:
        is_customer_key = is_customer_managed_key(kms_client, kms_key_id)
        status = "PASS" if is_customer_key else "FAIL"
        status_extended = f"Encrypted with {'customer-managed' if is_customer_key else 'AWS-managed'} key"
    elif is_encrypted:
        status = "FAIL"
        status_extended = "Encrypted with default AWS-managed key"
    else:
        status = "FAIL"
        status_extended = "Not encrypted"

    return {
        'AUTH_METHOD': 'encrypt-scanner-script',
        'TIMESTAMP': timestamp,
        'ACCOUNT_UID': account_id,
        'FINDING_UID': f"encrypt-scanner-encryption-{account_id}-{region}-{resource_id}",
        'PROVIDER': 'aws',
        'CHECK_ID': f'{resource_type.lower()}_encryption_customer_key',
        'CHECK_TITLE': f"Check if {resource_type} is encrypted with customer-managed KMS key",
        'CHECK_TYPE': 'Software and Configuration Checks',
        'STATUS': status,
        'STATUS_EXTENDED': status_extended,
        'SERVICE_NAME': resource_type.split('_')[0].lower(),
        'SUBSERVICE_NAME': resource_type.split('_')[0].lower(),
        'SEVERITY': 'medium',
        'RESOURCE_TYPE': f"Aws{resource_type}",
        'RESOURCE_UID': resource_arn,
        'RESOURCE_DETAILS': f"Region: {region}",
        'PARTITION': 'aws',
        'REGION': region,
        'DESCRIPTION': f"Check if {resource_type} {resource_id} is encrypted with a customer-managed KMS key",
        'RISK': f"Unencrypted or AWS-managed key encrypted {resource_type} may pose a security risk",
        'REMEDIATION_RECOMMENDATION_TEXT': f"Encrypt the {resource_type} with a customer-managed KMS key",
        'REMEDIATION_RECOMMENDATION_URL': "https://docs.aws.amazon.com/kms/latest/developerguide/services-integration.html",
    }

def output_csv(findings, report_dir):
    # Create the report directory if it doesn't exist
    os.makedirs(report_dir, exist_ok=True)

    filename = f"encrypt-scanner-encryption-{datetime.now().strftime('%Y%m%d%H%M%S')}.csv"
    filepath = os.path.join(report_dir, filename)
    
    headers = [
        'AUTH_METHOD', 'TIMESTAMP', 'ACCOUNT_UID', 'FINDING_UID', 'PROVIDER',
        'CHECK_ID', 'CHECK_TITLE', 'CHECK_TYPE', 'STATUS', 'STATUS_EXTENDED',
        'SERVICE_NAME', 'SUBSERVICE_NAME', 'SEVERITY', 'RESOURCE_TYPE',
        'RESOURCE_UID', 'RESOURCE_DETAILS', 'PARTITION', 'REGION',
        'DESCRIPTION', 'RISK', 'REMEDIATION_RECOMMENDATION_TEXT',
        'REMEDIATION_RECOMMENDATION_URL'
    ]

    with open(filepath, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers, delimiter=';')
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding)

    print(f"CSV report generated: {filepath}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AWS Encryption Scanner")
    parser.add_argument("--aws-access-key-id", help="AWS Access Key ID")
    parser.add_argument("--aws-secret-access-key", help="AWS Secret Access Key")
    parser.add_argument("--aws-session-token", help="AWS Session Token")
    parser.add_argument("--region", help="AWS Region (optional)")
    parser.add_argument("--scan-all-regions", action='store_true', help="Scan all available AWS regions")
    parser.add_argument("--report-dir", default=".", help="Directory to save the report (default: current directory)")
    args = parser.parse_args()

    check_encryption(
        aws_access_key_id=args.aws_access_key_id,
        aws_secret_access_key=args.aws_secret_access_key,
        aws_session_token=args.aws_session_token,
        region=args.region,
        scan_all_regions=args.scan_all_regions,
        report_dir=args.report_dir
    )