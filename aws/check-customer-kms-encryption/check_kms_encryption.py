import boto3
import csv
from datetime import datetime, timezone
from botocore.exceptions import ClientError

def is_customer_managed_key(kms_client, key_id):
    try:
        key_info = kms_client.describe_key(KeyId=key_id)
        return key_info['KeyMetadata']['KeyManager'] == 'CUSTOMER'
    except ClientError:
        return False

def check_encryption():
    ec2_client = boto3.client('ec2')
    rds_client = boto3.client('rds')
    sqs_client = boto3.client('sqs')
    dynamodb_client = boto3.client('dynamodb')
    redshift_client = boto3.client('redshift')
    elasticache_client = boto3.client('elasticache')
    secretsmanager_client = boto3.client('secretsmanager')
    sns_client = boto3.client('sns')
    efs_client = boto3.client('efs')
    kms_client = boto3.client('kms')
    sts_client = boto3.client('sts')

    account_id = sts_client.get_caller_identity()['Account']
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-4]

    findings = []

    # Check EBS volumes
    print("Checking EBS volumes...")
    volumes_paginator = ec2_client.get_paginator('describe_volumes')
    for page in volumes_paginator.paginate():
        for volume in page['Volumes']:
            finding = create_finding(volume, 'EbsVolume', account_id, timestamp, kms_client)
            findings.append(finding)

    # Check EBS snapshots
    print("Checking EBS snapshots...")
    snapshots_paginator = ec2_client.get_paginator('describe_snapshots')
    for page in snapshots_paginator.paginate(OwnerIds=['self']):
        for snapshot in page['Snapshots']:
            finding = create_finding(snapshot, 'EbsSnapshot', account_id, timestamp, kms_client)
            findings.append(finding)

    # Check RDS instances
    print("Checking RDS instances...")
    rds_paginator = rds_client.get_paginator('describe_db_instances')
    for page in rds_paginator.paginate():
        for instance in page['DBInstances']:
            finding = create_finding(instance, 'RdsInstance', account_id, timestamp, kms_client)
            findings.append(finding)

    # Check SQS queues
    print("Checking SQS queues...")
    queues = sqs_client.list_queues()
    for queue_url in queues.get('QueueUrls', []):
        queue_attrs = sqs_client.get_queue_attributes(QueueUrl=queue_url, AttributeNames=['All'])
        queue_info = {'QueueUrl': queue_url, 'Attributes': queue_attrs['Attributes']}
        finding = create_finding(queue_info, 'SqsQueue', account_id, timestamp, kms_client)
        findings.append(finding)

    # Check DynamoDB tables
    print("Checking DynamoDB tables...")
    tables = dynamodb_client.list_tables()['TableNames']
    for table_name in tables:
        table_info = dynamodb_client.describe_table(TableName=table_name)['Table']
        if 'SSEDescription' in table_info:
            finding = create_finding(table_info, 'DynamoDBTable', account_id, timestamp, kms_client)
            findings.append(finding)

    # Check Redshift clusters
    print("Checking Redshift clusters...")
    clusters = redshift_client.describe_clusters()['Clusters']
    for cluster in clusters:
        finding = create_finding(cluster, 'RedshiftCluster', account_id, timestamp, kms_client)
        findings.append(finding)

    # Check ElastiCache clusters
    print("Checking ElastiCache clusters...")
    cache_clusters = elasticache_client.describe_cache_clusters()['CacheClusters']
    for cluster in cache_clusters:
        finding = create_finding(cluster, 'ElastiCacheCluster', account_id, timestamp, kms_client)
        findings.append(finding)

    # Check Secrets Manager secrets
    print("Checking Secrets Manager secrets...")
    secrets = secretsmanager_client.list_secrets()['SecretList']
    for secret in secrets:
        finding = create_finding(secret, 'SecretsManagerSecret', account_id, timestamp, kms_client)
        findings.append(finding)

    # Check SNS topics
    print("Checking SNS topics...")
    topics = sns_client.list_topics()['Topics']
    for topic in topics:
        topic_attributes = sns_client.get_topic_attributes(TopicArn=topic['TopicArn'])['Attributes']
        finding = create_finding(topic_attributes, 'SNSTopic', account_id, timestamp, kms_client)
        findings.append(finding)

    # Check EFS file systems
    print("Checking EFS file systems...")
    file_systems = efs_client.describe_file_systems()['FileSystems']
    for fs in file_systems:
        finding = create_finding(fs, 'EFSFileSystem', account_id, timestamp, kms_client)
        findings.append(finding)

    output_csv(findings)

def create_finding(resource, resource_type, account_id, timestamp, kms_client):
    is_encrypted = False
    kms_key_id = None
    resource_id = None
    region = boto3.session.Session().region_name

    if resource_type == 'EbsVolume':
        is_encrypted = resource['Encrypted']
        kms_key_id = resource.get('KmsKeyId')
        resource_id = resource['VolumeId']
        region = resource['AvailabilityZone'][:-1]
    elif resource_type == 'EbsSnapshot':
        is_encrypted = resource['Encrypted']
        kms_key_id = resource.get('KmsKeyId')
        resource_id = resource['SnapshotId']
    elif resource_type == 'RdsInstance':
        is_encrypted = resource['StorageEncrypted']
        kms_key_id = resource.get('KmsKeyId')
        resource_id = resource['DBInstanceIdentifier']
        region = resource['AvailabilityZone'][:-1]
    elif resource_type == 'SqsQueue':
        is_encrypted = 'KmsMasterKeyId' in resource['Attributes']
        kms_key_id = resource['Attributes'].get('KmsMasterKeyId')
        resource_id = resource['QueueUrl'].split('/')[-1]
        region = resource['QueueUrl'].split('.')[1]
    elif resource_type == 'DynamoDBTable':
        is_encrypted = 'SSEDescription' in resource
        kms_key_id = resource.get('SSEDescription', {}).get('KMSMasterKeyArn')
        resource_id = resource['TableName']
    elif resource_type == 'RedshiftCluster':
        is_encrypted = resource['Encrypted']
        kms_key_id = resource.get('KmsKeyId')
        resource_id = resource['ClusterIdentifier']
    elif resource_type == 'ElastiCacheCluster':
        is_encrypted = resource.get('AtRestEncryptionEnabled', False)
        kms_key_id = resource.get('KmsKeyId')
        resource_id = resource['CacheClusterId']
    elif resource_type == 'SecretsManagerSecret':
        is_encrypted = True  # Secrets are always encrypted
        kms_key_id = resource.get('KmsKeyId')
        resource_id = resource['Name']
    elif resource_type == 'SNSTopic':
        is_encrypted = 'KmsMasterKeyId' in resource
        kms_key_id = resource.get('KmsMasterKeyId')
        resource_id = resource['TopicArn'].split(':')[-1]
    elif resource_type == 'EFSFileSystem':
        is_encrypted = resource['Encrypted']
        kms_key_id = resource.get('KmsKeyId')
        resource_id = resource['FileSystemId']

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
        'RESOURCE_UID': resource_id,
        'RESOURCE_DETAILS': f"Region: {region}",
        'PARTITION': 'aws',
        'REGION': region,
        'DESCRIPTION': f"Check if {resource_type} {resource_id} is encrypted with a customer-managed KMS key",
        'RISK': f"Unencrypted or AWS-managed key encrypted {resource_type} may pose a security risk",
        'REMEDIATION_RECOMMENDATION_TEXT': f"Encrypt the {resource_type} with a customer-managed KMS key",
        'REMEDIATION_RECOMMENDATION_URL': "https://docs.aws.amazon.com/kms/latest/developerguide/services-integration.html",
    }

def output_csv(findings):
    filename = f"encrypt-scanner-encryption-{datetime.now().strftime('%Y%m%d%H%M%S')}.csv"
    headers = [
        'AUTH_METHOD', 'TIMESTAMP', 'ACCOUNT_UID', 'FINDING_UID', 'PROVIDER',
        'CHECK_ID', 'CHECK_TITLE', 'CHECK_TYPE', 'STATUS', 'STATUS_EXTENDED',
        'SERVICE_NAME', 'SUBSERVICE_NAME', 'SEVERITY', 'RESOURCE_TYPE',
        'RESOURCE_UID', 'RESOURCE_DETAILS', 'PARTITION', 'REGION',
        'DESCRIPTION', 'RISK', 'REMEDIATION_RECOMMENDATION_TEXT',
        'REMEDIATION_RECOMMENDATION_URL'
    ]

    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers, delimiter=';')
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding)

    print(f"CSV report generated: {filename}")

if __name__ == "__main__":
    check_encryption()