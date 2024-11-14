#!/bin/bash

source .env

log() {
    local level="$1"
    shift
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $*" >&2
}

validate_env_var() {
    local var_name="$1"
    local var_value="${!var_name}"
    if [ -z "$var_value" ]; then
        log ERROR "Missing required environment variable: $var_name"
        exit 1
    fi
}

validate_env_var REPORT_BUCKET
validate_env_var TARGET_ACCOUNT
validate_env_var CUSTOMER
validate_env_var TARGET_ROLE

SESSION_NAME="security-scan"
S3_PREFIX="${CUSTOMER}/kms-encrypt-reports"
DT=$(date '+%Y-%m-%d-%H%M')

log INFO "Running kms-encrypt scan"

log INFO "Using Account: $TARGET_ACCOUNT, using Role: $TARGET_ROLE"

OUTPUT_DIR="${TARGET_ACCOUNT}/${TARGET_ACCOUNT}-kms-encrypt-${DT}"

log INFO "REPORT_BUCKET: $REPORT_BUCKET"
log INFO "TARGET_ROLE: $TARGET_ROLE"

# Validate Values from Environment Variables Created By Terraform
echo "REPORT_BUCKET:  $REPORT_BUCKET"
echo "TARGET_ROLE:    $TARGET_ROLE"

# Assume the role using AWS CLI and capture the output
ASSUME_ROLE_OUTPUT=$(aws sts assume-role --role-arn "$TARGET_ROLE" --role-session-name "$SESSION_NAME" 2>&1)

# Check if the assume-role command was successful
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to assume role. Error message: $ASSUME_ROLE_OUTPUT"
    exit 1
fi

# Extract credentials using jq
NEW_AWS_ACCESS_KEY_ID=$(echo $ASSUME_ROLE_OUTPUT | jq -r '.Credentials.AccessKeyId')
NEW_AWS_SECRET_ACCESS_KEY=$(echo $ASSUME_ROLE_OUTPUT | jq -r '.Credentials.SecretAccessKey')
NEW_AWS_SESSION_TOKEN=$(echo $ASSUME_ROLE_OUTPUT | jq -r '.Credentials.SessionToken')

# Check if credentials were successfully extracted
if [ -z "$NEW_AWS_ACCESS_KEY_ID" ] || [ -z "$NEW_AWS_SECRET_ACCESS_KEY" ] || [ -z "$NEW_AWS_SESSION_TOKEN" ]; then
    echo "ERROR: Failed to extract credentials from assumed role."
    exit 1
fi

# Run scout
echo -e "Assessing AWS Account: $TARGET_ACCOUNT, using Role: $TARGET_ROLE on $(date)"
echo -e "Assume Role Access Key: $NEW_AWS_ACCESS_KEY_ID"
python3 check_kms_encryption.py --aws-access-key-id "$NEW_AWS_ACCESS_KEY_ID" --aws-secret-access-key "$NEW_AWS_SECRET_ACCESS_KEY" \
    --aws-session-token "$NEW_AWS_SESSION_TOKEN" --report-dir "/tmp/$OUTPUT_DIR" --scan-all-regions

S3_DEST="s3://$REPORT_BUCKET/$S3_PREFIX/$OUTPUT_DIR"
log INFO "Saving kms encryption report to $S3_DEST"

upload_to_s3() {
    local source="$1"
    local destination="$2"
    
    if aws s3 cp "$source" "$destination" --recursive; then
        log INFO "Successfully uploaded to $destination"
    else
        log ERROR "Failed to upload to $destination"
        exit 1
    fi
}

upload_to_s3 "/tmp/$OUTPUT_DIR" "$S3_DEST"

log INFO "Completed AWS Account: $TARGET_ACCOUNT, using Role: $TARGET_ROLE"
log INFO "KMS encryption Assessments Completed"