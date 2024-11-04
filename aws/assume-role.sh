#!/bin/bash

# Check if the required command-line argument is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: source assume_role.sh <role-arn>"
    return 1
fi

ROLE_ARN=$1
SESSION_NAME="AWSCLI-Session"

# Assume the role using AWS CLI and capture the output
ASSUME_ROLE_OUTPUT=$(aws sts assume-role --role-arn "$ROLE_ARN" --role-session-name "$SESSION_NAME")

# Check if the assume-role command was successful
if [ $? -ne 0 ]; then
    echo "Failed to assume role $ROLE_ARN"
    return 1
fi

# Extract credentials using jq
export AWS_ACCESS_KEY_ID=$(echo $ASSUME_ROLE_OUTPUT | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo $ASSUME_ROLE_OUTPUT | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo $ASSUME_ROLE_OUTPUT | jq -r '.Credentials.SessionToken')


echo "Successfully assumed role $ROLE_ARN and exported credentials to session."
# Open new process
