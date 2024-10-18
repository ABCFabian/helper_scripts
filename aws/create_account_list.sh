#!/bin/bash

# Output file name
OUTPUT_FILE="aws_accounts.txt"

# Use AWS CLI to list accounts and format the output
aws organizations list-accounts \
  --query 'Accounts[?Status==`ACTIVE`].[Id,Name]' \
  --output text | \
  sort | \
  while read -r id name; do
    echo "$id $name"
  done > "$OUTPUT_FILE"

echo "AWS account list has been saved to $OUTPUT_FILE"

