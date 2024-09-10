#!/bin/bash

# Ensure AWS CLI is configured with appropriate permissions
# Install AWS CLI if not already installed: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html

# Fetch all controls using the ListControls API
controls=$(aws controltower list-enabled-controls --query 'Controls[*].{Id:ControlIdentifier,Name:Name}' --output json)

# Iterate over each control to get details
echo "Control Details:"
for control in $(echo "${controls}" | jq -c '.[]'); do
    control_id=$(echo "${control}" | jq -r '.Id')
    control_name=$(echo "${control}" | jq -r '.Name')

    # Fetch control details using the GetControl API
    control_details=$(aws controltower get-control --control-identifier "${control_id}" --query '{Description:Control.Description, AppliedAccounts:TargetAccounts, AppliedOUs:TargetOUs}' --output json)

    # Extracting details
    description=$(echo "${control_details}" | jq -r '.Description')
    applied_accounts=$(echo "${control_details}" | jq -r '.AppliedAccounts[]')
    applied_ous=$(echo "${control_details}" | jq -r '.AppliedOUs[]')

    # Display control information
    echo "Control Name: ${control_name}"
    echo "Description: ${description}"
    echo "Applied Accounts: ${applied_accounts}"
    echo "Applied OUs: ${applied_ous}"
    echo "-----------------------------------"
done