import boto3
import json
import requests
import sys
from urllib.parse import quote

def assume_role(role_arn, session_name):
    client = boto3.client('sts')
    response = client.assume_role(
        RoleArn=role_arn,
        RoleSessionName=session_name
    )
    return response['Credentials']

def get_console_url(credentials):
    session_data = {
        "sessionId": credentials['AccessKeyId'],
        "sessionKey": credentials['SecretAccessKey'],
        "sessionToken": credentials.get('SessionToken', '')  # SessionToken might be empty for direct IAM user access
    }
    session_json = json.dumps(session_data)

    # URL encode the session JSON
    encoded_session_json = quote(session_json)

    federation_url = "https://signin.aws.amazon.com/federation"
    response = requests.get(f"{federation_url}?Action=getSigninToken&Session={encoded_session_json}")

    # Debugging: Print response status and text
    print("Response Status Code:", response.status_code)
    print("Response Text:", response.text)

    # Check if response is valid JSON
    try:
        signin_token = response.json().get('SigninToken')
        if not signin_token:
            raise Exception("SigninToken not found in response.")
    except json.JSONDecodeError:
        raise Exception("Failed to decode JSON. Response might not be valid JSON.")
    
    console_url = f"{federation_url}?Action=login&Issuer=Example.org&Destination=https%3A%2F%2Fconsole.aws.amazon.com%2F&SigninToken={signin_token}"
    return console_url

def main():
    # Check if role ARN is provided as a command-line argument
    if len(sys.argv) > 1:
        role_arn = sys.argv[1]
        session_name = 'MySession'
        credentials = assume_role(role_arn, session_name)
    else:
        # Use current IAM access keys if no role ARN is provided
        session = boto3.Session()
        credentials = {
            'AccessKeyId': session.get_credentials().access_key,
            'SecretAccessKey': session.get_credentials().secret_key,
            'SessionToken': session.get_credentials().token  # May be None if using long-term credentials
        }

    console_url = get_console_url(credentials)
    
    print("AWS Management Console URL:", console_url)

if __name__ == "__main__":
    main()