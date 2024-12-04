import argparse
import mysql.connector
from datetime import datetime
from getpass import getpass
import boto3
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

def export_to_markdown(process_list, user_list, grants_list, filename, rds_name, rds_endpoint, db_user):
    with open(filename, 'w') as mdfile:
        if rds_name:
            mdfile.write(f"# {rds_name}\n\n")
        else:
            mdfile.write("# MySQL Export\n\n")
        mdfile.write(f"- RDS Endpoint: {rds_endpoint}\n")
        mdfile.write(f"- Assumed User: {db_user}")
        mdfile.write("\n## User List\n")
        mdfile.write("| User | Host | Plugin |\n")
        mdfile.write("|------|------|--------|\n")
        for user in user_list:
            mdfile.write(f"| {user['User']} | {user['Host']} | {user['plugin']} |\n")

        mdfile.write("\n## User Grants\n")
        mdfile.write("| User | Grant |\n")
        mdfile.write("|------|-------|\n")
        for user, grants in grants_list.items():
            for grant in grants:
                mdfile.write(f"| {user} | {grant.replace('*', '\\*')} |\n")
        mdfile.write("\n")
        
        mdfile.write("## Process List\n")
        mdfile.write("| Id | User | Host | db | Command | Time | State | Info |\n")
        mdfile.write("|----|------|------|----|---------|----- |-------|------|\n")
        for process in process_list:
            mdfile.write(f"| {process['Id']} | {process['User']} | {process['Host']} | {process['db']} | "
                         f"{process['Command']} | {process['Time']} | {process['State']} | {process['Info']} |\n")

    print(f"Data exported to markdown file: {filename}")

def main(db_user, rds_endpoint, rds_name, aws_profile):
    config = {
        'user': db_user,
        'host': '127.0.0.1',  # Connect through localhost due to SSH tunneling
        'raise_on_warnings': True
    }

    try:

        if aws_profile:
            if not rds_endpoint:
                raise ValueError("RDS endpoint is required when using IAM authentication.")

            # Set AWS profile
            boto3.setup_default_session(profile_name=aws_profile)

            # Generate an IAM authentication token
            client = boto3.client('rds')
            token = client.generate_db_auth_token(
                DBHostname=rds_endpoint,
                Port=3306,
                DBUsername=config['user']
            )
            config['password'] = token
            #config['auth_plugin'] = 'mysql_clear_password'
        else:
            # Securely prompt for password at runtime without echoing it
            password = getpass("Enter your database password: ")
            config['password'] = password
        config['auth_plugin'] = 'mysql_clear_password'


        conn = mysql.connector.connect(**config)
        cursor = conn.cursor(dictionary=True)

        # Execute SHOW PROCESSLIST
        cursor.execute("SHOW PROCESSLIST")
        process_list = cursor.fetchall()

        # Generate a filename with timestamp for process list
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Execute query to get MySQL users
        cursor.execute("SELECT User, Host, plugin FROM mysql.user")
        user_list = cursor.fetchall()

        # Get grants for each user
        grants_list = {}
        for user in user_list:
            username = user['User']
            hostname = user['Host']
            cursor.execute(f"SHOW GRANTS FOR '{username}'@'{hostname}'")
            grants = [row[f"Grants for {username}@{hostname}"] for row in cursor.fetchall()]
            grants_list[f"{username}@{hostname}"] = grants

        # Export all data to a markdown file
        markdown_filename = f"mysql_export_{rds_name}_{timestamp}.md" if rds_name else f"mysql_export_{timestamp}.md"
        export_to_markdown(process_list, user_list, grants_list, markdown_filename, rds_name, rds_endpoint, db_user)

    except mysql.connector.Error as err:
        print(f"Error: {err}")
    except ValueError as val_err:
        print(f"Configuration Error: {val_err}")

    finally:
        if 'conn' in locals() and conn.is_connected():
            cursor.close()
            conn.close()
            print("MySQL connection is closed")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export MySQL process list, user list, and permissions")
    parser.add_argument("--db-user", default=os.getenv('DB_USER'), help="Database username")
    parser.add_argument("--rds-endpoint", default=os.getenv('RDS_ENDPOINT'), help="RDS endpoint (required for IAM authentication)")
    parser.add_argument("--rds-name", default=os.getenv('RDS_NAME'), help="Specify the RDS name to include in the output file and markdown headline")
    parser.add_argument("--aws-profile", default=os.getenv('AWS_PROFILE'), help="Specify the AWS profile to use for IAM authentication")
    args = parser.parse_args()

    main(args.db_user, args.rds_endpoint, args.rds_name, args.aws_profile)