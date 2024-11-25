import csv
import os
import argparse
import mysql.connector
from datetime import datetime
from dotenv import load_dotenv
from getpass import getpass
import boto3

# Load environment variables from .env file
load_dotenv()

# RDS MySQL connection details from environment variables
config = {
    'user': os.getenv('DB_USER'),
    'host': '127.0.0.1',  # Connect through localhost due to SSH tunneling
    'raise_on_warnings': True
}

def export_to_csv(data, filename):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=data[0].keys())
        writer.writeheader()
        for row in data:
            writer.writerow(row)
    print(f"Data exported to {filename}")

def export_to_markdown(process_list, user_list, grants_list, filename, rds_name=None):
    with open(filename, 'w') as mdfile:
        if rds_name:
            mdfile.write(f"# {rds_name}\n\n")
        else:
            mdfile.write("# MySQL Export\n\n")

        mdfile.write("\n## User List\n")
        mdfile.write("| User | Host | Plugin |\n")
        mdfile.write("|------|------|--------|\n")
        for user in user_list:
            mdfile.write(f"| {user['User']} | {user['Host']} | {user['plugin']} |\n")

        mdfile.write("\n## User Grants\n")
        for user, grants in grants_list.items():
            mdfile.write(f"### Grants for {user}\n")
            for grant in grants:
                mdfile.write(f"- {grant.replace('*', '\\*')}\n")
            mdfile.write("\n")
        
        mdfile.write("## Process List\n")
        mdfile.write("| Id | User | Host | db | Command | Time | State | Info |\n")
        mdfile.write("|----|------|------|----|---------|------|-------|------|\n")
        for process in process_list:
            mdfile.write(f"| {process['Id']} | {process['User']} | {process['Host']} | {process['db']} | "
                         f"{process['Command']} | {process['Time']} | {process['State']} | {process['Info']} |\n")

    print(f"Data exported to markdown file: {filename}")

def main(get_users, export_markdown, rds_name, use_iam):
    try:
        if use_iam:
            # Use RDS endpoint from environment variables for token generation
            rds_endpoint = os.getenv('RDS_ENDPOINT')
            if not rds_endpoint:
                raise ValueError("RDS_ENDPOINT environment variable is not set.")

            # Generate an IAM authentication token
            client = boto3.client('rds')
            token = client.generate_db_auth_token(
                DBHostname=rds_endpoint,
                Port=3306,
                DBUsername=config['user']
            )
            config['password'] = token
            config['auth_plugin'] = 'mysql_clear_password'
        else:
            # Securely prompt for password at runtime without echoing it
            password = getpass("Enter your database password: ")
            config['password'] = password

        conn = mysql.connector.connect(**config)
        cursor = conn.cursor(dictionary=True)

        # Execute SHOW PROCESSLIST
        cursor.execute("SHOW PROCESSLIST")
        process_list = cursor.fetchall()

        # Generate a filename with timestamp for process list
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if get_users:
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

            if export_markdown:
                # Export all data to a markdown file
                markdown_filename = f"mysql_export_{rds_name}_{timestamp}.md" if rds_name else f"mysql_export_{timestamp}.md"
                export_to_markdown(process_list, user_list, grants_list, markdown_filename, rds_name)
            else:
                # Export process list and user list to CSVs separately
                process_filename = f"processlist_{rds_name}_{timestamp}.csv" if rds_name else f"processlist_{timestamp}.csv"
                export_to_csv(process_list, process_filename)

                user_filename = f"mysql_users_{rds_name}_{timestamp}.csv" if rds_name else f"mysql_users_{timestamp}.csv"
                export_to_csv(user_list, user_filename)

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
    parser = argparse.ArgumentParser(description="Export MySQL process list and optionally user list and permissions")
    parser.add_argument("--users", action="store_true", help="Also export MySQL users and their permissions")
    parser.add_argument("--markdown", action="store_true", help="Export all data to a single markdown file")
    parser.add_argument("--rds-name", help="Specify the RDS name to include in the output file and markdown headline")
    parser.add_argument("--use-iam", action="store_true", help="Use IAM authentication for RDS login")
    args = parser.parse_args()

    main(args.users, args.markdown, args.rds_name, args.use_iam)