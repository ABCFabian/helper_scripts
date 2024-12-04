import argparse
import pymongo
from datetime import datetime
from getpass import getpass
from dotenv import load_dotenv
import os
import boto3
from botocore.exceptions import ClientError

# Load environment variables from .env file
load_dotenv()

def export_to_markdown(process_list, user_list, filename, docdb_name, docdb_endpoint, db_user, connected_databases):
    with open(filename, 'w') as mdfile:
        if docdb_name:
            mdfile.write(f"# {docdb_name}\n\n")
        else:
            mdfile.write("# DocumentDB Export\n\n")
        mdfile.write(f"- DocumentDB Endpoint: {docdb_endpoint}\n")
        mdfile.write(f"- Assumed User: {db_user}\n")
        mdfile.write(f"- Connected Databases: {', '.join(connected_databases)}\n\n")
        
        if user_list:
            mdfile.write("## User List\n")
            mdfile.write("| User | Roles | Database |\n")
            mdfile.write("|------|-------|----------|\n")
            for user in user_list:
                mdfile.write(f"| {user['user']} | {', '.join(user['roles'])} | {user['db']} |\n")
        else:
            mdfile.write("## User List\nUnable to retrieve user list.\n")

        if process_list:
            mdfile.write("\n## Process List\n")
            mdfile.write("| User | Source IP | Connection ID |\n")
            mdfile.write("|------|-----------|---------------|\n")
            for process in process_list:
                mdfile.write(f"| {process['user']} | {process['source_ip']} | {process['conn_id']} |\n")
        else:
            mdfile.write("\n## Process List\nUnable to retrieve process list.\n")

    print(f"Data exported to markdown file: {filename}")

def get_user_list(client):
    user_list = []
    for db_name in client.list_database_names():
        db = client[db_name]
        users = db.command('usersInfo')
        for user in users['users']:
            user_list.append({
                'user': user['user'],
                'roles': [role['role'] for role in user['roles']],
                'db': db_name
            })
    return user_list

def get_process_list(client):
    process_list = list(client.admin.command('currentOp')['inprog'])
    result = []
    for op in process_list:
        if 'client' in op:
            user = op['effectiveUsers']
            source_ip = op['client'].split(':')[0]  # Extract IP without port
            result.append({'user': user, 'source_ip': source_ip, 'conn_id': op['opid']})
    return result

def main(db_user, docdb_endpoint, docdb_name, use_iam_auth, ssl_ca_certs):
    if use_iam_auth:
        connection_string = f"mongodb://{db_user}@{docdb_endpoint}:27017/?authSource=$external&authMechanism=MONGODB-AWS&ssl=true&ssl_ca_certs={ssl_ca_certs}&replicaSet=rs0&readPreference=secondaryPreferred&retryWrites=false"
    else:
        password = getpass("Enter your database password: ")
        connection_string = f"mongodb://{db_user}:{password}@{docdb_endpoint}:27017/?replicaSet=rs0&readPreference=secondaryPreferred&retryWrites=false"
    client = None
    process_list = []
    user_list = []
    connected_databases = []

    try:
        client = pymongo.MongoClient(connection_string)
        client.admin.command('ismaster')
        databases = client.list_database_names()
        process_list = get_process_list(client)
        user_list = get_user_list(client)
        connected_databases = databases

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        markdown_filename = f"documentdb_export_{docdb_name}_{timestamp}.md" if docdb_name else f"documentdb_export_{timestamp}.md"
        export_to_markdown(process_list, user_list, markdown_filename, docdb_name, docdb_endpoint, db_user, connected_databases)

    except pymongo.errors.PyMongoError as err:
        print(f"Error: {err}")
    except ClientError as e:
        print(f"AWS Error: {e}")
    finally:
        if client:
            client.close()
        print("DocumentDB connection is closed")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export DocumentDB process list, user list, and permissions")
    parser.add_argument("--db-user", default=os.getenv('DB_USER'), help="Database username or IAM role/user ARN")
    parser.add_argument("--docdb-endpoint", default=os.getenv('DOCDB_ENDPOINT'), help="DocumentDB endpoint")
    parser.add_argument("--docdb-name", default=os.getenv('DOCDB_NAME'), help="Specify the DocumentDB name to include in the output file and markdown headline")
    parser.add_argument("--use-iam-auth", action="store_true", default=os.getenv('USE_IAM_AUTH', 'false').lower() == 'true', help="Use IAM authentication")
    parser.add_argument("--ssl-ca-certs", default=os.getenv('SSL_CA_CERTS'), help="Path to the SSL CA certificate bundle")
    args = parser.parse_args()

    main(args.db_user, args.docdb_endpoint, args.docdb_name, args.use_iam_auth, args.ssl_ca_certs)