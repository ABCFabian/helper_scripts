import argparse
import psycopg2
from psycopg2.extras import DictCursor
from datetime import datetime
from getpass import getpass
import boto3
from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

def export_to_markdown(process_list, user_list, filename, rds_name, rds_endpoint, db_user, connected_databases):
    with open(filename, 'w') as mdfile:
        if rds_name:
            mdfile.write(f"# {rds_name}\n\n")
        else:
            mdfile.write("# PostgreSQL Export\n\n")
        mdfile.write(f"- RDS Endpoint: {rds_endpoint}\n")
        mdfile.write(f"- Assumed User: {db_user}\n")
        mdfile.write(f"- Connected Databases: {', '.join(connected_databases)}\n\n")
        
        if user_list:
            mdfile.write("## User List\n")
            mdfile.write("| Role name | Attributes | Member of | Description |\n")
            mdfile.write("|-----------|------------|-----------|-------------|\n")
            for user in user_list:
                mdfile.write(f"| {user['rolname']} | {user['attributes']} | {user['member_of']} | {user['description']} |\n")
        else:
            mdfile.write("## User List\nUnable to retrieve user list.\n")

        if process_list:
            mdfile.write("\n## Process List\n")
            mdfile.write("| PID | User | Client Address | Database | Backend Start | Query Start | State | Query |\n")
            mdfile.write("|----|------|----------------|----------|---------------|-------------|-------|-------|\n")
            for process in process_list:
                mdfile.write(f"| {process['pid']} | {process['usename']} | {process['client_addr'] or 'local'} | "
                             f"{process['datname']} | {process['backend_start']} | {process['query_start']} | "
                             f"{process['state']} | {process['query']} |\n")
        else:
            mdfile.write("\n## Process List\nUnable to retrieve process list.\n")

    print(f"Data exported to markdown file: {filename}")

def get_user_list(cursor):
    cursor.execute("""
        SELECT r.rolname,
               CASE WHEN r.rolsuper THEN 'Superuser, ' ELSE '' END ||
               CASE WHEN r.rolinherit THEN 'Inherit, ' ELSE 'NoInherit, ' END ||
               CASE WHEN r.rolcreaterole THEN 'Create role, ' ELSE '' END ||
               CASE WHEN r.rolcreatedb THEN 'Create DB, ' ELSE '' END ||
               CASE WHEN r.rolcanlogin THEN 'Can login, ' ELSE '' END ||
               CASE WHEN r.rolreplication THEN 'Replication, ' ELSE '' END ||
               CASE WHEN r.rolbypassrls THEN 'Bypass RLS, ' ELSE '' END AS attributes,
               COALESCE(ARRAY_TO_STRING(ARRAY(SELECT m.rolname FROM pg_auth_members am JOIN pg_roles m ON m.oid = am.roleid WHERE am.member = r.oid), ', '), '') AS member_of,
               pg_catalog.shobj_description(r.oid, 'pg_authid') AS description
        FROM pg_roles r
        WHERE r.rolname !~ '^pg_'
        ORDER BY 1;
    """)
    return cursor.fetchall()


def main(db_user, rds_endpoint, rds_name, aws_profile):
    config = {
        'user': db_user,
        'host': rds_endpoint,
        'port': 5432,
    }

    conn = None
    cursor = None
    process_list = []
    user_list = []
    connected_databases = []

    try:
        if aws_profile:
            if not rds_endpoint:
                raise ValueError("RDS endpoint is required when using IAM authentication.")
            boto3.setup_default_session(profile_name=aws_profile)
            client = boto3.client('rds')
            token = client.generate_db_auth_token(DBHostname=rds_endpoint, Port=5432, DBUsername=config['user'])
            config['password'] = token
        else:
            config['password'] = getpass("Enter your database password: ")

        # Try to connect to 'postgres' database
        try:
            config['dbname'] = 'postgres'
            conn = psycopg2.connect(**config)
            cursor = conn.cursor(cursor_factory=DictCursor)

            # Get list of databases
            cursor.execute("SELECT datname FROM pg_database WHERE datistemplate = false;")
            databases = [row['datname'] for row in cursor.fetchall()]

            # Get process list
            cursor.execute("""
                SELECT pid, usename, client_addr, datname, backend_start, query_start, state, query
                FROM pg_stat_activity
                WHERE pid <> pg_backend_pid()
            """)
            process_list = cursor.fetchall()

            # Get user list
            user_list = get_user_list(cursor)

            cursor.close()
            conn.close()

            connected_databases.append('postgres')
        except psycopg2.Error as e:
            print(f"Error connecting to 'postgres' database: {e}")

        # Try to connect to each database and get grants
        for db in databases:
            try:
                config['dbname'] = db
                conn = psycopg2.connect(**config)
                cursor = conn.cursor(cursor_factory=DictCursor)
                

                cursor.close()
                conn.close()
                connected_databases.append(db)
            except psycopg2.Error as e:
                print(f"Error connecting to '{db}' database: {e}")

        # Generate filename and export to markdown
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        markdown_filename = f"postgresql_export_{rds_name}_{timestamp}.md" if rds_name else f"postgresql_export_{timestamp}.md"
        export_to_markdown(process_list, user_list, markdown_filename, rds_name, rds_endpoint, db_user, connected_databases)

    except psycopg2.Error as err:
        print(f"Error: {err}")
    except ValueError as val_err:
        print(f"Configuration Error: {val_err}")
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
        print("PostgreSQL connections are closed")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export PostgreSQL process list, user list, and permissions")
    parser.add_argument("--db-user", default=os.getenv('DB_USER'), help="Database username")
    parser.add_argument("--rds-endpoint", default=os.getenv('RDS_ENDPOINT'), help="RDS endpoint (required for IAM authentication)")
    parser.add_argument("--rds-name", default=os.getenv('RDS_NAME'), help="Specify the RDS name to include in the output file and markdown headline")
    parser.add_argument("--aws-profile", default=os.getenv('AWS_PROFILE'), help="Specify the AWS profile to use for IAM authentication")
    args = parser.parse_args()

    main(args.db_user, args.rds_endpoint, args.rds_name, args.aws_profile)