import csv
import os
import mysql.connector
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# RDS MySQL connection details from environment variables
config = {
    'user': os.getenv('DB_USER'),
    'host': os.getenv('DB_HOST'),
#    'database': os.getenv('DB_DATABASE'),
    'raise_on_warnings': True
}

# Connect to the database
try:
    # Prompt for password at runtime
    password = input("Enter your database password: ")
    config['password'] = password

    conn = mysql.connector.connect(**config)
    cursor = conn.cursor(dictionary=True)

    # Execute SHOW PROCESSLIST
    cursor.execute("SHOW PROCESSLIST")
    results = cursor.fetchall()

    # Generate a filename with timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"processlist_{timestamp}.csv"

    # Write results to CSV
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=results[0].keys())
        writer.writeheader()
        for row in results:
            writer.writerow(row)

    print(f"Process list exported to {filename}")

except mysql.connector.Error as err:
    print(f"Error: {err}")

finally:
    if 'conn' in locals() and conn.is_connected():
        cursor.close()
        conn.close()
        print("MySQL connection is closed")
