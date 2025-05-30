import psycopg2
import os
import urllib.parse
from werkzeug.security import generate_password_hash

DB_HOST = os.environ.get('DB_HOST', 'localhost')
DB_PORT = os.environ.get('DB_PORT', '5433')
DB_NAME = os.environ.get('DB_NAME', 'incident_db')
DB_USER = os.environ.get('DB_USER', 'postgres')
DB_PASSWORD = os.environ.get('DB_PASSWORD', 'Bh@bh1d33')

password_encoded = urllib.parse.quote_plus(DB_PASSWORD)
DATABASE_URL = os.environ.get('DATABASE_URL', f"postgresql://{DB_USER}:{password_encoded}@{DB_HOST}:{DB_PORT}/{DB_NAME}")

def get_db_connection():
    """Establishes a connection to the PostgreSQL database."""
    conn = None
    try:
        conn = psycopg2.connect(DATABASE_URL)
        print("Successfully connected to the API database!")
        return conn
    except psycopg2.OperationalError as e:
        print(f"Error connecting to the API database: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None

def init_db():
    """Initializes the database tables (incidents and users if not exists) with email in users."""
    conn = get_db_connection()
    if conn is None:
        print("Database connection failed during API initialization.")
        return
    try:
        cur = conn.cursor()

        # Check for and create the incidents table (no changes here)
        cur.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE  table_name = 'incidents'
            );
        """)
        incidents_table_exists = cur.fetchone()[0]

        if not incidents_table_exists:
            cur.execute("""
                CREATE TABLE incidents (
                    id serial PRIMARY KEY,
                    reported_by varchar(255),
                    email_address varchar(255),
                    date_detected timestamp with time zone,
                    incident_type varchar(255),
                    other varchar(255),
                    description text NOT NULL,
                    others_involved text,
                    risk_level varchar(255),
                    root_cause text,
                    proposed_mitigation text,
                    resolution_date timestamp with time zone,
                    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            print("Created the 'incidents' table for API.")
        else:
            print("API table 'incidents' already exists.")

        # Check for and create/update the users table with email
        cur.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE  table_name = 'users'
            );
        """)
        users_table_exists = cur.fetchone()[0]

        if not users_table_exists:
            cur.execute("""
                CREATE TABLE users (
                    id serial PRIMARY KEY,
                    username varchar(80) UNIQUE NOT NULL,
                    email varchar(120) UNIQUE NOT NULL,
                    password_hash varchar(128) NOT NULL
                )
            """)
            default_password = generate_password_hash("defaultpassword")
            cur.execute("INSERT INTO users (username, email, password_hash) VALUES ('testuser', 'testuser@example.com', %s)", (default_password,))
            conn.commit()
            print("Created the 'users' table for API with email and added a default user.")
        else:
            # Check if the email column exists and add it if not
            cur.execute("""
                SELECT column_name
                FROM information_schema.columns
                WHERE table_name = 'users'
                AND column_name = 'email';
            """)
            email_column_exists = cur.fetchone()

            if not email_column_exists:
                cur.execute("ALTER TABLE users ADD COLUMN email varchar(120) UNIQUE;")
                # It's good practice to set a default value or handle existing rows
                cur.execute("UPDATE users SET email = username || '@example.com' WHERE email IS NULL;")
                cur.execute("ALTER TABLE users ALTER COLUMN email SET NOT NULL;")
                conn.commit()
                print("Added column 'email' to the 'users' table.")
            else:
                print("API table 'users' already has the 'email' column.")

        cur.close()
    except Exception as e:
        print(f"Error initializing API database: {e}")
        conn.rollback()
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':
    init_db()