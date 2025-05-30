from flask import Flask, jsonify, request, url_for, render_template_string # Added url_for, render_template_string
from db.database import get_db_connection
from psycopg2.extras import RealDictCursor, DictCursor
import datetime
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity, get_jwt
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import timedelta
from flask_cors import CORS
import secrets
import string
import re
# from notifications import send_password_reset_email, notify_new_incident, notify_incident_closed # Temporarily comment or remove send_password_reset_email from here
from notifications import notify_new_incident, notify_incident_closed # Keeping other notifications for now
from functools import wraps
import logging
import os # Added for os.getenv
from dotenv import load_dotenv # Added for loading .env

# NEW IMPORTS FOR PASSWORD RESET
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature


# Load environment variables from .env file (Make sure this is at the top after imports)
load_dotenv()

app = Flask(__name__)
CORS(app)

# Setup Flask-JWT-Extended
app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY', "super-secret-fallback") # Use environment variable for secret key
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=120)
jwt = JWTManager(app)

#salt
JWT_SALT = os.getenv('JWT_SALT')

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# NEW: Flask-Mail Configuration
app.config['MAIL_SERVER'] = os.getenv('SMTP_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('SMTP_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() in ('true', '1', 't')
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'False').lower() in ('true', '1', 't')
app.config['MAIL_USERNAME'] = os.getenv('SMTP_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('SMTP_SENDER_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('SMTP_SENDER_EMAIL')

# NEW: Frontend URL for password reset links
app.config['FRONTEND_URL'] = os.getenv('FRONTEND_URL', 'http://localhost:3000')

mail = Mail(app) # Initialize Flask-Mail

# NEW: Initialize URLSafeTimedSerializer for password reset tokens
# Using JWT_SECRET_KEY as the secret for the serializer for consistency
s = URLSafeTimedSerializer(app.config['JWT_SECRET_KEY'])


# --- Role-Based Access Control Decorator ---
def role_required(required_roles):
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            claims = get_jwt()
            user_role = claims.get('role')
            if user_role not in required_roles:
                app.logger.warning(f"Access denied for user {get_jwt_identity()} (role: {user_role}). Required roles: {required_roles}")
                return jsonify({"msg": "Access denied: Insufficient permissions"}), 403
            return fn(*args, **kwargs)
        return wrapper
    return decorator

def generate_random_password(length=12):
    """Generates a random password."""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for i in range(length))

def serialize_incident(incident):
    """Serializes an incident object into a dictionary for JSON response.
        Formats dates as dd/mm/yyyy."""
    date_detected_str = incident[3].strftime('%d/%m/%Y') if incident[3] else None
    resolution_date_str = incident[11].strftime('%d/%m/%Y') if incident[11] else None
    created_at_str = incident[12].strftime('%d/%m/%Y %H:%M:%S') if incident[12] else None

    return {
        'id': incident[0],
        'reported_by': incident[1],
        'email_address': incident[2],
        'date_detected': date_detected_str,
        'incident_type': incident[4],
        'other': incident[5],
        'description': incident[6],
        'others_involved': incident[7],
        'risk_level': incident[8],
        'root_cause': incident[9],
        'proposed_mitigation': incident[10],
        'resolution_date': resolution_date_str,
        'created_at': created_at_str,
        'incident_status': incident[13]
    }

def parse_date_yyyymmdd(date_str):
    """Helper function to parse YYYY-MM-DD string to datetime.date object."""
    if not date_str:
        return None
    try:
        return datetime.datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        app.logger.error(f"Error parsing date '{date_str}' from YYYY-MM-DD format.")
        return None

def is_valid_email(email):
    """Basic email format validation."""
    return re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None

def serialize_user(user_tuple):
    """
    Serializes a user tuple fetched from the database into a dictionary.
    Assumes the tuple order is: (id, username, email, fullname, role, created_at, password_reset_required)
    """
    if not user_tuple or len(user_tuple) < 7: # Updated length to include password_reset_required
        app.logger.warning(f"Incomplete user tuple for serialization: {user_tuple}")
        return None

    user_id, username, email, fullname, role, created_at, password_reset_required = user_tuple
    created_at_str = created_at.strftime('%Y-%m-%d %H:%M:%S') if created_at else 'N/A'

    return {
        'id': user_id,
        'username': username,
        'email': email,
        'fullname': fullname,
        'role': role,
        'created_at': created_at_str,
        'password_reset_required': password_reset_required
    }

# NEW: Helper function to send password reset email via Flask-Mail
def send_password_reset_email_via_flask_mail(user_email, user_id, reset_token, fullname):
    """Sends a password reset email using Flask-Mail."""
    # Ensure user_id is included as a query parameter in the reset link
    reset_link = f"{app.config['FRONTEND_URL']}/reset-password?token={reset_token}&user_id={user_id}"

    msg = Message(
        subject="Password Reset Request for Incident Reporting System",
        recipients=[user_email],
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    msg.html = render_template_string("""
        <p>Dear {{ fullname }},</p>
        <p>You have requested to reset your password for the Incident Reporting System.</p>
        <p>Please click on the link below to reset your password:</p>
        <p><a href="{{ reset_link }}">{{ reset_link }}</a></p>
        <p>This link is valid for 1 hour.</p>
        <p>If you did not request a password reset, please ignore this email.</p>
        <p>Thank you,</p>
        <p>The Incident Reporting Team</p>
    """, fullname=fullname, reset_link=reset_link)
    
    try:
        mail.send(msg)
        app.logger.info(f"Password reset email sent to {user_email}")
        return True
    except Exception as e:
        app.logger.error(f"Failed to send password reset email to {user_email}: {e}")
        return False

#sending email to new user
def send_welcome_email_to_new_user(user_email, user_id, reset_token, fullname,username):
    """Sends a password reset email using Flask-Mail."""
    # Ensure user_id is included as a query parameter in the reset link
    reset_link = f"{app.config['FRONTEND_URL']}/reset-password?token={reset_token}&user_id={user_id}"

    msg = Message(
        subject="Welcome to the Incident Reporting System! Set Your Password",
        recipients=[user_email],
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    msg.html = render_template_string("""
        <p>Dear {{ fullname }},</p>
        <p>Welcome to the Incident Reporting System!</p>
        <p>Your account has been created with username <strong>{{ username }}</strong>.</p> 
        <p>Please click on the link below to set your initial password:</p>
        <p><a href="{{ reset_link }}">{{ reset_link }}</a></p>
        <p>This link is valid for 1 hour.</p>
        <p>If you have any questions, please contact your administrator.</p>
        <p>Thank you,</p>
        <p>The Incident Reporting Team</p>
    """, fullname=fullname, reset_link=reset_link,username=username)
    
    try:
        mail.send(msg)
        app.logger.info(f"Welcome and password setup email sent to new user: {user_email}")
        return True
    except Exception as e:
        app.logger.error(f"Failed to send welcome email to {user_email}: {e}")
        return False
    
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"msg": "Missing username or password"}), 400

    username_input = data.get('username') # Rename to avoid shadowing
    password_input = data.get('password')

    conn = get_db_connection()
    if conn is None:
        return jsonify({'msg': 'Database connection failed'}), 500

    try:
        cur = conn.cursor()
        # Ensure you select all fields you want to return, including fullname, email, username, id
        # The order here must match the order in the unpacking below
        cur.execute("SELECT id, username, password_hash, password_reset_required, role, email, fullname FROM users WHERE username = %s", (username_input,))
        user = cur.fetchone() # This will be a tuple like (id, username, password_hash, ...)
        cur.close()

        if user and check_password_hash(user[2], password_input): # user[2] is password_hash
            # Unpack the fields from the 'user' tuple based on your SELECT query order
            user_id, username_db, password_hash, password_reset_required, role, email, fullname = user
            
            # Create access token using username from DB
            access_token = create_access_token(identity=username_db, additional_claims={"role": role})
            
            # Construct the response data dictionary including the new fields
            response_data = {
                "access_token": access_token,
                "role": role,
                "user_id": user_id,       # <-- Add user_id
                "username": username_db,   # <-- Add username
                "email": email,            # <-- Add email
                "fullname": fullname       # <-- Add fullname
            }
            
            # Conditionally add password_reset_required
            if password_reset_required:
                response_data["new-user-temp-password"] = True
            
            return jsonify(response_data), 200 # Explicitly return 200 OK
        else:
            return jsonify({"msg": "Bad username or password"}), 401
    except Exception as e:
        app.logger.error(f"Error during login: {e}", exc_info=True)
        return jsonify({'msg': 'Error during login'}), 500
    finally:
        if conn:
            conn.close()

@app.route('/createuser', methods=['POST'])
@role_required(['admin'])
def create_user():
    data = request.get_json()
    if not data or 'username' not in data or 'email' not in data or 'fullname' not in data:
        return jsonify({"msg": "Missing username, email, or fullname"}), 400

    username = data.get('username')
    email = data.get('email')
    fullname = data.get('fullname')
    role = data.get('role', 'reporter')
    if role not in ['reporter', 'editor', 'admin']:
        return jsonify({"msg": "Invalid role specified"}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({'msg': 'Database connection failed'}), 500

    try:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE username = %s OR email = %s", (username, email))
        existing_user = cur.fetchone()
        if existing_user:
            cur.close()
            return jsonify({"msg": "Username or email already exists"}), 409

        generated_password = generate_random_password()
        password_hash = generate_password_hash(generated_password)
        sql = "INSERT INTO users (username, email, password_hash, fullname, password_reset_required, role, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id"
        values = (username, email, password_hash, fullname, True, role, datetime.datetime.now()) # added created_at
        
        cur.execute(sql, values)
        new_user_id = cur.fetchone()[0]
        conn.commit()
        cur.close()

        # MODIFIED: Use the new Flask-Mail based sending
        # Also need to get fullname from the input data, as it's not in DB yet for new user.
        send_welcome_email_to_new_user(email, new_user_id, s.dumps(email, salt=JWT_SALT), fullname,username)

        return jsonify({"msg": f"User created successfully. A temporary password has been sent to {email}.", "user_id": new_user_id}), 201
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error during user creation: {e}", exc_info=True)
        return jsonify({'msg': 'Error creating user'}), 500
    finally:
        if conn:
            conn.close()

@app.route('/change_password', methods=['POST'])
@jwt_required()
def change_password():
    current_user = get_jwt_identity()
    data = request.get_json()
    if not data or 'old_password' not in data or 'new_password' not in data or 'confirm_password' not in data: # Added old_password check
        return jsonify({"msg": "Missing old_password, new_password, or confirm_password"}), 400 # Updated error message

    old_password = data.get('old_password') # Added old_password
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')

    if new_password != confirm_password:
        return jsonify({"msg": "New password and confirm password do not match"}), 400

    if len(new_password) < 6:
        return jsonify({"msg": "New password must be at least 6 characters long"}), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({'msg': 'Database connection failed'}), 500

    try:
        cur = conn.cursor()
        # Fetch current password hash to verify old password
        cur.execute("SELECT password_hash FROM users WHERE username = %s", (current_user,))
        user_data = cur.fetchone()
        if not user_data or not check_password_hash(user_data[0], old_password):
            return jsonify({"msg": "Invalid old password"}), 401 # Return 401 if old password doesn't match

        new_password_hash = generate_password_hash(new_password)
        cur.execute("UPDATE users SET password_hash = %s, password_reset_required = %s WHERE username = %s",
                    (new_password_hash, False, current_user))
        conn.commit()
        cur.close()
        return jsonify({"msg": "Password updated successfully"}), 200
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error during password change: {e}", exc_info=True)
        return jsonify({'msg': 'Error updating password'}), 500
    finally:
        if conn:
            conn.close()

@app.route('/profile', methods=['GET'])
@jwt_required()
def get_profile():
    current_user = get_jwt_identity()
    conn = get_db_connection()
    if conn is None:
        return jsonify({'error': 'Database connection failed'}), 500
    try:
        cur = conn.cursor()
        # Include password_reset_required in the select statement
        cur.execute("SELECT id, username, email, fullname, role, created_at, password_reset_required FROM users WHERE username = %s", (current_user,))
        user_tuple = cur.fetchone()
        cur.close()
        if user_tuple:
            return jsonify(serialize_user(user_tuple)) # Use the updated serialize_user
        else:
            return jsonify({'error': 'User not found'}), 404
    except Exception as e:
        app.logger.error(f"Error fetching profile: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/incidents', methods=['GET'])
@role_required(['reporter', 'editor', 'admin'])
def get_incidents():
    claims = get_jwt()
    current_user_username = get_jwt_identity()
    user_role = claims.get('role')
    app.logger.info(f"User {current_user_username} ({user_role}) accessed /incidents")

    status_filter = request.args.get('status', '').strip().lower()
    reporter_filter = request.args.get('reporter', '').strip()

    sort_by = request.args.get('sort_by', 'id').strip().lower()
    order = request.args.get('order', '').strip().lower()

    allowed_sort_columns = {
        'id': 'id',
        'reported_by': 'reported_by',
        'status': 'incident_status',
        'created_at': 'created_at' # Added for sorting by created_at
    }

    if sort_by not in allowed_sort_columns:
        sort_by_column = 'id'
    else:
        sort_by_column = allowed_sort_columns[sort_by]

    if order not in ['asc', 'desc']:
        if sort_by_column == 'id':
            sort_order = 'DESC'
        else:
            sort_order = 'ASC'
    else:
        sort_order = order.upper()

    conn = get_db_connection()
    if conn is None:
        app.logger.error("Database connection failed in get_incidents.")
        return jsonify({'error': 'Database connection failed'}), 500

    try:
        cur = conn.cursor()

        sql_query = """
            SELECT id, reported_by, email_address, date_detected, incident_type, other,
                    description, others_involved, risk_level, root_cause, proposed_mitigation,
                    resolution_date, created_at, incident_status
            FROM incidents
        """
        where_clauses = []
        query_params = []

        # Role-based filtering: Reporter sees only their own incidents - COMMENTED OUT FOR NOW TO SHOW ALL
        #if user_role == 'reporter':
           # cur.execute("SELECT fullname FROM users WHERE username = %s", (current_user_username,))
            #reporter_fullname = cur.fetchone()
            #if reporter_fullname:
                #where_clauses.append("reported_by = %s")
                #query_params.append(reporter_fullname[0])
            #else:
                #return jsonify({"msg": "Reporter's fullname not found"}), 404


        if status_filter and status_filter != 'all':
            where_clauses.append("incident_status ILIKE %s")
            query_params.append(status_filter)

        if reporter_filter:
            where_clauses.append("reported_by ILIKE %s")
            query_params.append(f"%{reporter_filter}%")

        if where_clauses:
            sql_query += " WHERE " + " AND ".join(where_clauses)

        sql_query += f" ORDER BY {sort_by_column} {sort_order}"

        app.logger.info(f"Executing SQL: {sql_query} with params: {query_params}")

        cur.execute(sql_query, tuple(query_params))
        incidents = cur.fetchall()
        cur.close()
        serialized_incidents = [serialize_incident(incident) for incident in incidents]
        return jsonify(serialized_incidents)
    except Exception as e:
        app.logger.error(f"Error fetching incidents: {e}", exc_info=True)
        return jsonify({'error': 'An internal server error occurred while fetching incidents.'}), 500
    finally:
        if conn:
            conn.close()


@app.route('/incidents/<int:incident_id>', methods=['GET'])
@role_required(['reporter', 'editor', 'admin'])
def get_incident(incident_id):
    claims = get_jwt()
    current_user_username = get_jwt_identity()
    user_role = claims.get('role')
    app.logger.info(f"User {current_user_username} ({user_role}) accessed /incidents/{incident_id}")

    conn = get_db_connection()
    if conn is None:
        return jsonify({'error': 'Database connection failed'}), 500
    try:
        cur = conn.cursor()

        sql_query = """
            SELECT id, reported_by, email_address, date_detected, incident_type, other,
                    description, others_involved, risk_level, root_cause, proposed_mitigation,
                    resolution_date, created_at, incident_status
            FROM incidents WHERE id = %s
        """
        query_params = [incident_id]

        cur.execute(sql_query, tuple(query_params))
        incident = cur.fetchone()
        cur.close()
        if incident:
            # Apply reporter-specific visibility - COMMENTED OUT FR NOW
            #if user_role == 'reporter':
                #cur.execute("SELECT fullname FROM users WHERE username = %s", (current_user_username,))
                #reporter_fullname_db = cur.fetchone()
                #if reporter_fullname_db and incident[1] != reporter_fullname_db[0]: # incident[1] is reported_by
                    #return jsonify({"msg": "Unauthorized: You can only view incidents you reported"}), 403
            return jsonify(serialize_incident(incident))
        else:
            return jsonify({'error': 'Incident not found'}), 404
    except Exception as e:
        app.logger.error(f"Error getting incident {incident_id}: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/incidents/<int:incident_id>', methods=['PUT'])
@role_required(['editor', 'admin'])
def update_incident(incident_id):
    current_user = get_jwt_identity()
    app.logger.info(f"User {current_user} is updating incident {incident_id}")
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON data'}), 400

    conn = get_db_connection()
    if conn is None:
        app.logger.error("Database connection failed in update_incident.")
        return jsonify({'error': 'Database connection failed'}), 500

    try:
        cur = conn.cursor()

        current_incident_status = None
        reporter_email_for_notification = None
        incident_type_for_notification = None
        cur.execute("SELECT incident_status, email_address, incident_type FROM incidents WHERE id = %s", (incident_id,))
        incident_info = cur.fetchone()
        if incident_info:
            current_incident_status, reporter_email_for_notification, incident_type_for_notification = incident_info
        else:
            return jsonify({"msg": "Incident not found"}), 404

        new_incident_status = data.get('incident_status')

        sql = """
            UPDATE incidents
            SET risk_level = %s,
                root_cause = %s,
                proposed_mitigation = %s,
                resolution_date = %s,
                incident_status = %s
            WHERE id = %s
        """
        resolution_date_db = parse_date_yyyymmdd(data.get('resolution_date'))

        values = (
            data.get('risk_level'),
            data.get('root_cause'),
            data.get('proposed_mitigation'),
            resolution_date_db,
            new_incident_status,
            incident_id
        )
        cur.execute(sql, values)
        conn.commit()

        if cur.rowcount == 0:
            return jsonify({"msg": "Incident not found or no changes made"}), 404

        if current_incident_status != 'closed' and new_incident_status == 'closed' and reporter_email_for_notification:
            app.logger.info(f"Incident {incident_id} status changed to 'closed'. Notifying reporter: {reporter_email_for_notification}")
            resolution_date_str = resolution_date_db.strftime('%d/%m/%Y') if resolution_date_db else 'N/A'
            notify_incident_closed(incident_id, reporter_email_for_notification, incident_type_for_notification, resolution_date_str)

        cur.close()
        return jsonify({'msg': f'Incident {incident_id} updated successfully'}), 200

    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error updating incident {incident_id}: {e}", exc_info=True)
        return jsonify({'error': 'An internal server error occurred while updating the incident.'}), 500
    finally:
        if conn:
            conn.close()

@app.route('/incidents', methods=['POST'])
@role_required(['reporter', 'editor', 'admin'])
def create_incident():
    current_user_username = get_jwt_identity() # Changed to current_user_username for clarity
    app.logger.info(f"User {current_user_username} is creating an incident")
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON data'}), 400
    
    # Fetch current user's fullname and email from DB
    conn_user = get_db_connection()
    if conn_user is None:
        return jsonify({'error': 'Database connection failed for user lookup'}), 500
    try:
        cur_user = conn_user.cursor()
        cur_user.execute("SELECT fullname, email FROM users WHERE username = %s", (current_user_username,))
        user_info = cur_user.fetchone()
        cur_user.close()
        if not user_info:
            return jsonify({'error': 'Reporting user details not found'}), 404
        reported_by_name = user_info[0]
        reporter_email_address = user_info[1]
    finally:
        if conn_user:
            conn_user.close()

    # Use reported_by_name and reporter_email_address from the current user
    required_fields = ['date_detected', 'incident_type', 'description', 'risk_level'] # Removed reported_by, email_address as they're now automatic
    if not all(field in data for field in required_fields):
        return jsonify({'error': f"Missing required fields: {', '.join(required_fields)}"}), 400

    conn = get_db_connection()
    if conn is None:
        app.logger.error("Database connection failed in create_incident.")
        return jsonify({'error': 'Database connection failed'}), 500
    try:
        cur = conn.cursor()
        sql = """
            INSERT INTO incidents (reported_by, email_address, date_detected, incident_type, other, description, others_involved, risk_level, root_cause, proposed_mitigation, resolution_date, incident_status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id;
        """
        date_detected_db = parse_date_yyyymmdd(data.get('date_detected'))
        resolution_date_db = parse_date_yyyymmdd(data.get('resolution_date'))

        incident_type = data.get('incident_type')
        description = data.get('description')
        incident_status = data.get('incident_status') or 'new'

        values = (
            reported_by_name,         # From logged-in user
            reporter_email_address,   # From logged-in user
            date_detected_db,
            incident_type,
            data.get('other'),
            description,
            data.get('others_involved'),
            data.get('risk_level'),
            data.get('root_cause'),
            data.get('proposed_mitigation'),
            resolution_date_db,
            incident_status
        )
        cur.execute(sql, values)
        incident_id = cur.fetchone()[0]
        conn.commit()

        # --- MODIFIED: Fetching only Admin emails for New Incident Notification ---
        admin_emails = []
        cur.execute("SELECT email FROM users WHERE role = 'admin'") # Filter for 'admin' role only
        emails = cur.fetchall()
        for email_tuple in emails:
            if email_tuple and email_tuple[0]:
                admin_emails.append(email_tuple[0])

        if admin_emails:
            app.logger.info(f"New incident #{incident_id} created. Notifying admins: {admin_emails}")
            notify_new_incident(incident_id, reported_by_name, description, incident_type, admin_emails)
        else:
            app.logger.warning("No admin emails found to notify about new incident.")

        cur.close()
        return jsonify({'id': incident_id}), 201
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Error creating incident: {e}", exc_info=True)
        return jsonify({'error': 'An internal server error occurred while creating the incident.'}), 500
    finally:
        if conn:
            conn.close()


@app.route('/users', methods=['GET'])
@jwt_required()
def get_users():
    current_user_id = get_jwt_identity()
    claims = get_jwt()
    user_role = claims.get('role')

    if user_role != 'admin':
        app.logger.warning(f"User {current_user_id} attempted to access /users without admin role.")
        return jsonify({"msg": "Forbidden: Only administrators can view users"}), 403

    conn = get_db_connection()
    if conn is None:
        app.logger.error("Database connection failed in get_users.")
        return jsonify({'error': 'Database connection failed'}), 500

    try:
        cur = conn.cursor()
        # Include password_reset_required in the select statement
        cur.execute("SELECT id, username, email, fullname, role, created_at, password_reset_required FROM users ORDER by fullname")
        users = cur.fetchall()
        cur.close()

        serialized_users = [serialize_user(user) for user in users]
        serialized_users = [user for user in serialized_users if user is not None]

        return jsonify(serialized_users)

    except Exception as e:
        app.logger.error(f"Error fetching users: {e}", exc_info=True)
        return jsonify({'error': 'An internal server error occurred while fetching users.'}), 500
    finally:
        if conn:
            conn.close()


@app.route('/users/<int:user_id>', methods=['PUT'])
@jwt_required()
def update_user(user_id):
    current_user_identity = get_jwt_identity()
    claims = get_jwt()
    updater_role = claims.get('role')

    if updater_role != 'admin':
        app.logger.warning(f"User {current_user_identity} (Role: {updater_role}) attempted to update user {user_id} without admin role.")
        return jsonify({"msg": "Forbidden: Only administrators can update user information"}), 403

    data = request.get_json()
    if not data:
        return jsonify({"msg": "No input data provided"}), 400

    fullname = data.get('fullname')
    email = data.get('email')
    role = data.get('role')

    errors = {}
    if fullname is not None and not isinstance(fullname, str):
        errors['fullname'] = 'Full name must be a string.'
    elif fullname is not None and not (3 <= len(fullname) <= 100):
        errors['fullname'] = 'Full name must be between 3 and 100 characters.'

    if email is not None:
        if not isinstance(email, str) or not is_valid_email(email):
            errors['email'] = 'Invalid email format.'

    if role is not None:
        valid_roles = ['reporter', 'editor', 'admin'] # Corrected valid roles based on your code
        if not isinstance(role, str) or role.lower() not in valid_roles:
            errors['role'] = f'Invalid role. Must be one of: {", ".join(valid_roles)}'
        else:
            role = role.lower()

    if errors:
        return jsonify({"msg": "Validation failed", "errors": errors}), 400

    conn = get_db_connection()
    if conn is None:
        app.logger.error("Database connection failed in update_user.")
        return jsonify({'error': 'Database connection failed'}), 500

    try:
        cur = conn.cursor()

        set_clauses = []
        params = []
        if fullname is not None:
            set_clauses.append("fullname = %s")
            params.append(fullname)
        if email is not None:
            cur.execute("SELECT id FROM users WHERE email = %s AND id != %s", (email, user_id))
            if cur.fetchone():
                return jsonify({"msg": "Validation failed", "errors": {"email": "Email address already in use."}}), 400
            set_clauses.append("email = %s")
            params.append(email)
        if role is not None:
            set_clauses.append("role = %s")
            params.append(role)

        if not set_clauses:
            return jsonify({"msg": "No fields provided for update"}), 400

        sql_query = f"UPDATE users SET {', '.join(set_clauses)} WHERE id = %s"
        params.append(user_id)

        cur.execute(sql_query, tuple(params))
        conn.commit()

        if cur.rowcount == 0:
            return jsonify({"msg": "User not found or no changes made"}), 404

        # Fetch the updated user to return its details
        cur.execute("SELECT id, username, email, fullname, role, created_at, password_reset_required FROM users WHERE id = %s", (user_id,))
        updated_user = cur.fetchone()
        cur.close()

        if updated_user:
            return jsonify({"msg": "User updated successfully", "user": serialize_user(updated_user)}), 200
        else:
            return jsonify({"msg": "User updated, but failed to retrieve updated data."}), 200

    except Exception as e:
        app.logger.error(f"Error updating user {user_id}: {e}", exc_info=True)
        return jsonify({'error': 'An internal server error occurred while updating the user.'}), 500
    finally:
        if conn:
            conn.close()

# NEW: Endpoint to request a password reset link
@app.route('/request_password_reset', methods=['POST'])
def request_password_reset():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify(msg="Email is required"), 400

    conn = get_db_connection()
    if conn is None:
        return jsonify({'msg': 'Database connection failed'}), 500
    
    try:
        cur = conn.cursor()
        cur.execute("SELECT username, email, fullname,id FROM users WHERE email = %s", (email,))
        user_data = cur.fetchone() # user_data will be (username, email, fullname)
        cur.close()

        if user_data:
            user_email = user_data[1]
            fullname = user_data[2]
            user_id = user_data[3]

            # Generate a unique, time-limited token using the user's email
            token = s.dumps(user_email, salt=JWT_SALT)
            #send_password_reset_email_via_flask_mail(user_email, user_id, reset_token, fullname):
            if send_password_reset_email_via_flask_mail(user_email, user_id,token, fullname):
                # Always return a generic success message to prevent user enumeration
                return jsonify(msg="If an account with that email exists, a password reset link has been sent."), 200
            else:
                return jsonify(msg="Failed to send password reset email. Please try again later."), 500
        else:
            # Always return a generic success message to prevent user enumeration
            return jsonify(msg="If an account with that email exists, a password reset link has been sent."), 200
    except Exception as e:
        app.logger.error(f"Error requesting password reset for {email}: {e}", exc_info=True)
        return jsonify({'msg': 'Error during password reset request'}), 500
    finally:
        if conn:
            conn.close()

# NEW: Endpoint to reset the password using the token
@app.route('/reset-password', methods=['POST'])
def reset_password_confirm():
    data = request.get_json()

    # Backend is explicitly looking for these:
    token = data.get('token')
    new_password = data.get('new_password')
    # If your backend expects confirm_password for its own validation:
    # confirm_password = data.get('confirm_password')

    # If your backend expects user_id from the payload:
    user_id = data.get('user_id') # <--- IMPORTANT: Check if your backend expects this from the BODY or from the TOKEN

    if not token or not new_password: # Removed confirm_password here as it's usually frontend-validated
        return jsonify({"msg": "Token and new password are required"}), 400

    # If your backend requires user_id in the payload, add it here:
    if not user_id:
        return jsonify({"msg": "User ID is required"}), 400

    try:
        # Load the user_id (or email) from the token payload
        # This assumes the token itself contains the user's ID/email as its payload
        token_payload = s.loads(token, salt=JWT_SALT, max_age=3600) # 1 hour expiry
        # If your token only contains the user_id, you can use:
        # user_id_from_token = token_payload
        # If your token contains the email, and you map it to user_id:
        email_from_token = token_payload
        
        conn = get_db_connection()
        cursor = conn.cursor()

        # Retrieve user from DB based on email (or user_id if token contains ID)
        cursor.execute("SELECT id FROM users WHERE email = %s", (email_from_token,))
        user = cursor.fetchone()
        conn.close()

        if not user:
            return jsonify({"msg": "User not found or token invalid."}), 404

        # Important: Verify that the user_id from the URL/payload matches the user identified by the token
        # If your token payload is just the user ID string, use:
        # if str(user[0]) != str(token_payload):
        #    return jsonify({"msg": "Token does not match user ID."}), 400
        # If your token payload is email, and you're sending user_id in the payload, then:
        if str(user[0]) != str(user_id): # Comparing DB user ID with payload user_id
            return jsonify({"msg": "Mismatch between user ID and token."}), 400

        # Update password
        hashed_password = generate_password_hash(new_password)
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET password_hash = %s, password_reset_required = FALSE WHERE id = %s", (hashed_password, user[0]))
        conn.commit()
        conn.close()

        return jsonify({"msg": "Password has been reset successfully!"}), 200

    except SignatureExpired:
        return jsonify({"msg": "Password reset link has expired."}), 400
    except BadTimeSignature:
        return jsonify({"msg": "Invalid password reset token."}), 400
    except Exception as e:
        app.logger.error(f"Error resetting password: {e}", exc_info=True)
        return jsonify({"msg": "An error occurred during password reset."}), 500


@app.route('/api/users_for_filter', methods=['GET'])
@jwt_required() # Protect this endpoint if user list is sensitive
def get_users_for_filter():
    conn = get_db_connection()
    if conn is None:
        return jsonify({'msg': 'Database connection failed'}), 500

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor) # Use RealDictCursor to get dicts
        # Fetch all users, or filter by role if you only want 'reporter' users
        # For a filter dropdown, typically you'd fetch all users who can be reporters.
        # If your 'users' table has a 'role' column:
        cur.execute("SELECT username, fullname FROM users ORDER BY fullname ASC")
        # OR, if you want all users regardless of role (and let frontend differentiate):
        # cur.execute("SELECT username, fullname FROM users ORDER BY fullname ASC")

        users = cur.fetchall()
        cur.close()
        return jsonify(users), 200
    except Exception as e:
        app.logger.error(f"Error fetching users for filter: {e}", exc_info=True)
        return jsonify({'msg': 'Error fetching users for filter'}), 500
    finally:
        if conn:
            conn.close()


@app.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required() # Protect this endpoint
def delete_user(user_id):
    conn = get_db_connection()
    if conn is None:
        app.logger.error("Database connection failed for user deletion.")
        return jsonify({'msg': 'Database connection failed'}), 500

    try:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        current_username = get_jwt_identity() # Get the username of the authenticated user

        # 1. Get the role of the authenticated user (requester)
        cur.execute("SELECT id, username, role FROM users WHERE username = %s", (current_username,))
        requester_info = cur.fetchone()

        if not requester_info:
            cur.close()
            # This indicates an issue with the JWT or user database, should ideally not happen
            return jsonify({'msg': 'Authenticated user not found or invalid token'}), 401

        requester_id = requester_info['id']
        requester_role = requester_info['role']

        #Current User can't delete their own user
        if requester_id == user_id:
            cur.close()
            app.logger.warning(...)
            return jsonify({'msg': 'You cannot delete your own active account.'}), 403

        # 2. Get information about the user to be deleted
        cur.execute("SELECT id, username, role FROM users WHERE id = %s", (user_id,))
        user_to_delete_info = cur.fetchone()

        if not user_to_delete_info:
            cur.close()
            return jsonify({'msg': f"User with ID '{user_id}' not found"}), 404

        # 3. Authorization Check
        # Rule: Only 'admin' users can delete other users.
        # Rule: A user can delete their own account.
        if requester_role != 'admin' and requester_id != user_to_delete_info['id']:
            cur.close()
            app.logger.warning(
                f"Unauthorized attempt to delete user ID '{user_id}' by '{current_username}' (role: {requester_role})"
            )
            return jsonify({'msg': 'Forbidden: You do not have permission to delete this user'}), 403

        # Optional: Prevent an admin from deleting themselves if they are the only admin
        # This requires an additional query to count active admins.
        # For simplicity, we'll allow self-deletion for now.
        if requester_role == 'admin' and requester_id == user_to_delete_info['id']:
            # Example of a check you might add:
            # cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin' AND is_active = TRUE;")
            # if cur.fetchone()['count'] == 1:
            #     return jsonify({'msg': 'Cannot delete the last admin account'}), 403
            pass

        # 4. Perform Hard Deletion
        # DANGER: This permanently removes the user. Ensure no foreign key constraints are violated
        # or handle cascading deletes/nullification if other tables depend on 'users.id'.
        sql_delete_user = """
        DELETE FROM users WHERE id = %s;
        """
        cur.execute(sql_delete_user, (user_id,))

        if cur.rowcount == 0:
            # This case means the user wasn't deleted, possibly due to a race condition
            # or a very quick non-existent check after the initial fetch.
            conn.rollback()
            cur.close()
            return jsonify({'msg': f"User with ID '{user_id}' could not be deleted."}), 404

        conn.commit() # Commit the transaction
        cur.close()

        app.logger.info(f"User ID '{user_id}' hard-deleted by '{current_username}'.")
        return jsonify({'msg': f"User with ID '{user_id}' has been deleted successfuly."}), 200

    except Exception as e:
        if conn:
            conn.rollback() # Rollback in case of any error during the transaction
        app.logger.error(f"Error deleting user ID '{user_id}': {e}", exc_info=True)
        return jsonify({'msg': 'Error processing user deletion'}), 500
    finally:
        if conn:
            conn.close()


application = app
if __name__ == '__main__':
    app.run(debug=True)