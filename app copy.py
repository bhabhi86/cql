from flask import Flask, jsonify, request
from db.database import get_db_connection
import datetime
from flask_jwt_extended import create_access_token, jwt_required, JWTManager, get_jwt_identity, get_jwt
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import timedelta
from flask_cors import CORS
import secrets
import string
import re
from notifications import send_password_reset_email, notify_new_incident, notify_incident_closed
from functools import wraps
import logging

app = Flask(__name__)
CORS(app)

# Setup Flask-JWT-Extended
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this in your actual app!
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=120)
jwt = JWTManager(app)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

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
    Assumes the tuple order is: (id, username, email, fullname, role, created_at)
    """
    if not user_tuple or len(user_tuple) < 6:
        app.logger.warning(f"Incomplete user tuple for serialization: {user_tuple}")
        return None

    user_id, username, email, fullname, role, created_at = user_tuple
    created_at_str = created_at.strftime('%Y-%m-%d %H:%M:%S') if created_at else 'N/A'

    return {
        'id': user_id,
        'username': username,
        'email': email,
        'fullname': fullname,
        'role': role,
        'created_at': created_at_str
    }

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"msg": "Missing username or password"}), 400

    username = data.get('username')
    password = data.get('password')

    conn = get_db_connection()
    if conn is None:
        return jsonify({'msg': 'Database connection failed'}), 500

    try:
        cur = conn.cursor()
        cur.execute("SELECT id, username, password_hash, password_reset_required, role FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()

        if user and check_password_hash(user[2], password):
            user_id, username, password_hash, password_reset_required, role = user
            access_token = create_access_token(identity=username, additional_claims={"role": role})
            response_data = {"access_token": access_token, "role": role}
            if password_reset_required:
                response_data["password_reset_required"] = True
            return jsonify(response_data)
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
        sql = "INSERT INTO users (username, email, password_hash, fullname, password_reset_required, role) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id"
        values = (username, email, password_hash, fullname, True, role)

        cur.execute(sql, values)
        new_user_id = cur.fetchone()[0]
        conn.commit()
        cur.close()

        send_password_reset_email(email, generated_password)

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
    if not data or 'new_password' not in data or 'confirm_password' not in data:
        return jsonify({"msg": "Missing new_password or confirm_password"}), 400

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
        cur.execute("SELECT id, username, email, fullname, role FROM users WHERE username = %s", (current_user,))
        user = cur.fetchone()
        cur.close()
        if user:
            return jsonify({'id': user[0], 'username': user[1], 'email': user[2], 'fullname': user[3], 'role': user[4]})
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
        'status': 'incident_status'
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
    current_user = get_jwt_identity()
    app.logger.info(f"User {current_user} is creating an incident")
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON data'}), 400
    required_fields = ['reported_by', 'email_address', 'description']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

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

        reported_by_name = data.get('reported_by')
        incident_type = data.get('incident_type')
        description = data.get('description')
        incident_status = data.get('incident_status') or 'new'

        values = (
            reported_by_name,
            data.get('email_address'),
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
        cur.execute("SELECT id, username, email, fullname, role,created_at FROM users")
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
        valid_roles = ['user', 'editor', 'admin']
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

        cur.execute("SELECT id, username, email, fullname, role, created_at FROM users WHERE id = %s", (user_id,))
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

if __name__ == '__main__':
    app.run(debug=True, port=5002)