# notifications.py

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

# Configuration for your email sender
SMTP_SERVER = os.getenv('SMTP_SERVER', 'smtp.example.com') # e.g., 'smtp.gmail.com'
SMTP_PORT = int(os.getenv('SMTP_PORT', 587)) # e.g., 587 for TLS, 465 for SSL
SMTP_USERNAME = os.getenv('SMTP_USERNAME', 'your_email@example.com') # Your sending email
SMTP_PASSWORD = os.getenv('SMTP_SENDER_PASSWORD', 'your_email_password') # Your email password
SENDER_EMAIL = os.getenv('SMTP_SENDER_EMAIL', 'your_email@example.com')
APP_NAME = os.getenv('APP_NAME', 'Incident Reporting System') # Name of your application


def send_email(to_email, subject, body_html):
    """Sends an email using the configured SMTP server."""
    try:
        msg = MIMEMultipart('alternative')
        msg['From'] = SENDER_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject

        # Attach the HTML body
        msg.attach(MIMEText(body_html, 'html'))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()  # Upgrade connection to secure TLS
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SENDER_EMAIL, to_email, msg.as_string())
        print(f"Email sent successfully to {to_email} with subject: {subject}")
        return True
    except Exception as e:
        print(f"Failed to send email to {to_email}: {e}")
        return False

# --- NEW FUNCTION 1: Notify Admins/Editors about a New Incident ---
def notify_new_incident(incident_id, reported_by, description, incident_type, recipient_emails):
    """
    Sends an email notification about a new incident to specified recipients.
    """
    subject = f"New Incident #{incident_id} Reported - {incident_type}"
    body_html = f"""
    <html>
    <body>
        <p>Hello,</p>
        <p>A new incident has been reported in the {APP_NAME}.</p>
        <ul>
            <li><strong>Incident ID:</strong> {incident_id}</li>
            <li><strong>Reported By:</strong> {reported_by}</li>
            <li><strong>Incident Type:</strong> {incident_type}</li>
            <li><strong>Description:</strong> {description}</li>
        </ul>
        <p>Please review the incident details in the system.</p>
        <p>Thank you,</p>
        <p>The {APP_NAME} Team</p>
    </body>
    </html>
    """
    for email in recipient_emails:
        send_email(email, subject, body_html)
    print(f"New incident #{incident_id} notification sent to: {', '.join(recipient_emails)}")


# --- NEW FUNCTION 2: Notify Reporter when Incident is Closed ---
def notify_incident_closed(incident_id, reported_by_email, incident_type, resolution_date):
    """
    Sends an email notification to the original reporter when their incident is closed.
    """
    subject = f"Incident #{incident_id} - {incident_type} has been Closed"
    body_html = f"""
    <html>
    <body>
        <p>Hello,</p>
        <p>This is to inform you that the incident you reported has now been marked as 'Closed'.</p>
        <ul>
            <li><strong>Incident ID:</strong> {incident_id}</li>
            <li><strong>Incident Type:</strong> {incident_type}</li>
            <li><strong>Resolution Date:</strong> {resolution_date}</li>
        </ul>
        <p>Thank you for using the {APP_NAME}.</p>
        <p>Sincerely,</p>
        <p>The {APP_NAME} Team</p>
    </body>
    </html>
    """
    return send_email(reported_by_email, subject, body_html)