import psutil
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
# Email configuration
SMTP_SERVER = "your_smtp_server.com"
SMTP_PORT = 587
SMTP_USERNAME = "your_username"
SMTP_PASSWORD = "your_password"
SENDER_EMAIL = "your_email@example.com"
RECIPIENT_EMAIL = "recipient@example.com"

# Access environment variables
SMTP_SERVER = os.environ.get("SMTP_SERVER")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
SENDER_EMAIL = os.environ.get("SENDER_EMAIL")
RECIPIENT_EMAIL = os.environ.get("RECIPIENT_EMAIL")

# Monitoring and Alerting
def monitor_cpu_usage():
    while True:
        cpu_percent = psutil.cpu_percent(interval=1)
        # Add alerting logic here (e.g., send an email if CPU usage exceeds a threshold)
        if cpu_percent > 90:
            send_alert_email(f"High CPU Usage Alert: {cpu_percent}%")
            
def send_alert_email(message):
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        
        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = RECIPIENT_EMAIL
        msg["Subject"] = "Alert: High CPU Usage"
        
        msg.attach(MIMEText(message, "plain"))
        
        server.sendmail(SENDER_EMAIL, RECIPIENT_EMAIL, msg.as_string())
        server.quit()
        
        print("Alert email sent successfully!")

    except smtplib.SMTPException as e:
        print(f"Failed to send email: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")
        print("Additional information:")
        print("Ensure that the SMTP server address and port are correct.")
        print("Also, check your network connectivity and DNS resolution.")

# Start monitoring in a separate thread
import threading
monitor_thread = threading.Thread(target=monitor_cpu_usage)
monitor_thread.daemon = True
monitor_thread.start()