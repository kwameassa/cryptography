import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Email server information
smtp_server = "ec2-16-171-225-190.eu-north-1.compute.amazonaws.com"
smtp_port = 25  # Use port 587 for TLS or 465 for SSL

# Sender and recipient email addresses
sender_email = "your-email@example.com"
recipient_email = "recipient-email@example.com"

# Email content
subject = "Test Email"
body = "This is a test email sent from Python."

# Create the MIME object
message = MIMEMultipart()
message["From"] = sender_email
message["To"] = recipient_email
message["Subject"] = subject

# Attach the body to the email
message.attach(MIMEText(body, "plain"))

# Connect to the SMTP server
try:
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        # Identify yourself to the SMTP server
        server.ehlo()

        # Start TLS (optional)
        # server.starttls()

        # Login to the SMTP server (if required)
        # server.login("your_username", "your_password")

        # Send the email
        server.sendmail(sender_email, recipient_email, message.as_string())

    print("Email sent successfully!")

except Exception as e:
    print(f"An error occurred: {e}")
