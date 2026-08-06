"""
This module provides basic functions and methods meant to be used by other
modules.

Functions:
mail_send - sends email via SMTP.
"""
from socket import gethostbyname, gaierror
from smtplib import SMTP, SMTPConnectError
from email.mime.text import MIMEText


def mail_send(mail_info):
    """Takes input, sends mail.

    Keyword arguments:
    mail_info - A dict() object with the following keys and
    corresponding values: sender, recipients, subject, server and
    body.

    Outputs:
    Sends an email, returns nothing.

    Raises:
    gaierror - Occurs when DNS resolution of a hostname fails.
    SMTPConnectError - Occurs when the remote SMTP sever refuses the
    connection."""
    # Defining mail properties.
    msg = MIMEText(mail_info['body'])
    msg['Subject'] = mail_info['subject']
    msg['From'] = mail_info['sender']
    msg['To'] = mail_info['recipients']
    # Obtaining IP address of SMTP server host name.  If using an IP
    # address, omit the gethostbyname function.
    try:
        s = SMTP(gethostbyname(mail_info['server']), '25')
    except gaierror:
        print('Hostname resolution of %s failed.', mail_info['server'])
        exit(1)
    except SMTPConnectError:
        print('Unable to connect to %s, the server refused the ' +
              'connection.', mail_info['server'])
        exit(1)
    # Sending the mail.
    s.sendmail(mail_info['sender'], mail_info['recipients'], msg.as_string())
