"""
This module provides basic functions and methods meant to be used by other
modules.

Functions:
mail_send - sends email via SMTP.
get_credentials - retrieves credentials from an encrypted password file.

Classes:
ValidateInput - performs input validation.
"""
from socket import gethostbyname, gaierror
from smtplib import SMTP, SMTPConnectError
from email.mime.text import MIMEText
from logging import getLogger
from re import match

from requests import post, HTTPError
from pyotp import TOTP


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


def get_credentials(scss_dict):
    """Makes an API call to SCSS, returns credentials.

    Keyword Arguments:
    scss_dict - a dict() object containing the following keys with
    the correct corresponding values: api_key, otp, userid and url.

    Output:
    data - str(), the data returned from scss."""
    log = getLogger(__name__)
    # Setting variables based on the data passed by the scss_dict.
    api_key = scss_dict['api_key']
    otp = TOTP(scss_dict['otp']).now()
    userid = scss_dict['userid']
    url = scss_dict['url']
    user_agent = 'scss-client'
    # Building HTTP headers.
    headers = {
        'User-Agent': user_agent,
        'api-key': api_key,
        'totp': otp,
        'userid': userid
    }
    # Connecting to SCSS.  If SSL verification fails, change verify to
    # false.  This isn't recommended (as it defeats the purpose of
    # verification), but it will make the code work in an emergency.
    scss_response = post(url, headers=headers, timeout=5)
    try:
        scss_response.raise_for_status
    except HTTPError:
        log.exception(
            'Unable to retrieve credentials from SCSS.  The HTTP error code '
            'is %s', scss_response.status_code
        )
        exit(1)
    data = scss_response.json().get('gpg_pass')
    log.debug('Credentials successfully retrieved from SCSS')
    return data


class ValidateInput:
    """Performs input validation."""
    def __init__(self):
        """Input validation class

        Methods:
        SHA1 - Input validation for a SHA1 hash.
        Email - Input validation for a email address.
        FileExt - Input validation for a file extension.
        Subject - Input validation for email subject line."""

    def email(self, email):
        """Input validation for an email address.

        Input:
        email - str(), The supplied email address to validate.

        Returns:
        Boolean - The method will return True if input validation
        passes or False if input validation fails."""
        email_pattern = (
            r'[a-zA-Z0-9_\.\-]{3,32}@[a-zA-Z0-9_\-]{3,64}\.\S{3,24}'
        )
        email_validate = match(email_pattern, email)
        if email_validate:
            return True
        else:
            return False

    def sha1(self, _hash):
        """Input validation for a SHA1 hash.

        Input:
        hash - str(), The supplied sha1 hash.

        Returns:
        Boolean - The method will return True if input validation
        passes or False if input validation fails."""
        hash_pattern = r'[a-zA-Z0-9]{40}'
        hash_validate = match(hash_pattern, _hash)
        if hash_validate:
            return True
        else:
            return False

    def file_ext(self, file_ext):
        """Input validation for a file extension.

        Input:
        file_ext - str(), The file extension.

        Returns:
        Boolean - The method will return True if input validation
        passes or False if input validation fails."""
        ext_pattern = r'[a-zA-Z0-9]{3,4}'
        ext_validate = match(ext_pattern, file_ext)
        if ext_validate:
            return True
        else:
            return False

    def subject(self, subject_line):
        """Input validation for an email subject line.
        Yes, it isn't a whole lot.

        Input:
        subject_line - str(), The email subject line to search for.

        Returns:
        Boolean - The method will return True if input validation
        passes or False if input validation fails."""
        subject_pattern = r'".{1,998}"'
        subject_validate = match(subject_pattern, subject_line)
        if subject_validate:
            return True
        else:
            return False
