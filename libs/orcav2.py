"""
This module provides classes and methods to search for phishing emails
based on known IOCs within Trend AI Vision One via their product APIs to
remove phishing emails from users' inboxes.

Classes:
OrcaV2 - API calls to Trend AI Vision One to find/remove phishing emails.
"""
from logging import getLogger
from configparser import ConfigParser
from time import sleep
import http.client as hc
import urllib.parse as uparse
import datetime as dt
import ssl
import sys
import json


class OrcaV2:
    """One off phishing search to be invoked via CLI.

    Class Variables:
    config - The config file used by all instances of this class.

    Methods:
    find_phish - Finds a phishing email based on supplied keyword
    arguments.
    pull_email - Quarantines a single phishing email from all
    mailboxes.
    """
    config = ConfigParser()
    config.read('orca.ini')

    def __init__(self):
        """One off phishing search to be invoked via CLI.

        Inputs:
        config - Orca.config.

        Instance variables:
        tm_api - str(), An API key used to authenticate to TrendMicro.
        api_counter - int(), A counter used to stay within the API
        rate limit.
        """
        self.tm_api = OrcaV2.config['api']['tm_api']
        self.api_counter = int()

    def find_phish(self, **phish_):
        """Searches for phishing emails based on supplied keyword
        arguments.

        Keyword Arguments:
        sender - str(), malicious email address.  Required if not
        searching by file_hash or url.
        subject - str(), Email subject line (optional)
        file_hash - str(), file_hash(optional)
        url - str(), actual URL in email (optional)

        Returns
        evil_list - list(), A list of dictionaries containing the
        following keys: mailbox, mmi, mui and d_time.

        Exceptions:
        HTTPError - Occurs when there is a non-200s response."""
        # Start logging.
        log = getLogger(__name__)
        # Initializing variables and constants.
        tm_host = 'api.xdr.trendmicro.com'
        tm_url = '/v3.0/search/emailActivities'
        headers = {'Authorization': 'Bearer ' + self.tm_api}
        params = uparse.urlencode({
                        'select': 'select=mailMsgId,duser',
                        'startDateTime': (dt.datetime.now() + dt.timedelta(-7)).isoformat(),
                        'endDateTime': dt.datetime.now().isoformat(),
                        'top': 500
        })
        evil_list = []
        # Search used when URL is supplied.
        if 'url' in phish_:
            log.debug('Performing URL search.')
            headers.update({
                'TMV1-Query': f'mailUrlsRealLink:{phish_['url']}'
                })
        # Search used when file_hash is supplied.
        elif 'file_hash' in phish_:
            log.debug('Performing SHA1 hash search.')
            headers.update({
                            'TMV1-Query': f'attachmentSha1:{phish_['file_hash']}'
                            })
        # Search used when subject and sender is supplied.
        elif 'subject' in phish_ and 'sender' in phish_:
            log.debug('Performing sender/subject search.')
            headers.update({
                'TMV1-Query': f'mailFromAddresses:{phish_['sender']} and mailMsgSubject:{phish_['subject']}'
            })
        # Search used when only the sender is supplied.
        elif 'sender' in phish_:
            log.debug('Performing sender search.')
            headers.update({
                'TMV1-Query': f'mailFromAddresses:{phish_['sender']}'
                })
        # Search used when only the subject is supplied.
        elif 'subject' in phish_:
            log.debug('Performing sender search.')
            headers.update({
                            'TMV1-Query': f'mailMsgSubject:{phish_['subject']}'
                            })
        ssl_context = ssl.create_default_context()
        max_tries = 2
        for attempt in range(max_tries):
            try:
                conn = hc.HTTPSConnection(
                    tm_host,
                    context=ssl_context,
                    timeout=10
                    )
            except TimeoutError:
                log.exception('Connection timed out.  Trying again.')
                if attempt <= max_tries:
                    sleep(3)
                else:
                    log.error('Max attempts reached.  Aborting.')
                    conn.close()
                    sys.exit(1)
            finally:
                conn.request('GET', tm_url, params, headers=headers)
                response = conn.getresponse()
                data = json.loads(response.read())
                print(data)
                for entry in data['items']:
                    print(entry.keys())
        evil_sender_data = data['items']
        for evil_data in evil_sender_data:
            if evil_data['msgUuid']:
                evil_list.append({
                    'muid': evil_data['msgUuid']
                })
            elif evil_data['mailMsgId']:
                evil_list.append({
                    'mmi': evil_data['mailMsgId']
                    })
            log.info(f'Email found in {evil_data['mailSmtpRecipients']}')
        conn.close()
        return evil_list

    def pull_email(self, evil_list):
        """Quarantines evil emails from O365.

        Input:
        evil_list - list(), A list of dict() that contain the following
        keys: mmi, rcpt.

        Output:
        None.

        Exceptions:
        HTTPError - Excpetion that occurs when a request returns a
        non-201 response."""
        # It's five o'clock somewhere.  Time for logging!
        log = getLogger(__name__)
        # Here is where you edit information needed for the API request.
        ssl_context = ssl.create_default_context()
        tm_host = 'api.xdr.trendmicro.com'
        tm_url = '/v3.0/response/emails/quarantine'
        headers = {
            'Authorization': 'Bearer ' + self.tm_api,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }
        # Iterate through the list of evil emails, making an API call
        # to quarantine the email in question.  If there is an error
        # containing the evil, log it and skip over that item.
        max_tries = 2
        json_array = []
        for attempt in range(max_tries):
            try:
                conn = hc.HTTPSConnection(
                    tm_host,
                    context=ssl_context,
                    timeout=10
                )
            except TimeoutError:
                log.exception('Connection timed out.  Trying again.')
                if attempt <= max_tries:
                    sleep(3)
                else:
                    log.error('Max attempts reached.  Aborting.')
                    conn.close()
                    sys.exit(1)
        while len(evil_list) != 0:
            evil = evil_list.pop(0)
            # All of these are required parameters.  Do not change.
            if evil['muid']:
                json_body = json.dumps([{
                    'description': 'Orca_Quarantine',
                    'uniqueId': evil['muid'],
                }])
                print(json_body)
            elif evil['mmi']:
                json_body = json.dumps([{
                    'description': 'Orca_Quarantine',
                    'messageId': evil['mmi'],
                }])
                print(json_body)
            log.debug('Added to quarantine call %s', json_body)
            # Making sure to keep the JSON array at or under 10 entries.
            try:
                conn.request('POST', tm_url, headers=headers, body=json_body)
                response = conn.getresponse()
                if response.status != 207:
                    raise hc.HTTPException
                return_data = response.read()
            except hc.HTTPException:
                log.exception(
                    f'{response.status} response when pulling phishing email.'
                )
                continue
        conn.close()
        return return_data
