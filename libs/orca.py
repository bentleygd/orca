from csv import DictReader
from logging import getLogger
from tempfile import TemporaryFile
from configparser import ConfigParser
from ssl import PROTOCOL_TLSv1_2, CERT_NONE
from time import sleep

from requests import request, HTTPError
from ldap3 import Connection, Server, SUBTREE, Tls
from ldap3.core.exceptions import LDAPExceptionError

from libs.coreutils import get_credentials


class get_phish_tank_urls:
    """Gets phishing URLs from PhishTank.org.
    Please note that this is a descriptor designed specifically for
    the OrcaPod class"""

    def __get__(self, obj, objtype=None):
        """
        Inputs:
        None

        Outputs:
        phish_tank_list - The list of verified phishing URLs from
        PhishTank.

        Exceptions:
        HTTPError - Occurs when unable to retrieve the CSV of bad URLs
        from PhishTank.org."""
        # All the cool kids are logging.
        log = getLogger(__name__)
        # Getting the data from PhishTank.
        phish_tank_url = (
            'http://data.phishtank.com/data/' + obj.phish_tank_api +
            '/online-valid.csv'
        )
        phish_tank_data = request('GET', phish_tank_url)
        try:
            phish_tank_data.raise_for_status()
        except HTTPError:
            log.exception('Error retrieving phish tank list.')
        # Writing the data to a file so it behaves like a CSV
        # file.
        data_file = TemporaryFile()
        for data_entry in phish_tank_data.split('\n'):
            # Checking for blank entries.
            if len(data_entry) > 0:
                data_file.write(data_entry)
        # Getting the URLs from the file and writing them to a list.
        phish_tank_list = []
        reader = DictReader(data_file)
        for row in reader:
            phish_tank_list.append(row['url'])
        # Closing the file to be tidy.
        data_file.close()
        return phish_tank_list


class get_openphish_urls:
    """Gets phishing URLs from OpenPhish.
    Please note that this is a descriptor designed specifically for
    the OrcaPod class."""

    def __get__(self, obj, objtype=None):
        """Gets phishing URLs from OpenPhish.com.

        Inputs:
        None.

        Outputs:
        open_phish_list - The list of verified phishing URLs from OpenPhish.

        Exceptions:
        HTTPError - Occurs when unable to retrieve the CSV of bad URLs
        from OpenPhish."""
        # Hooray for logging!
        log = getLogger(__name__)
        # Let's make the request as a Windows PC!
        user_agent = (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
            '(KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36'
        )
        open_phish_data = request(
            'GET',  # HTTP verb
            'https://openphish.com/feed.txt',  # URL
            headers={'user-agent': user_agent}  # TrollFace
        )
        try:
            open_phish_data.raise_for_status()
        except HTTPError:
            log.exception('Error retrieving phish tank list.')
        # Writing the URLs to a list.
        open_phish_list = []
        for entry in open_phish_data.text.split('\n'):
            # Checking for blank entries
            if len(entry) > 0:
                open_phish_list.append(entry)
        return open_phish_list


class get_ad_emails:
    """Gets email address from AD via LDAP.
    Please note that this is a descriptor designed specifically for the Orca
    and OrcaPod classes"""

    def __get__(self, obj, objtype=None):
        """
        Inputs:
        None

        Outputs:
        email_list - list(), A list of email addresses from AD accounts.

        Exceptions:
        TBD
        """
        # Let's log some stuff.
        log = getLogger(__name__)
        # Initializing variables.
        ldap_url = obj.ldap_dict['url']  # LDAP URL we are connecting to.
        ldap_bind_dn = obj.ldap_dict['bind_dn']  # LDAP user name.
        ldap_bind_secret = obj.ldap_dict['bind_secret']  # User's password.
        search_ou = obj.ldap_dic['search_ou']
        # Using TLS when connecting to LDAP.
        tls_config = Tls(validate=CERT_NONE, version=PROTOCOL_TLSv1_2)
        server = Server(ldap_url, use_ssl=True, tls=tls_config)
        try:
            conn = Connection(
                server,
                user=ldap_bind_dn,
                password=ldap_bind_secret,
                auto_bind=True
            )
        except LDAPExceptionError:
            log.exception('Error occurred connecting to LDAP server.')
        log.debug('Successfully connected to LDAP server: %s', ldap_url)
        # Getting user data from LDAP, and converting the data (a list
        # of strings) to a dictionary so that it can be easily written
        # to different outputs if so desired.
        mailbox_list = []
        raw_user_data = []
        # Searching LDAP for users that are in the OUs (and all sub-OUs)
        # specified in config['ldap']['search_ou'].
        ldap_filter = ('(&(objectClass=user)(objectCategory=CN=Person,' +
                       'CN=Schema,CN=Configuration,DC=24hourfit,DC=com))')
        for ou in search_ou:
            user_data = conn.extend.standard.paged_search(
                ou,
                ldap_filter,
                search_scope=SUBTREE,
                attributes=['mail'],
                paged_size=500,
            )
            for raw_data in user_data:
                raw_user_data.append(raw_data['raw_attributes'])
        # Mapping LDAP data to a dictionary.  We are decoding the values
        # so that Python recognizes them as a string instead of byte-like
        # objects for compatibiltiy with other string (or string realted)
        # functions/methods.
        for data in raw_user_data:
            mailbox = data['mail'][0].decode().lower()
            mailbox_list.append(mailbox)
        log.info(
            'Successfully retrieved mailboxes from %s',
            ldap_url
        )
        # Unbinding the LDAP object as a good house cleaning measure.
        conn.unbind()
        return mailbox_list


class OrcaPod:
    """Automation for bulk phishing mitigation and remediation.

    Class Variables:
    config - ConfigParser(), The configuration file used by all
    instances of this object.

    Methods:
    find_phish - Searches all mailboxes for emails containing a phishing
    URL.
    eat_phish - Removes emails containing phishing URLs from hunting
    grounds."""
    # Setting configuration.
    config = ConfigParser()
    config.read('orca.ini')

    def __init__(self, config):
        """
        Instances variables:
        phish_tank_api - str(), The API key used for PhishTank.
        tm_api - str(), Trend Micro Cloud App Security API key.
        hunting_grounds - list(), A list of mailboxes.
        ldap_dict - dict(), A dictionary with the values needed to
        connect to a LDAP URL using ldap3.
        """
        self.phish_tank_api = config['api']['phish_tank_api']
        self.tm_api = config['api']['tm_api']
        self.ldap_dict = {
            'url': config['ldap']['url'],
            'bind_dn': config['ldap']['bind_dn'],
            'search_ou': config['ldap']['search_ou'].split('|'),
            'bind_secret': get_credentials({
                'api_key': config['scss']['api_key'],
                'otp': config['scss']['otp'],
                'userid': config['scss']['user'],
                'url': config['scss']['url']
            })
        }
        self._mailboxes = get_ad_emails()  # descriptor call.
        self._pt_urls = get_phish_tank_urls()  # descriptor call.
        self._op_urls = get_openphish_urls()  # descriptor call.

    def bulk_find_phish(self, url_list):
        """Finds phishing emails in O365.

        Input:
        url_list - list(), A list of URLs to search for.

        Output:
        phishes - list(), A list of dict() objects that contain
        the following keys: mailbox, mail_message_id, mail_unique_id,
        delivery_time.

        Exceptions:
        HTTPError - Occurs when the HTTP request returns a non-200
        response code."""
        # Scuba Steve says: "logging is the coolest!"
        log = getLogger(__name__)
        # Initializing results list.
        phishes = []
        # Setting up the API request.
        tm_url = 'https://api.tmcas.trendmicro.com/v1/sweeping/mails'
        headers = {'Authorization': 'Bearer ' + self.tm_api}
        # Searching for each URL in every mailbox for the past 24
        # hours.
        search_counter = 0  # Rate limit counter.
        # Iterate through the list of phishing URLs, searching for each
        # URL in every mailbox.
        for url in url_list:
            for mailbox in self._mailboxes:
                if search_counter == 20:
                    sleep(60)
                    search_counter = 0
                    log.debug('API rate limit reached.  Sleeping.')
                params = {
                    'mailbox': mailbox,
                    'lastndays': 1,
                    'url': url,
                }
                response = request(
                    'GET',
                    tm_url,
                    headers=headers,
                    params=params
                )
                # Checking for a non 200 response.
                try:
                    response.raise_for_status
                except HTTPError:
                    # Ruh roh!
                    log.exception(
                        'Non-200 HTTP respomse when performing mail sweep ' +
                        'on %s' % mailbox
                    )
                    search_counter += 1
                    continue
                data = response.json()
                # If there is a phish, add it to the results.
                if len(data['value'][0]['mail_message_id']) > 0:
                    phish_data = data['value'][0]
                    phishes.append(
                        {
                            'mailbox': mailbox,
                            'mmi': phish_data['mail_message_id'],
                            'mui': phish_data['mail_unique_id'],
                            'd_time': phish_data['mail_message_delivery_time']
                        }
                    )
                    log.info('Phishing email found in %s' % mailbox)
                search_counter += 1
        return phishes

    def bulk_eat_phish(self, phish_list):
        """Deletes phishing emails from O365 (in bulk)

        Input:
        phish_list - list(), A list of dict() that contain the following
        keys: mailbox, mmi, mui and delivery time.  This should be the
        returned value from Orca.bulk_find_phish().

        Output:
        None.

        Exceptions:
        HTTPError - Excpetion that occurs when a request returns a
        non-200 response."""
        # It's five o'clock somewhere.  Time for logging!
        log = getLogger(__name__)
        # Initializing variables and constants.
        tm_url = 'https://api.tmcas.trendmicro.com/v1/mitigation/mails'
        headers = {
            'Authorization': 'Bearer ' + self.tm_api,
            'Content-Type': 'application/json'
        }
        eat_counter = 0
        # Iterate through the phish list, making an API call to delete
        # the phish.  If there is an error deleting a phish, log it
        # and continue.
        for phish in phish_list:
            if eat_counter == 20:
                sleep(60)
                eat_counter = 0
                log.debug('API rate limit reached.  Sleeping.')
            # All of these are required parameters.  Do not change.
            params = {
                'action_type': 'MAIL_DELETE',
                'service': 'exchange',
                'account_provider': 'office365',
                'mailbox': phish['mailbox'],
                'mail_message_id': phish['mmi'],
                'mail_unique_id': phish['mui'],
                'mail_message_delivery_time': phish['d_time']
            }
            response = request(
                'POST',
                tm_url,
                headers=headers,
                params=params
            )
            try:
                response.raise_for_status
            except HTTPError:
                log.exception('Non-200 response when deleting phishing email.')
                eat_counter += 1
                continue
            log.info('Phishing email deleted from %s' % phish['mailbox'])
            eat_counter += 1


class Orca:
    """
    One off phishing search to be invoked via CLI.

    Class Variables:
    config - The config file used by all instances of this class.

    Methods:
    find_phish - Searches through mailboxes for one phishing message.
    delete_phish - Deletes a single phishing email from all mailboxes.
    """
    config = ConfigParser()
    config.read('orca.ini')

    def __init__(self, config):
        """
        Inputs:
        config - Dolphin.config.

        Instance variables:
        mailboxes - list(), A list of mailboxes to search through.
        ldap_dict - dict(), A dictionary with the values needed to
        connect to a LDAP URL using ldap3.
        """
        self.ldap_dict = {
            'url': config['ldap']['url'],
            'bind_dn': config['ldap']['bind_dn'],
            'search_ou': config['ldap']['search_ou'].split('|'),
            'bind_secret': get_credentials({
                'api_key': config['scss']['api_key'],
                'otp': config['scss']['otp'],
                'userid': config['scss']['user'],
                'url': config['scss']['url']
            })
        }
        self.mailboxes = get_ad_emails()
        self.tm_api = config['api']['tm_api']

    def find_phish_url(self, url):
        """Finds phishes that match the provided URL.

        Inputs:
        url - str(), The URL to search for.

        Outputs:
        phish_list - list(), A list of mailboxes and mail information
        for the provided URL.

        Exceptions:
        HTTPError - Occurs when there is a non-200 HTTP response."""
        # Logging, it's what's for dinner.
        log = getLogger(__name__)
        # Initializing variabels and constants.
        phish_list = []
        headers = {'Authorization:' 'Bearer ' + self.tm_api}
        tm_url = 'https://api.tmcas.trendmicro.com/v1/sweeping/mails'
        search_counter = 0
        # Looking for the phishing URL in each mailbox.
        for mailbox in self.mailboxes:
            # API rate limit check.
            if search_counter == 20:
                log.debug('API rate limit reached.  Sleeping for 60 seconds.')
                sleep(60)
                search_counter = 0
            params = {
                'mailbox': mailbox,
                'lastndays': 1,
                'url': url,
            }
            response = request(
                'GET',
                tm_url,
                headers=headers,
                params=params
            )
            # Checking if the search returned any results.
            try:
                response.raise_for_status
            except HTTPError:
                log.exception(
                    'Abnormal HTTP response searching for phishing email.'
                )
                # Incrementing search counter for API rate limiting.
                search_counter += 1
                continue
            json_data = response.json()
            phish_data = json_data['value'][0]
            phish_list.append({
                'mailbox': phish_data['mailbox'],
                'mui': phish_data['mail_unique_id'],
                'mmi': phish_data['mail_message_id'],
                'd_time': phish_data['mail_message_delivery_time']
            })
            # Incrementing search counter for API rate limiting.
            log.info('Phishing email found in %s' % mailbox)
            search_counter += 1
        return phish_list

    def find_evil_file(self, filehash):
        """Searches for emails that contain a malicious file hash.

        Input:
        filehash - str(), the SHA1 digest of a file to search for.

        Returns
        evil_list - list(), A list of dictionaries containing the
        following keys: mailbox, mmi, mui and d_time.

        Exceptions:
        HTTPError - Occurs when there is a non-200 response."""
        # Start logging.
        log = getLogger(__name__)
        # Initializing variables and constants.
        tm_url = 'https://api.tmcas.trendmicro.com/v1/sweeping/mails'
        headers = {'Authorization': 'Bearer ' + self.tm_api}
        search_counter = 0
        evil_list = []
        # Searching for emails that have an attachment with a matching
        # file hash.
        for mailbox in self.mailboxes:
            if search_counter == 20:
                log.debug('API rate limit reached.  Sleeping...')
                sleep(60)
                search_counter = 0  # Resetting rate limit counter.
            params = {
                'mailbox': mailbox,
                'lastndays': 7,
                'file_sha1': filehash
            }
            response = request(
                'GET',
                tm_url,
                params=params,
                headers=headers
            )
            try:
                response.raise_for_status
            except HTTPError:
                log.exception(
                    'Abnormal HTTP response when performing file search'
                )
                # Incrementing rate limit counter for an unsuccesful
                # search.
                search_counter += 1
                continue
            json_data = response.json()
            evil_file_data = json_data['value'][0]
            evil_list.append({
                'mailbox': evil_file_data['mailbox'],
                'mui': evil_file_data['mail_unique_id'],
                'mmi': evil_file_data['mail_message_id'],
                'd_time': evil_file_data['mail_message_delivery_time']
            })
            log.info('Email with malicious file found in %s' % mailbox)
            # Incrementing rate limit counter for successful attempt.
            search_counter += 1
        return evil_list

    def find_evil_sender(self, sender):
        """Searches for emails from a malicious sender.

        Input:
        sender - str(), malicious email address.

        Returns
        evil_list - list(), A list of dictionaries containing the
        following keys: mailbox, mmi, mui and d_time.

        Exceptions:
        HTTPError - Occurs when there is a non-200 response."""
        # Start logging.
        log = getLogger(__name__)
        # Initializing variables and constants.
        tm_url = 'https://api.tmcas.trendmicro.com/v1/sweeping/mails'
        headers = {'Authorization': 'Bearer ' + self.tm_api}
        search_counter = 0
        evil_list = []
        # Searching for emails from a malicious sender.
        for mailbox in self.mailboxes:
            if search_counter == 20:
                log.debug('API rate limit reached.  Sleeping...')
                sleep(60)
                search_counter = 0  # Resetting rate limit counter.
            params = {
                'mailbox': mailbox,
                'lastndays': 1,
                'sender': sender
            }
            response = request(
                'GET',
                tm_url,
                params=params,
                headers=headers
            )
            try:
                response.raise_for_status
            except HTTPError:
                log.exception(
                    'Abnormal HTTP response when performing sender search'
                )
                # Incrementing rate limit counter for an unsuccesful
                # search.
                search_counter += 1
                continue
            json_data = response.json()
            evil_sender_data = json_data['value'][0]
            evil_list.append({
                'mailbox': evil_sender_data['mailbox'],
                'mui': evil_sender_data['mail_unique_id'],
                'mmi': evil_sender_data['mail_message_id'],
                'd_time': evil_sender_data['mail_message_delivery_time']
            })
            log.info('Email from malicious sender found in %s' % mailbox)
            # Incrementing rate limit counter for successful attempt.
            search_counter += 1
        return evil_list

    def bulk_purge_email(self, evil_list):
        """Deletes evil emails from O365 (in bulk)

        Input:
        evil_list - list(), A list of dict() that contain the following
        keys: mailbox, mmi, mui and delivery time.

        Output:
        None.

        Exceptions:
        HTTPError - Excpetion that occurs when a request returns a
        non-200 response."""
        # It's five o'clock somewhere.  Time for logging!
        log = getLogger(__name__)
        # Setting up the API request.
        tm_url = 'https://api.tmcas.trendmicro.com/v1/mitigation/mails'
        headers = {
            'Authorization': 'Bearer ' + self.tm_api,
            'Content-Type': 'application/json'
        }
        # Initialing API counter.
        api_counter = 0
        # Iterate through the list of evil emails, making an API call
        # to delete the email in question.  If there is an error
        # purging the evil, log it and skip over that item.
        for evil in evil_list:
            if api_counter == 20:
                sleep(60)
                api_counter = 0
                log.debug('API rate limit reached.  Sleeping.')
            # All of these are required parameters.  Do not change.
            params = {
                'action_type': 'MAIL_DELETE',
                'service': 'exchange',
                'account_provider': 'office365',
                'mailbox': evil['mailbox'],
                'mail_message_id': evil['mmi'],
                'mail_unique_id': evil['mui'],
                'mail_message_delivery_time': evil['d_time']
            }
            response = request(
                'POST',
                tm_url,
                headers=headers,
                params=params
            )
            try:
                response.raise_for_status
            except HTTPError:
                log.exception('Non-200 response when deleting phishing email.')
                api_counter += 1
                continue
            log.info('Evil email deleted from %s' % evil['mailbox'])
            api_counter += 1
