from csv import DictReader
from logging import getLogger
from tempfile import TemporaryFile
from configparser import ConfigParser
from time import sleep

from requests import request, HTTPError


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


class Orca:
    """One off phishing search to be invoked via CLI.

    Class Variables:
    config - The config file used by all instances of this class.

    Methods:
    find_phish - Finds a phishing email based on supplied keyword
    arguments.
    purge_email - Deletes a single phishing email from affected
    mailboxes.
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
        self.tm_api = Orca.config['api']['tm_api']
        self.api_counter = int()

    def find_phish(self, **phish_):
        """Searches for phishing emails based on supplied keyword
        arguments.

        Keyword Arguments:
        sender - str(), malicious email address.  Required if not
        searching by url or file_hash.
        subject - str(), Email subject line (optional)
        file_ext - str(), file extension (optional)
        file_hash - str(), file_hash(optional)
        url - str(), phishing url to search for (optional)

        Returns
        evil_list - list(), A list of dictionaries containing the
        following keys: mailbox, mmi, mui and d_time.

        Exceptions:
        HTTPError - Occurs when there is a non-200s response."""
        # Start logging.
        log = getLogger(__name__)
        # Initializing variables and constants.
        tm_url = 'https://api.tmcas.trendmicro.com/v1/sweeping/mails'
        headers = {'Authorization': 'Bearer ' + self.tm_api}
        evil_list = []
        # Searching for emails from a malicious sender.
        if self.api_counter == 20:
            log.debug('API rate limit reached.  Sleeping for 60 seconds.')
            sleep(60)
            self.api_counter = 0  # Resetting rate limit counter.
        # Search used when URL is supplied.
        if 'url' in phish_:
            log.debug('Performing URL search.')
            params = {
                'lastndays': 1,
                'url': phish_['url'],
                'limit': 1000
            }
        # Search used when file_hash is supplied.
        elif 'file_hash' in phish_:
            log.debug('Performing SHA1 hash search.')
            params = {
                'file_sha1': phish_['file_hash'],
                'lastndays': 1,
                'limit': 1000
            }
        # Search used when sender, subject and file extnension is
        # supplied.
        elif (
            'file_ext' in phish_ and
            'subject' in phish_ and
            'sender' in phish_
        ):
            log.debug('Performing sender/subject/file extension search.')
            params = {
                'lastndays': 1,
                'sender': phish_['sender'],
                'subject': phish_['subject'],
                'file_extension': phish_['file_ext'],
                'limit': 1000
            }
        # Search used when subject and sender is supplied.
        elif 'subject' in phish_ and 'sender' in phish_:
            log.debug('Performing sender/subject search.')
            params = {
                'lastndays': 1,
                'sender': phish_['sender'],
                'subject': phish_['subject'],
                'limit': 1000
            }
        # Search used when file extension and sender is supplied.
        elif 'file_ext' in phish_ and 'sender' in phish_:
            log.debug('Performing sender/file extension search.')
            params = {
                'lastndays': 1,
                'sender': phish_['sender'],
                'file_extension': phish_['file_ext'],
                'limit': 1000
            }
        # Search used when only the sender is supplied.
        elif 'sender' in phish_:
            log.debug('Performing sender search.')
            params = {
                'lastndays': 1,
                'sender': phish_['sender'],
                'limit': 1000
            }
        response = request(
            'GET',
            tm_url,
            params=params,
            headers=headers
        )
        # Checking if the search was successful from an API call
        # perpsective (i.e., looking for a HTTP 200)
        try:
            response.raise_for_status
        except HTTPError:
            log.exception(
                'Abnormal HTTP response when performing sender search. ' +
                'The API response is %s' % response.text
            )
            # Incrementing rate limit counter for an unsuccesful
            # search.
            self.api_counter += 1
        json_data = response.json()
        evil_sender_data = json_data['value']
        for evil_data in evil_sender_data:
            evil_list.append({
                'mailbox': evil_data['mailbox'],
                'mui': evil_data['mail_unique_id'],
                'mmi': evil_data['mail_message_id'],
                'd_time': evil_data['mail_message_delivery_time']
            })
            if 'sender' in phish_:
                log.info(
                    'Email from %s found in %s' %
                    (phish_['sender'], evil_data['mailbox'])
                )
            elif 'url' in phish_:
                log.info(
                    'Email with %s found in %s' %
                    (phish_['url'], evil_data['mailbox'])
                )
            elif 'file_hash' in phish_:
                log.info(
                    'Email with malicious file matching %s found in %s' %
                    (phish_['file_hash'], evil_data['mailbox'])
                )
        # Incrementing rate limit counter for successful attempt.
        self.api_counter += 1
        return evil_list

    def purge_email(self, evil_list):
        """Deletes evil emails from O365.

        Input:
        evil_list - list(), A list of dict() that contain the following
        keys: mailbox, mmi, mui and delivery time.

        Output:
        None.

        Exceptions:
        HTTPError - Excpetion that occurs when a request returns a
        non-201 response."""
        # It's five o'clock somewhere.  Time for logging!
        log = getLogger(__name__)
        # Setting up the API request.
        tm_url = 'https://api.tmcas.trendmicro.com/v1/mitigation/mails'
        headers = {
            'Authorization': 'Bearer ' + self.tm_api,
            'Content-Type': 'application/json'
        }
        # Iterate through the list of evil emails, making an API call
        # to delete the email in question.  If there is an error
        # purging the evil, log it and skip over that item.
        json_array = []
        while len(evil_list) != 0:
            evil = evil_list.pop(0)
            # All of these are required parameters.  Do not change.
            json_body = {
                'action_type': 'MAIL_DELETE',
                'service': 'exchange',
                'account_provider': 'office365',
                'mailbox': evil['mailbox'],
                'mail_message_id': evil['mmi'],
                'mail_unique_id': evil['mui'],
                'mail_message_delivery_time': evil['d_time']
            }
            log.debug('Added to delete call %s' % json_body)
            json_array.append(json_body)
            # Making sure to keep the JSON array at or under 10 entries.
            if len(json_array) == 10:
                log.info('Max mailbox size reached.')
                # Checking API count.
                if self.api_counter == 20:
                    sleep(60)
                    self.api_counter = 0
                    log.info('API rate limit reached.  Sleeping.')
                # Posting JSON array.
                response = request(
                    'POST',
                    tm_url,
                    headers=headers,
                    json=json_array
                )
                # Checking whether or not the API call is successful.
                try:
                    if response.status_code != 201:
                        raise HTTPError
                except HTTPError:
                    log.exception(
                        'Non-201 response when pulling phishing email.'
                    )
                    self.api_counter += 1
                    continue
                self.api_counter += 1
                log.info('Deleted emails from %d mailboxes' % len(json_array))
                log.debug('Array has %d entries.  Clearing.' % len(json_array))
                json_array.clear()
                sleep(30)
        # Sending the API call with 9 or fewer entries.
        # Checking API count.
        if self.api_counter == 20:
            sleep(60)
            self.api_counter = 0
            log.info('API rate limit reached.  Sleeping.')
        # Posting JSON array.
        response = request(
            'POST',
            tm_url,
            headers=headers,
            json=json_array
        )
        # Checking whether or not the API call is successful.
        try:
            if response.status_code != 201:
                raise HTTPError
        except HTTPError:
            log.exception(
                'Non-201 response when pulling phishing email.  The API ' +
                'response is %s' % response.text
            )
            self.api_counter += 1
        log.info('Deleted emails from %d mailboxes' % (len(json_array)))
        self.api_counter += 1

    def pull_email(self, evil_list):
        """Quarantines evil emails from O365.

        Input:
        evil_list - list(), A list of dict() that contain the following
        keys: mailbox, mmi, mui and delivery time.

        Output:
        None.

        Exceptions:
        HTTPError - Excpetion that occurs when a request returns a
        non-201 response."""
        # It's five o'clock somewhere.  Time for logging!
        log = getLogger(__name__)
        # Setting up the API request.
        tm_url = 'https://api.tmcas.trendmicro.com/v1/mitigation/mails'
        headers = {
            'Authorization': 'Bearer ' + self.tm_api,
            'Content-Type': 'application/json'
        }
        # Iterate through the list of evil emails, making an API call
        # to quarantine the email in question.  If there is an error
        # containing the evil, log it and skip over that item.
        json_array = []
        while len(evil_list) != 0:
            evil = evil_list.pop(0)
            # All of these are required parameters.  Do not change.
            json_body = {
                'action_type': 'MAIL_QUARANTINE',
                'service': 'exchange',
                'account_provider': 'office365',
                'mailbox': evil['mailbox'],
                'mail_message_id': evil['mmi'],
                'mail_unique_id': evil['mui'],
                'mail_message_delivery_time': evil['d_time']
            }
            log.debug('Added to quarantine call %s' % json_body)
            json_array.append(json_body)
            # Making sure to keep the JSON array at or under 10 entries.
            if len(json_array) == 10:
                log.info('Reached max mailbox size.')
                # Checking API count.
                if self.api_counter == 20:
                    sleep(60)
                    self.api_counter = 0
                    log.info('API rate limit reached.  Sleeping.')
                # Posting JSON array.
                response = request(
                    'POST',
                    tm_url,
                    headers=headers,
                    json=json_array
                )
                # Checking whether or not the API call is successful.
                try:
                    if response.status_code != 201:
                        raise HTTPError
                except HTTPError:
                    log.exception(
                        'Non-201 response when pulling phishing email.'
                    )
                    self.api_counter += 1
                    continue
                self.api_counter += 1
                log.info('Pulled emails from %d mailboxes' % (len(json_array)))
                log.debug('Reached max array size.  Clearing array.')
                json_array.clear()
                sleep(30)
        # Sending the API call with 9 or fewer entries.
        # Checking API count.
        if self.api_counter == 20:
            sleep(60)
            self.api_counter = 0
            log.debug('API rate limit reached.  Sleeping.')
        # Posting JSON array.
        response = request(
            'POST',
            tm_url,
            headers=headers,
            json=json_array
        )
        # Checking whether or not the API call is successful.
        try:
            if response.status_code != 201:
                raise HTTPError
        except HTTPError:
            log.exception(
                'Non-201 response when pulling phishing email.  The API ' +
                'response is %s' % response.text
            )
            self.api_counter += 1
        log.info('Pulled emails from %d mailboxes' % (len(json_array)))
        self.api_counter += 1


class OrcaPod(Orca):
    """Automation for bulk phishing mitigation and remediation.
    This is a sub-class of Orca.

    Class Variables:
    config - ConfigParser(), The configuration file used by all
    instances of this object.

    Methods:
    find_phish - Searches all mailboxes for emails containing a phishing
    URL.
    eat_phish - Removes emails containing phishing URLs from hunting
    grounds."""

    def __init__(self, config):
        """
        Instances variables:
        phish_tank_api - str(), The API key used for PhishTank.
        """
        Orca.__init__(self)
        self.phish_tank_api = Orca.config['api']['phish_tank_api']
        self._pt_urls = get_phish_tank_urls()  # descriptor call.
        self._op_urls = get_openphish_urls()  # descriptor call.
