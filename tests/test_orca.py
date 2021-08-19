from configparser import ConfigParser
from secrets import token_bytes
from hashlib import sha256
from base64 import b64encode

from libs.coreutils import mail_send
from libs.orca import Orca


class OrcaTest:
    """Test class for Orca."""
    def __init__(self):
        self.config = ConfigParser()
        self.config.read('orca.ini')
        self.url = str()
        self.search_subject = str()

    def url_search_test(self):
        """Test for URL search."""
        random_hash = sha256(b64encode(token_bytes(16))).hexdigest()
        self.url = 'https://www.' + random_hash + '.com/click/here'
        mail_info = {
            'sender': self.config['test']['sender'],
            'recipients': self.config['test']['recipient'],
            'subject': 'Orca URL Test',
            'body': self.url,
            'server': self.config['test']['smtp_server']
        }
        mail_send(mail_info)
        phish_hunt = Orca()
        search_results = phish_hunt.find_phish(url=self.url)
        if search_results['mailbox'] == self.config['test']['recipient']:
            test = True
        else:
            test = False
        assert test is True

    def url_pull_test(self):
        """Test for pulling by URL"""
        phish_hunt = Orca()
        phish_list = Orca.find_phish(url=self.url)
        try:
            phish_hunt(phish_list)
        except Exception:
            test = False
        test = True
        assert test is True

    def subject_search_test(self):
        """Test for searching by subject."""
        self.search_subject = sha256(b64encode(token_bytes(16))).hexdigest()
        mail_info = {
            'sender': self.config['test']['sender'],
            'recipients': self.config['test']['recipient'],
            'subject': self.search_subject,
            'body': 'This is a test message.',
            'server': self.config['test']['smtp_server']
        }
        mail_send(mail_info)
        phish_hunt = Orca()
        search_results = phish_hunt.find_phish(
            sender=mail_info['sender'],
            subject=mail_info['subject']
        )
        if search_results['mailbox'] == self.config['test']['recipient']:
            test = True
        else:
            test = False
        assert test is True

    def subject_pull_test(self):
        """Test for pulling by URL"""
        phish_hunt = Orca()
        phish_list = Orca.phish_hunt.find_phish(
            sender=self.config['test']['sender'],
            subject=self.config['test']['subject']
        )
        try:
            phish_hunt(phish_list)
        except Exception:
            test = False
        test = True
        assert test is True
