"""
This module is a CLI script that calls the class/functions in orcav2.py and
coreutils.py.  This is the 'main' script that is executed by usres to find
and remove phishing emails.

Classes:
None

Functions:
None
"""
from argparse import ArgumentParser
from configparser import ConfigParser
from logging import basicConfig, DEBUG, getLogger
import sys

from libs import orca


# Loading config file.
config = ConfigParser()
config.read('orca.ini')
# Setting up an asrgument parser for CLI execution.
parser = ArgumentParser(
    prog='Orca CLI Client',
    description="""A command line client to utilize Trend Micro's Cloud
        Security APIs for email threat mitigation and remediation."""
    )
# This is the only mandatory argument.  API endpoints exist to delete emails,
# but due to a conservative stance in many organizations, the use of the
# delete endpoint isn't included.  However, it is trivial to include.
#
# To see the code for the delete functionality, check the purge_email method
# in the deprecated Orca module.
parser.add_argument(
    'action',
    help='Action to perform.',
    choices=['pull'],
    default='pull'
)
parser.add_argument(
    '-se', '--sender',
    default=None,
    help='Email sender to search for',
)
parser.add_argument(
    '-u', '--url',
    default=None,
    help='URL to search for'
)
parser.add_argument(
    '-su', '--subject',
    default=None,
    help="""Email subject to search for.  Must be enclosed in dobule
         quotes (e.g., "Evil Subject Line")"""
)
parser.add_argument(
    '-ha', '--hash',
    default=None,
    help='SHA1 hash of file to search for'
)
orca_args = parser.parse_args()
# Setting up logging.
log = getLogger(__name__)
# Use console logging if verbose is enabled.  Otherwise, log to file.
basicConfig(
    format='%(asctime)s %(name)s %(levelname)s: %(message)s',
    datefmt='%m/%d/%Y %H:%M:%S',
    level=DEBUG
)
phish_hunt = orca.Orca()
# Looking for phishing emails based on supplied arguments.
# Check if URL is supplied.
if orca_args.url is not None:
    # Finding and pulling emails with indicated URL.
    phish_list = phish_hunt.find_phish(url=orca_args.url)
    print('*' * 32 + 'WARNING' + '*' * 32)
    print('You are going to pull email from %d mailboxes.', len(phish_list))
    WARNING = str(input('Press Y/N to continue> '))
    if WARNING.lower() == 'y':
        log.info('Acknowledgment accepted for %d mailboxes', len(phish_list))
    else:
        print('*' * 32 + 'ABORTING' + '*' * 32)
        sys.exit()
    # Checking for pull or purge and taking appropriate action.
    log.debug(f'Performing URL pull for {orca_args.url}')
    if orca_args.action == 'pull':
        phish_hunt.pull_email(phish_list)
    # elif orca_args.action == 'purge':
    #    phish_hunt.purge_email(phish_list)
# Check if file hash is supplied.
elif orca_args.hash is not None:
    # Finding and pulling emails with indicated file hash.
    phish_list = phish_hunt.find_phish(file_hash=orca_args.hash)
    print('*' * 32 + 'WARNING' + '*' * 32)
    print('You are going to pull email from %d mailboxes.', len(phish_list))
    WARNING = str(input('Press Y/N to continue> '))
    if WARNING.lower() == 'y':
        log.info('Acknowledgment accepted for %d mailboxes', len(phish_list))
    else:
        print('*' * 32 + 'ABORTING' + '*' * 32)
        sys.exit()
    # Checking for pull or purge and taking appropriate action.
    log.debug(f'Performing SHA1 hash pull for {orca_args.hash}')
    if orca_args.action == 'pull':
        phish_hunt.pull_email(phish_list)
# Checking if sender and subject are supplied.
elif (orca_args.sender is not None and
        orca_args.subject is not None):
    
    phish_list = phish_hunt.find_phish(
        sender=orca_args.sender,
        subject=orca_args.subject
    )
    print('*' * 32 + 'WARNING' + '*' * 32)
    print('You are going to pull email from %d mailboxes.', len(phish_list))
    WARNING = str(input('Press Y/N to continue> '))

    if WARNING.lower() == 'y':
        log.info('Acknowledgment accepted for %d mailboxes', len(phish_list))
    else:
        print('*' * 32 + 'ABORTING' + '*' * 32)
        sys.exit()
    # Checking for pull or purge and taking appropriate action.
    log.debug(
        f'Pulling based on sender:{orca_args.sender} subject:{orca_args.subject}'
    )

    if orca_args.action == 'pull':
        phish_hunt.pull_email(phish_list)
# Checking if sender and file extension are supplied.
elif (orca_args.sender is not None and
        orca_args.file_hash is not None):
    phish_list = phish_hunt.find_phish(
        sender=orca_args.sender,
        file_ext=orca_args.file_extension
    )
    print('*' * 32 + 'WARNING' + '*' * 32)
    print('You are going to pull email from %d mailboxes.', len(phish_list))
    WARNING = str(input('Press Y/N to continue> '))

    if WARNING.lower() == 'y':
        log.info('Acknowledgment accepted for %d mailboxes', len(phish_list))
    else:
        print('*' * 32 + 'ABORTING' + '*' * 32)
        sys.exit()

    log.debug(
        f'Pulling based on sender:{orca_args.sender} file_ext:{orca_args.file_extension}'
        )
    if orca_args.action == 'pull':
        phish_hunt.pull_email(phish_list)
# Checking only for sender
elif orca_args.sender is not None:
    phish_list = phish_hunt.find_phish(sender=orca_args.sender)
    print('*' * 32 + 'WARNING' + '*' * 32)
    print('You are going to pull email from %d mailboxes.', len(phish_list))
    WARNING = str(input('Press Y/N to continue> '))

    if WARNING.lower() == 'y':
        log.info('Acknowledgment accepted for %d mailboxes', len(phish_list))
    else:
        print('*' * 32 + 'ABORTING' + '*' * 32)
        sys.exit()

    log.debug('Pulling email based on sender: %s', orca_args.sender)
    if orca_args.action == 'pull':
        phish_hunt.pull_email(phish_list)
# Chcking for subject only
elif orca_args.subject is not None:
    phish_list = phish_hunt.find_phish(subject=orca_args.subject)
    print('*' * 32 + 'WARNING' + '*' * 32)
    print('You are going to pull email from %d mailboxes.', len(phish_list))
    WARNING = str(input('Press Y/N to continue> '))

    if WARNING.lower() == 'y':
        log.info('Acknowledgment accepted for %d mailboxes', len(phish_list))
    else:
        print('*' * 32 + 'ABORTING' + '*' * 32)
        sys.exit()

    log.debug(f'Pulling email based on sender: {orca_args.sender}')
    if orca_args.action == 'pull':
        phish_hunt.pull_email(phish_list)
