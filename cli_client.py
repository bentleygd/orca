from argparse import ArgumentParser
from logging import basicConfig, INFO

from libs import orca


# Setting up logging config.
basicConfig = (
    format='%(asctime)s %(levelname)s %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p',
    level=INFO
)

# Setting up an asrgument parser for CLI execution.
parser = ArgumentParser(
    prog='Orca CLI Client',
    description="""A command line client to utilize Trend Micro's Cloud
        Security APIs for email threat mitigation and remediation."""
    )
# This is the only mandatory argument.
parser.add_argument(
    'action',
    help='Action to perform.',
    choices=['search', 'quarantine', 'purge'],
    default='search'
)
parser.add_argument(
    '--sender',
    default=None,
    help='Email sender to search for',
)
parser.add_argument(
    '--url',
    default=None,
    help='URL to search for'
)
parser.add_argument(
    '--subject',
    default=None,
    help='Email subject to search for'
)
parser.add_argument(
    '--hash',
    default=None,
    help='SHA1 hash of file to search for'
)
