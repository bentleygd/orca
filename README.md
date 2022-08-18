# orca

Python scripts that utilize Trend Micro Cloud App Security APIs for phishing identification, mitigation and remediation.  As a courtesy warning, if Trend Micro ever substantially changes their APIs this code may not work.

[![Total alerts](https://img.shields.io/lgtm/alerts/g/bentleygd/orca.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/bentleygd/orca/alerts/) [![Language grade: Python](https://img.shields.io/lgtm/grade/python/g/bentleygd/orca.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/bentleygd/orca/context:python) [![Known Vulnerabilities](https://snyk.io/test/github/bentleygd/orca/badge.svg)](https://snyk.io/test/github/bentleygd/orca)

## Purpose
The purpose of orca is to automate finding and removing phishing emails for customers of Trend Micro Cloud App Security.  The utilization of orca can significantally reduce man hours spent on containing and eradicating phishing threats.  The CLI client can also be leveraged to "deputize" teams outside core security teams (such as the help desk) so that phishing threats can be addressed as soon as users report them to the help desk instead of having to wait for the extra minutes needed to notify the security team.

## Installation

To install orca, simply clone the main branch which inlcudes a handy CLI script.

```bash
git clone git@github.com:bentleygd/orca.git
```

## Usage

Orca can be invoked from the command line by utilizing the cli_client.py script.

```
usage: Orca CLI Client [-h] [-se SENDER] [-u URL] [-su SUBJECT] [-ha HASH]
                       [-fe FILE_EXTENSION] [-v] [-q]
                       {pull}

A command line client to utilize Trend Micros Cloud Security APIs for email
threat mitigation and remediation.

positional arguments:
  {pull}                Action to perform.

optional arguments:
  -h, --help            show this help message and exit
  -se SENDER, --sender SENDER
                        Email sender to search for
  -u URL, --url URL     URL to search for
  -su SUBJECT, --subject SUBJECT
                        Email subject to search for. Must be enclosed in
                        dobule quotes (e.g., "Evil Subject Line")
  -ha HASH, --hash HASH
                        SHA1 hash of file to search for
  -fe FILE_EXTENSION, --file-extension FILE_EXTENSION
                        File extension to search for. Do not include the .
  -v, --verbose         Increasese verbosity level
  -q, --quiet           Suppress console logging.
  ```

  Alternately, if you wish to integrate the code located in libs/orca.py into your code, you can do so farily easily.
  ```python
  from orca.libs import orca


  # Instantiating the Orca class.
  phish_assist = orca.Orca()
  # Getting a list of phishing emails based on sender and subject line.
  evil_emails = phish_assit.find_phish(
    sender=bad_guy@evil.org,
    subject="Phishing Email"
    )
  # Getting rid (quarantining) of the evil emails.  The pull email method
  # doesn't return anything.
  phish_assit.pull_email(evil_emails)
```

## Configuration

Documentation on an exmaple configuration file goes here.

## Code Documentation

Full code documentation can be found [here](https://github.com/bentleygd/orca/blob/main/DOCs.md)
