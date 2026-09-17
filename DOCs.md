# OrcaV2 Class Documentation

## Overview

The `Orca` and `OrcaV2` classes provide functionality for searching, purging, and quarantining phishing emails. It integrates with the TrendMicro Vision One API to interact with email data, specifically focusing on Office 365 mailboxes. The class is designed to be invoked via CLI to perform tasks such as finding phishing emails, deleting them, or quarantining them for further investigation.

`Important Note:` The Orca class is deprecated as Trend Micro no longer has a stand-alone, Cloud App Security product.  All previous response functionailty now falls under the Vision One umbrella.

### Class Variables:
- `config`: The configuration file used across all instances of the `Orca` class.

### Instance Variables:
- `tm_api`: The API key used for authenticating requests to TrendMicro.
- `api_counter`: A counter to track API usage and ensure rate limits are respected.

---

## Methods

### `__init__(self)`
#### Purpose:
Initializes an instance of the `Orca` class by loading configuration and setting up API authentication.

#### Inputs:
- `config`: The `Orca.config` configuration file.

#### Instance Variables:
- `tm_api`: API key fetched from the configuration file.
- `api_counter`: Initialized to zero for tracking the number of API calls.

---

### `find_phish(self, **phish_)`
#### Purpose:
Searches for phishing emails based on provided keyword arguments, such as sender, subject, file extension, file hash, or URL.

#### Keyword Arguments:
- `sender`: (str) Malicious email address (required if not searching by URL or file hash).
- `subject`: (str) Subject of the email (optional).
- `file_ext`: (str) File extension (optional).
- `file_hash`: (str) SHA1 file hash (optional).
- `url`: (str) Phishing URL to search for (optional).

#### Returns:
- `evil_list`: A list of dictionaries containing:
  - `mailbox`: Mailbox where the phishing email was found.
  - `mmi`: Mail message ID.

#### Exceptions:
- `HTTPError`: Raised if a non-200 HTTP response is returned.

#### Description:
- The method constructs search parameters based on provided keyword arguments (e.g., sender, subject, file hash, etc.).
- It checks if the API rate limit has been reached and pauses execution if necessary.
- The method performs an HTTP GET request to the TrendMicro API to search for phishing emails.
- If the response is successful (HTTP 200), it processes the data and logs the results.
- The method returns a list of emails matching the search criteria.

---

### `pull_email(self, evil_list)`
#### Purpose:
Quarantines phishing emails from Office 365 mailboxes.

#### Inputs:
- `evil_list`: A list of dictionaries containing phishing email details (mailbox, mmi).

#### Output:
- `return_data`: The HTTP response from the TrendAI Vision One response API.

#### Exceptions:
- `HTTPError`: Raised if a non-207 HTTP response is returned when attempting to quarantine an email.

#### Description:
- This method iterates over the `evil_list` and constructs a request body to quarantine each email.
- It ensures that the number of emails in each API request does not exceed the maximum allowed size.
- The method checks if the API rate limit is reached and pauses execution when necessary.
- After sending the request to quarantine emails, it logs the result and increments the `api_counter`.
- If an error occurs during the quarantine process, it logs the exception and continues with the next email.

---

## Logging

The class utilizes logging at various stages of the process:
- **Debug Logs**: To track the status of searches, deletions, and quarantines.
- **Info Logs**: To report the number of emails found, deleted, or quarantined.
- **Exception Logs**: To record any errors or abnormal responses from API requests.

---

## Example Usage

```python
# Instantiate the Orca class
orca = OrcaV2()

# Search for phishing emails by sender
phishing_emails = orca.find_phish(sender='malicious@example.com')

# Quarantine the found phishing emails
orca.pull_email(phishing_emails)
```

---

## Notes

- API rate limits are managed by the `api_counter`, which is reset after 60 seconds if the limit is reached.
- The `find_phish` method supports various search criteria (sender, subject, URL, file hash, etc.), enabling flexible phishing email searches.
- The `purge_email` method allows for managing the emails once identified, by either quarantining them.
