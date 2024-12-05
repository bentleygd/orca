# Orca Class Documentation

## Overview

The `Orca` class provides functionality for searching, purging, and quarantining phishing emails. It integrates with the TrendMicro API to interact with email data, specifically focusing on Office 365 mailboxes. The class is designed to be invoked via CLI to perform tasks such as finding phishing emails, deleting them, or quarantining them for further investigation.

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
  - `mui`: Mail unique ID.
  - `d_time`: Delivery time of the email.

#### Exceptions:
- `HTTPError`: Raised if a non-200 HTTP response is returned.

#### Description:
- The method constructs search parameters based on provided keyword arguments (e.g., sender, subject, file hash, etc.).
- It checks if the API rate limit has been reached and pauses execution if necessary.
- The method performs an HTTP GET request to the TrendMicro API to search for phishing emails.
- If the response is successful (HTTP 200), it processes the data and logs the results.
- The method returns a list of emails matching the search criteria.

---

### `purge_email(self, evil_list)`
#### Purpose:
Deletes phishing emails from Office 365 mailboxes.

#### Inputs:
- `evil_list`: A list of dictionaries containing phishing email details (mailbox, mmi, mui, d_time).

#### Output:
- None

#### Exceptions:
- `HTTPError`: Raised if a non-201 HTTP response is returned when attempting to delete an email.

#### Description:
- The method iterates over the provided `evil_list`, and for each email, it constructs a request body with required parameters (mailbox, mmi, mui, etc.).
- It ensures that the request does not exceed the maximum allowed batch size of 10 emails per request.
- The method checks if the API rate limit has been reached and pauses execution if necessary.
- After sending the request to delete emails, the method logs the result and increments the `api_counter`.
- If an error occurs during the deletion process, it logs the exception and continues with the next email.

---

### `pull_email(self, evil_list)`
#### Purpose:
Quarantines phishing emails from Office 365 mailboxes.

#### Inputs:
- `evil_list`: A list of dictionaries containing phishing email details (mailbox, mmi, mui, d_time).

#### Output:
- None

#### Exceptions:
- `HTTPError`: Raised if a non-201 HTTP response is returned when attempting to quarantine an email.

#### Description:
- Similar to the `purge_email` method, this method iterates over the `evil_list` and constructs a request body to quarantine each email.
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
orca = Orca()

# Search for phishing emails by sender
phishing_emails = orca.find_phish(sender='malicious@example.com')

# Purge the found phishing emails
orca.purge_email(phishing_emails)

# Quarantine the found phishing emails
orca.pull_email(phishing_emails)
```

---

## Notes

- The class interacts with the TrendMicro API, specifically the `sweeping/mails` and `mitigation/mails` endpoints, to perform phishing email searches, purges, and quarantines.
- API rate limits are managed by the `api_counter`, which is reset after 60 seconds if the limit is reached.
- The `find_phish` method supports various search criteria (sender, subject, URL, file hash, etc.), enabling flexible phishing email searches.
- The `purge_email` and `pull_email` methods allow for managing the emails once identified, by either deleting or quarantining them.

---

# Phishing URL Retrieval Documentation

## Overview

Two classes, `get_phish_tank_urls` and `get_openphish_urls`, are designed to retrieve phishing URLs from two different sources:

1. **PhishTank** - A community-driven platform that provides verified phishing URLs.
2. **OpenPhish** - A commercial phishing feed service.

Both classes use descriptors to fetch phishing URLs and provide a list of verified phishing URLs upon request.

---

## Class: `get_phish_tank_urls`

### Description:
This class is responsible for retrieving verified phishing URLs from PhishTank.org. It is specifically designed to be used as a descriptor in the OrcaPod class.

### Method: `__get__(self, obj, objtype=None)`

#### Purpose:
This method retrieves the list of verified phishing URLs from PhishTank.org by requesting a CSV file containing online valid phishing URLs.

#### Inputs:
- **None**: This method is invoked automatically when accessing the descriptor.

#### Outputs:
- **phish_tank_list**: A list of phishing URLs retrieved from PhishTank.

#### Exceptions:
- **HTTPError**: Raised if there is an issue with the request to retrieve the CSV file from PhishTank.org.

#### Steps:
1. **Logging**: Logs errors and information using the `getLogger` function.
2. **Request PhishTank Data**: Sends an HTTP GET request to the PhishTank API to retrieve the phishing URL CSV.
3. **Error Handling**: If the request fails, an `HTTPError` is raised and logged.
4. **Data Parsing**: The CSV data is processed and written to a temporary file.
5. **Extract URLs**: The CSV data is read using `DictReader`, and the URLs are extracted and stored in a list.
6. **File Closure**: The temporary file is closed after reading.
7. **Return**: The list of phishing URLs is returned.

---

## Class: `get_openphish_urls`

### Description:
This class retrieves verified phishing URLs from OpenPhish.com, a commercial phishing feed service. It is also a descriptor designed for the OrcaPod class.

### Method: `__get__(self, obj, objtype=None)`

#### Purpose:
This method retrieves the list of phishing URLs from OpenPhish.com by requesting a plain text feed containing phishing URLs.

#### Inputs:
- **None**: This method is automatically called when accessing the descriptor.

#### Outputs:
- **open_phish_list**: A list of phishing URLs retrieved from OpenPhish.

#### Exceptions:
- **HTTPError**: Raised if there is an issue with the request to retrieve the phishing URL feed from OpenPhish.

#### Steps:
1. **Logging**: Logs errors and information using the `getLogger` function.
2. **User-Agent Setup**: Sets a custom user-agent header to simulate a request from a Windows PC.
3. **Request OpenPhish Data**: Sends an HTTP GET request to retrieve the phishing URL feed from OpenPhish.
4. **Error Handling**: If the request fails, an `HTTPError` is raised and logged.
5. **Parse URLs**: The text feed is split by newlines, and each entry is checked for blanks before being added to the list of phishing URLs.
6. **Return**: The list of phishing URLs is returned.

---

## Example Usage

### Accessing Phishing URLs from PhishTank:
```python
# Assuming obj is an instance of the class containing the descriptor
phish_tank_urls = obj.phish_tank_urls
```

### Accessing Phishing URLs from OpenPhish:
```python
# Assuming obj is an instance of the class containing the descriptor
open_phish_urls = obj.open_phish_urls
```

---

## Notes

- Both classes are designed to be used as descriptors and will retrieve phishing URLs when accessed as part of an object.
- The classes do not take any arguments for initialization but rely on accessing the API or URL directly.

