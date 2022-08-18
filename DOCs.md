# Orca Code Documentation
As stated [here](https://github.com/bentleygd/orca/blob/main/README.md), if Trend Micro changes any of Cloud App Security's APIs this code may not function anymore and would require signficant rework.

## Orca
The orca class is designed to be invoked via the CLI or other scripts in order to automate finding and removing phishing emails.

**Class Variables**
- **config** \- The config file used by all instances of this class.  This is a configuration that is returned by the ConfigParser class from the configparser module in the Python 3 standard library.

**Methods**
- **find_phish** \- Finds a phishing email based on keyword arguments supplied when the method is invoked.
- **purge_email** \- Deletes a single phishing email from all mailboxes in which it was received.  The required input is the output of the find_phish method.
- **pull_email** \- Quarantines a single phishing email from all mailboxes in which it was received.  The required input is the output of the find_phish method.

**Code Example:**

```python
from orca.libs import orca


  # Instantiating the Orca class.
  phish_assist = orca.Orca()
  # Getting a list of phishing emails based on sender, subject line and
  # file extension.
  evil_emails = phish_assit.find_phish(
    sender="bad_guy@evil.org",
    subject="Word Document With Malware",
    file_ext=".docm",
    )
  # Getting rid (quarantining) of the evil emails.  The pull email method
  # doesn't return anything.
  phish_assit.pull_email(evil_emails)
  ```
