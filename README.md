![License: CISCO](https://img.shields.io/badge/License-CISCO-blue.svg)
[![published](https://static.production.devnetcloud.com/codeexchange/assets/images/devnet-published.svg)](https://developer.cisco.com/codeexchange/github/repo/)

# Cisco Secure Endpoint (formerly known as AMP for Endpoints) Exclusion Migration Tool

> **NOTE:** This is sample code and needs to be tested properly before using in production!

## Features

* Prompts user wether all policies should be downloaded/updated. This will download all the XML files from the AMP cloud and creates a new directory `policies` to store them all.
* Prompts user which XML file should be used to parse the exclusions out of.
* Prints the parsed exclusions on the CLI and also creates a directory `exclusions` with a TXT file.
* Parsed exclusions can be used to migrate exclusions from policy to policy, and more importantly, from tenant to tenant (in the MSSP multi-org portal).

### Roadmap

* Automatically update the Exclusions (API not yet available to do so).
* Make sure the RegEx of the GUI's **Add Multiple Exclusions...** option captures the right exclusions type.

### Cisco Products / Services

* Cisco Secure Endpoint (formerly known as AMP for Endpoints)

## Installation

1. Download the GitHub directory into it's own directory.

2. In a terminal window, change directory (`cd amp_exclusion_management`) to the one containing the code. 

3. Create a Python virtual environment and install the `requirements.txt` file:

```python
python3.8 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

4. Open up the `creds.json` file and add Secure Endpoint (AMP4E) API credentials. Optionally change the AMP host URL to `.eu.` or `.apjc.` if you are not using the US AMP cloud. Don't forget to save the file. You can retrieve these AMP keys in your AMP4E Dashboard under **Accounts > API keys**. If you don't have an account you can test with dCloud (e.g. **https://amp.dcloud.cisco.com/users/login** `devnetexpress@cisco.comand` `C1sco12345`).

5. Execute the python `AMP_exclusion_management.py` file in your venv:

```python
python AMP_exclusion_management.py
```

6. Enter `yes` if you would like to download all policy XML files, or overwrite the previous ones (handy if you are not sure if you have the latest). This will download all the XML files from the AMP cloud and creates a new directory `policies` to store them all.

7. Enter the name of the XML file you would like to parse for exclusions (e.g. `ios_Audit_e1241826-0d35-4231-b521-28432f437950.xml`). 

8. Copy the parsed exclusions from the TXT file in the newly created directory `exclusions` (e.g. `ios_Audit_e1241826-0d35-4231-b521-28432f437950_for_copying.txt`). There is also another file with a similar name (e.g. `ios_Audit_e1241826-0d35-4231-b521-28432f437950_for_checking.txt`) which is prepended with the **Exclusion Type**. This is meant to double check after the first time you have copied your exclusions.

9. Go to your AMP tenant that you wish to migrate exclusions into. Go to an existing **custom exclusion set** or create a new one. Click on **Add Multiple Exclusions...** and paste the copied exclusions. They should be auto-detected as the exclusion type (**please check this the first time you are migrating exclusions to a tenant**). Please check out the [AMP for Endpoints User Guide](https://docs.amp.cisco.com/en/A4E/AMP%20for%20Endpoints%20User%20Guide.pdf) for more information.

10. Repeat steps 5 until 9 as many times as you would like. Most likely you will select `no` on the first prompt, since you don't have to download each XML file again each time. You can parse exclusions out of any policy XML file you would like.

## Author(s)

* Christopher van der Made (Cisco)


