'''
Usage: fill in API keys (line 16-17), activate venv and execute script and use prompt to direct script
> source venv/bin/activate
> python AMP_exclusion_management.py
'''

# import libraries
import xml.etree.ElementTree as ET
import requests
import sys
import json
import os
import time

# Config Paramters
CREDS_FILE     = "creds.json"
CREDS_DATA     = None

# A function to load CONFIG_DATA from file
def loadConfig():
    global CONFIG_DATA
    log("Loading config data...")

    # If we have a stored config file, then use it, otherwise create an empty one
    if os.path.isfile(CREDS_FILE):

        # Open the CONFIG_FILE and load it
        with open(CREDS_FILE, 'r') as creds_file:
            CONFIG_DATA = json.loads(creds_file.read())
        log("Config loading complete.")
    else:
        sys.stdout.write("Config file not found, please check creds.json is in your directory...")

# simple logger function
def log(message):
    sys.stdout.write(message)
    sys.stdout.write("\n")

def download_policy_xml():
    # Setup AMP for Endpoints session and auth
    session = requests.session()
    session.auth = (CONFIG_DATA["amp_client_id"], CONFIG_DATA["amp_api_key"])

    # Policies URL
    url = f'https://{CONFIG_DATA["amp_host"]}/v1/policies'

    # Get First page of Polices
    response = session.get(url)

    # error checking
    if response.status_code != 200:
        log(f"Error occured (please check API keys), status code: {response.status_code}")
        sys.exit()

    # Decode JSON response
    response_json = response.json()

    # Store policy link, product, and name in a dict {'link' : 'product_name'}
    policies = {
        policy["links"]["policy"]: f'{policy["product"]}_{policy["name"]}'
        for policy in response_json["data"]
    }

    # Paginate if needed
    while 'next' in response_json['metadata']['links']:
        next_url = response_json['metadata']['links']['next']
        response = session.get(next_url)
        response_json = response.json()
        for policy in response_json['data']:
            # Store link, product, and name in existing dictionary
            policies[policy['links']['policy']] = f'{policy["product"]}_{policy["name"]}'

    # Build absolute path for 'policies' dir
    output_path = os.path.join(path, 'policies')

    # Check if output_path exists, create if not
    if not os.path.exists(f'{output_path}'):
        os.makedirs(f'{output_path}')

    log(f'Number of polices found: {len(policies)}')

    # Iterate over policies, download and save the XML to disk
    for count, (policy_link, name) in enumerate(policies.items(), start=1):
        guid = policy_link.split('/')[-1]
        log(f'XML downloaded [{(len(policies)+1)-count }]: {name}_{guid}.xml')
        response = session.get(f'{policy_link}.xml')
        with open(f'{output_path}/{name}_{guid}.xml', 'w') as f:
            f.write(response.text)

# function to parse the XML file, make sure it is in the same directory, or prepend the path
def XML_parser(XML_file_name):
    XML_file = open(f"policies/{XML_file_name}", "r")

    if XML_file:
        # user feedback
        log("\nXML file successfully opened!") 
    else:
        log("error while opening XML file")
        return
    
    # parse XML file
    tree = ET.parse(XML_file)

    # user feedback
    if tree:
        log("XML file successfully parsed to dictionary!") 
    else:
        log("error while parsing XML file")
        return    
    
    # empty list for exclusions
    exclusion_list = []

    # Build absolute path for 'policies' dir
    output_path = os.path.join(path, 'exclusions')

    # Check if output_path exists, create if not
    if not os.path.exists(f'{output_path}'):
        os.makedirs(f'{output_path}')
    
    # create text file
    TXT_file = open(f"exclusions/{XML_file_name[:-4]}.txt", "w+")

    for info_items in tree.iter('{http://www.w3.org/2000/09/xmldsig#}info'):
        for item in info_items:
            # removing the piped flags up front
            # for future reference: 1 = Object is a threat detection name 2 = object is a folder path 3 = object is a file extention 4 = object is a file name 5 = object is a process 6 = object is a regular expression
            str_item = str(item.text)
            split_item = str_item[10:]
            exclusion_list.append(split_item)
            
            # write to file
            TXT_file.write(f"{split_item}\n")

    for process_items in tree.iter('{http://www.w3.org/2000/09/xmldsig#}process'):
        for item in process_items:
            # removing the piped flags up front
            str_item = str(item.text)
            split_item = str_item[5:]
            exclusion_list.append(split_item)
            
            # write to file
            TXT_file.write(f"{split_item}\n")
    
    return exclusion_list


if __name__ == "__main__":
    # Get script file path
    path = os.path.dirname(os.path.realpath(__file__))

    # set credentials
    loadConfig()

    # first download and/or update all the policies available
    if input("Download/update all policy XML files before parsing? (yes/no): ").lower() == "yes": 
        download_policy_xml()
    else:
        log("Skipping downloads...")

    # prompt user which policy to use for exclusions
    XML_file_name = input("Please provide the policy XML containing the custom exclusions you would like to parse (e.g. ios_Audit_e1241826-0d35-4231-b521-28432f437950.xml): ")
    if XML_file_name != "":
        exclusion_list = XML_parser(XML_file_name)
        if exclusion_list != 0:
            log("\nExclusions parsed, please copy paste items below into **Add Multiple Exclusions** pane in AMP GUI:\n")
            log(f"A **exclusions/{XML_file_name}.txt** file is also created for you with the same content.\n")
            time.sleep(2)
            for exclusion in exclusion_list:
                log(exclusion)
    else:
        log("No policy selected...")

