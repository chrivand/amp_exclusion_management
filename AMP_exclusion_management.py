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
    
    # create text file without exclusion type for copy pasting
    TXT_file_copy = open(f"exclusions/{XML_file_name[:-4]}_for_copying.txt", "w+")

    # create text file with exclusion type for checking
    TXT_file_check = open(f"exclusions/{XML_file_name[:-4]}_for_checking.txt", "w+")

    for info_items in tree.iter('{http://www.w3.org/2000/09/xmldsig#}info'):
        for item in info_items:
            # removing the piped flags up front
            str_item = str(item.text)
            split_item = str_item.split("|")
            # check if all items were found, otherwise skip item
            if len(split_item) != 5:
                continue
            
            # add to list
            exclusion_list.append(split_item[4])
            
            # write to file
            TXT_file_copy.write(f"{split_item[4]}\n")

            # write to file with exclusion type for checking
            if split_item[1] == "1":
                TXT_file_check.write(f"Threat - {split_item[4]}\n")
            elif split_item[1] == "2":
                TXT_file_check.write(f"Path - {split_item[4]}\n")
            elif split_item[1] == "3":
                TXT_file_check.write(f"File Extension - {split_item[4]}\n")
            elif split_item[1] == "4":
                TXT_file_check.write(f"File Name - {split_item[4]}\n")
            elif split_item[1] == "5":
                TXT_file_check.write(f"Process - {split_item[4]}\n")
            elif split_item[1] == "6":
                TXT_file_check.write(f"RegEx - {split_item[4]}\n")

    for process_items in tree.iter('{http://www.w3.org/2000/09/xmldsig#}process'):
        for item in process_items:
            # removing the piped flags up front and back
            str_item = str(item.text)
            split_item = str_item.split("|")
            # check if all items were found, otherwise skip item
            if len(split_item) != 6:
                continue
     
            # add to list
            exclusion_list.append(split_item[3])
            
            # write to file
            TXT_file_copy.write(f"{split_item[3]}\n")

            # write to file with exclusion type for checking
            if split_item[4] == "1":
                TXT_file_check.write(f"PROCESS Scan Child - {split_item[3]}\n")
            elif split_item[4] == "2":
                TXT_file_check.write(f"PROCESS Written Files - {split_item[3]}\n")
            elif split_item[4] == "4":
                TXT_file_check.write(f"PROCESS Self-Protect Engine - {split_item[3]}\n")
            elif split_item[4] == "8":
                TXT_file_check.write(f"PROCESS Child - {split_item[3]}\n")
            elif split_item[4] == "32":
                TXT_file_check.write(f"PROCESS Heuristic - {split_item[3]}\n")
            elif split_item[4] == "64":
                TXT_file_check.write(f"PROCESS SFP Rules - {split_item[3]}\n")
            elif split_item[4] == "128":
                TXT_file_check.write(f"PROCESS SFP Rules Child - {split_item[3]}\n")
            else:
                TXT_file_check.write(f"PROCESS - {split_item[3]}\n")
                
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
        if len(exclusion_list) == 0:
            log(f"\nNo exclusions parsed, please check {XML_file_name} policy file...\n")
        else:
            log("\nExclusions parsed:\n")
            time.sleep(1)
            for exclusion in exclusion_list:
                log(exclusion)
            time.sleep(1)
            log(f"\nA **exclusions/{XML_file_name}_for_copying.txt** file is also created for you with the same content.\n")
            log("Please copy paste those items from txt file into **Add Multiple Exclusions** pane in AMP GUI\n")
            log(f"A **exclusions/{XML_file_name}_for_checking.txt** file is also created for you containing the Exclusion Type to double check your copied entries.\n")

    else:
        log("No policy selected...")

