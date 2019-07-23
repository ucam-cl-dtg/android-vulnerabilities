from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException
from datetime import datetime, date
import sys
import os
import utils
import json
from collections import defaultdict
import re
import urllib.request
import pprint

MANUAL_KEYS = ['Surface', 'Vector', 'Target', 'Channel', 'Condition', 'Privilege']
NIST_URL = 'https://nvd.nist.gov/vuln/data-feeds'

def get_subnode(node, key):
    """Returns the requested value from a dictionary, while ignoring null values"""
    if node == None:
        return None
    return node[key]

def load_from_year(year, cves):
    """Loads descriptions from the NIST data for all vulnerabilities in a given year"""
    path = 'cve-data/nvdcve-1.0-{year}.json'.format(year=year)
    descriptions = dict()
    with open(path, 'r') as f:
        items = json.load(f)['CVE_Items']
        if items != None:
            for item in items:
                cve_object = get_subnode(item, 'cve') 
                cve_data = get_subnode(cve_object, 'CVE_data_meta')
                cve = get_subnode(cve_data, 'ID')
                if cve in cves:
                    description_data = get_subnode(get_subnode(cve_object, 'description'), 'description_data')
                    if description_data != None and len(description_data) > 0:
                        value = get_subnode(description_data[0], 'value')
                        descriptions[cve] = value
    return descriptions

def get_descriptions(cves):
    """Loads vulnerability descriptions from the NIST data"""
    descriptions = dict()
    cve_years = defaultdict(list)
    for cve in cves:
        year = cve.split('-')[1]
        cve_years[year].append(cve)

    for year, cves in cve_years.items():
        descriptions.update(load_from_year(year, set(cves)))
    return descriptions

def load_date_from_commit(url):
    """Given the URL of a commit identifier, returns the date of the commit"""
    if 'googlesource.com' in url:
        with urllib.request.urlopen(url + '?format=JSON') as url:
            data = json.loads(url.read().decode())
            time_string = data['author']['time']
            time = datetime.strptime(time_string, '%a %b %d %H:%M:%S %Y %z')
            # Return only the date, not the time
    # MORE TO DO HERE
    raise Exception

def load_manual_data(cve):
    """Returns manually entered data on the vulnerability, to be combined with automatically scraped data"""
    path = 'manual-data/{cve}.json'.format(cve=cve)
    data = dict()
    if os.path.isfile(path):
        with open(path, 'r') as f:
            rjson = json.load(f)
            for key, value in rjson.items():
                data[key] = value
    return data

def write_manual_data(cve, data):
    """Writes manually entered data out to a file"""
    with open('manual-data/{cve}.json'.format(cve=cve), 'w') as f:
        json.dump(data, f, indent=2)

def write_data(cve, data):
    """Writes all data out to a file"""
    with open('data/{cve}.json'.format(cve=cve), 'w') as f:
        json.dump(data, f, indent=2)

def make_reference(url):
    """Creates a reference object (stored as a dictionary) for a given URL"""
    ref_dict = dict()
    ref_dict['url'] = url
    return ref_dict

def regexp_versions(versions_string):
    """Converts the list of versions from the bulletin data into a regexp"""
    if len(versions_string) == 0:
        return ''
    versions = versions_string.replace(' ', '').replace('.', '\\.').split(',')
    regexp = ''
    for version in versions:
        dots = version.count('.')
        if dots == 2:
            regexp += ('(' + version + ')|')
        elif dots == 1:
            regexp += ('(' + version + '\\.[0-9])|')
        elif dots == 0:
            regexp += ('(' + version + '\\.[0-9]\\.[0-9])|')
        else:
            raise ValueError('Invalid version string provided')
    return regexp[:-1]

def check_blank(text, ref):
    """Formats a data-reference pair and avoids references being given to blank data items"""
    if text == '':
        return []
    return [[text, ref]]

def write_data_for_website(cve, data):
    """Process data and write out to a JSON file suitable for loading into androidvulnerabilities.org"""
    export = dict()

    ref_out = dict()
    for key, value in (data['References']).items():
        if key != '*':
            ref_out[key] = value
    nist_ref = 'NIST-' + cve
    ref_out[nist_ref] = make_reference(NIST_URL)
    bulletin_ref = 'Bulletin-' + cve
    ref_out[bulletin_ref] = make_reference(data['URL'])
    
    export['name'] = cve
    export['CVE'] = [[cve, bulletin_ref]]
    # Slightly different categories than in original set, but still usable
    export['Categories'] = [data['Category']]
    export['Details'] = check_blank(data['Description'], nist_ref)
    # Discovered by
    # Discovered on
    export['Submission'] = data['Submission']
    # Reported on
    # Fixed on
    # Fix released on
    export['Affected_versions'] = check_blank(data['Updated AOSP versions'], bulletin_ref)
    # Affected devices
    export['Affected_versions_regexp'] = [regexp_versions(data['Updated AOSP versions'])]
    if 'Qualcomm' in data['Category']:
        export['Affected_manufacturers'] = [['Qualcomm', bulletin_ref]]
    elif 'NVIDIA' in data['Category']:
        export['Affected_manufacturers'] = [['NVIDIA', bulletin_ref]]
    else:
        # If it's not Qualcomm or NVIDIA, assume for this purposes that all other vulnerabilities affect all phones
        export['Affected_manufacturers'] = [['all', bulletin_ref]]
    export['Fixed_versions'] = check_blank(data['Updated AOSP versions'], bulletin_ref)
    export['references'] = data['References']
    export['Surface'] = data['Surface']
    export['Vector'] = data['Vector']
    export['Target'] = data['Target']
    export['Channel'] = data['Channel']
    export['Condition'] = data['Condition']
    export['Privilege'] = data['Privilege']
    
    with open('website-data/{cve}.json'.format(cve=cve), 'w') as f:
        json.dump(export, f, indent=2)

def parse_references(table_cell):
    """Parse the contents of a table cell and produce a reference dictionary"""
    ref_data = dict()
    # Take references which link to URLs
    refs = table_cell.find_elements_by_tag_name('a')
    for ref in refs:
        text = ref.get_attribute('innerHTML').replace('\n', ' ')
        if text != '*':
            url = make_reference(ref.get_attribute('href'))
            ref_data[text] = url

    # Strip out links, line breaks and square brackets, and take the remaining sections of the string as references
    regex = r'(\<a(.*?)\>(.*?)\<\/a\>)|(\<br\>)|(\n)|\[|\]'

    contents = table_cell.get_attribute('innerHTML')
    text_items = re.sub(regex, ' ', contents).split()
    for item in text_items:
        ref_data[item] = make_reference('N/A')

    return ref_data

def process_table(table, category, source_url):
    """Produce a list of dictionaries of vulnerabilities from an HTML table"""
    rows = table.find_elements_by_tag_name('tr')
    headers = []
    for header in table.find_elements_by_tag_name('th'):
        headers.append(header.get_attribute('innerHTML'))

    table_data = dict()
    cve = None
    # Exclude the top (title) row
    for row in rows[1:]:
        row_data = defaultdict(str)
        # Find each cell of the table
        items = row.find_elements_by_tag_name('td')
        if(len(items) != len(headers)):
            raise Exception("Invalid table")
        for (header, item) in zip(headers, items):
            if header == 'References':
                row_data['References'] = parse_references(item)
            else:
                row_data[header] = item.get_attribute('innerHTML')
                if header == 'CVE':
                    cve = row_data['CVE']

        if cve != None:
            row_data['Category'] = category
            row_data['URL'] = source_url
            table_data[cve] = row_data

    return table_data

def get_submitter_name():
    """Loads the submitter's name in from a file if the file exists, or prompts for it otherwise"""
    if os.path.isfile('submitter'):
        with open('submitter', 'r') as f:
            return f.readline().strip()
    else:
        return input("Enter the name to record submissions under...")

# Setup
driver = utils.getDriver()
vulnerabilities = dict()

# Submission details
submission = dict()
submission['by'] = get_submitter_name()
submission['on'] = date.today().strftime('%Y-%m-%d')

for month in range(1, 8):
    url = 'https://source.android.com/security/bulletin/2019-{:02d}-01.html'.format(month)
    utils.fetchPage(driver, url)

    contents = driver.find_elements_by_xpath('//devsite-heading | //div[@class="devsite-table-wrapper"]/table')

    title = None

    for item in contents:
        if item.get_attribute('level') == 'h3':
            # If item is a title
            title = item.get_attribute('text').replace('\n', ' ')
        elif title != None:
            # If item is a table, and there hasn't been a table since the last title
            vulnerabilities.update(process_table(item, title, url))
            title = None

descriptions = get_descriptions(vulnerabilities.keys())
for cve in descriptions.keys():
    vulnerabilities[cve]['Description'] = descriptions[cve]

#pprint.pprint(vulnerabilities)

for cve, vulnerability in vulnerabilities.items():
    pprint.pprint(vulnerability)
    if(vulnerability['Severity'] == 'Critical'):
        # If no stored submission date, assume today
        manual_data = load_manual_data(cve)
        if 'Submission' not in manual_data.keys()
        manual_data['Submission'] = submission
        for key in MANUAL_KEYS:
            if key not in manual_data.keys():
                entered = input("Enter {key}: ".format(key=key))
                if entered != '':
                    value = entered.split(',')
                else:
                    value = []
                manual_data[key] = value
        vulnerability.update(manual_data)
        write_manual_data(cve, manual_data)
        write_data_for_website(cve, vulnerability)

    write_data(cve, vulnerability)

utils.quitDriver(driver)
