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
import atexit
import pprint

MANUAL_KEYS = ['Surface', 'Vector', 'Target', 'Channel', 'Condition', 'Privilege']
MANUAL_KEYS_REQUIRED = {'Surface', 'Target', 'Channel', 'Condition', 'Privilege'}
NIST_URL = 'https://nvd.nist.gov/vuln/data-feeds'
KNOWN_MANUFACTURERS = {'Qualcomm', 'NVIDIA', 'Broadcom', 'LG', 'MediaTek'}

def get_subnode(node, key):
    """Returns the requested value from a dictionary, while ignoring null values"""
    if node != None and key in node:
        return node[key]
    return None

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
                    #print("Processing " + cve)
                    cve_output_data = dict()
                    description_data = get_subnode(get_subnode(cve_object, 'description'), 'description_data')
                    if description_data != None and len(description_data) > 0:
                        value = get_subnode(description_data[0], 'value')
                        cve_output_data['Description'] = value
                    cwe_data = get_subnode(get_subnode(cve_object, 'problemtype'), 'problemtype_data')
                    if cwe_data != None and len(cwe_data) > 0:
                        cwe_description_data = get_subnode(cwe_data[0], 'description')
                        if cwe_description_data != None and len(cwe_description_data) > 0:
                            value = get_subnode(cwe_description_data[0], 'value')
                            cve_output_data['CWE'] = value
                    impact = get_subnode(item, 'impact')
                    baseMetricV3 = get_subnode(impact, 'baseMetricV3')
                    if baseMetricV3 != None:
                        cvssV3 = get_subnode(baseMetricV3, 'cvssV3')
                        cve_output_data['Attack_method'] = get_subnode(cvssV3, 'attackVector')
                    else:
                        baseMetricV2 = get_subnode(impact, 'baseMetricV2')
                        cvssV2 = get_subnode(baseMetricV2, 'cvssV2')
                        cve_output_data['Attack_method'] = get_subnode(cvssV2, 'accessVector')

                    descriptions[cve] = cve_output_data
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

def load_date_from_commit(url, driver):
    """Given the URL of a commit identifier, returns the date of the commit"""
    if 'googlesource.com' in url:
        with urllib.request.urlopen(url + '?format=JSON') as source:
            src = source.read()[5:]
            data = json.loads(src.decode())
            time_string = data['author']['time']
            time = datetime.strptime(time_string, '%a %b %d %H:%M:%S %Y %z')
            return time.date()
    elif 'codeaurora.org' in url:
        utils.fetchPage(driver, url)
        rows = driver.find_elements_by_xpath('//table[@class="commit-info"]/tbody/tr')
        for row in rows:
            if row.find_element_by_tag_name('th').get_attribute('innerHTML') != 'author':
                continue
            time_string = row.find_element_by_xpath('./td[@class="right"]').get_attribute('innerHTML')
            time = datetime.strptime(time_string, '%Y-%m-%d %H:%M:%S %z')
            return time.date()
    # If it's not one of these sources, we don't know
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
    if url != None:
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

def decode_cwe(cwe, dataset):
    """Convert a CWE reference to a vector description to be used in data files"""
    if cwe in dataset:
        return dataset[cwe]
    decoded = input("Please enter vector for {cwe}: ".format(cwe=cwe))
    dataset[cwe] = decoded
    return decoded

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

    report_date = re.search(r'[0-9]{4}-[0-9]{2}-[0-9]{2}(?=\.html)', data['URL'])
    
    export['name'] = cve
    export['CVE'] = [[cve, bulletin_ref]]
    # Slightly different categories than in original set, but still usable
    export['Categories'] = [data['Category']]
    export['Details'] = check_blank(data['Description'], nist_ref)
    # Discovered by
    # Discovered on
    export['Submission'] = data['Submission']
    if report_date != None:
        export['Reported_on'] = [[report_date.group(), bulletin_ref]]
    export['Fixed_on'] = [[data['Fixed_on'], data['Fixed_on_ref']]]
    export['Fixed_released_on'] = [[data['Fix_released_on'], bulletin_ref]]
    export['Affected_versions'] = check_blank(data['Updated AOSP versions'], bulletin_ref)
    # Affected devices
    export['Affected_versions_regexp'] = [regexp_versions(data['Updated AOSP versions'])]
    # Initially assume all devices are affected
    manufacturer_affected = 'all'
    for manufacturer in KNOWN_MANUFACTURERS:
        if manufacturer in data['Category']:
            # A specific manufacturer is named, so use that
            manufacturer_affected = manufacturer
    export['Affected_manufacturers'] = [[manufacturer_affected, bulletin_ref]]
    export['Fixed_versions'] = check_blank(data['Updated AOSP versions'], bulletin_ref)
    export['references'] = data['References']
    export['Surface'] = data['Surface']
    export['Vector'] = data['Vector']
    export['Target'] = data['Target']
    export['Channel'] = data['Channel']
    export['Condition'] = data['Condition']
    export['Privilege'] = data['Privilege']
    export['CWE'] = [data['CWE']]
    
    with open('website-data/{cve}.json'.format(cve=cve), 'w') as f:
        json.dump(export, f, indent=2)

def parse_references(table_cell):
    """Parse the contents of a table cell and produce a reference dictionary"""
    ref_data = dict()
    # Take references which link to URLs
    refs = table_cell.find_elements_by_tag_name('a')
    for ref in refs:
        text = ref.get_attribute('innerHTML').replace('\n', ' ').strip()
        if text != '*':
            url = make_reference(ref.get_attribute('href'))
            ref_data[text] = url

    # Strip out links, line breaks and square brackets, and take the remaining sections of the string as references
    regex = r'(\<a(.*?)\>(.*?)\<\/a\>)|(\<br( *)\/?\>)|(\n)|\[|\]'

    contents = table_cell.get_attribute('innerHTML')
    text_items = re.sub(regex, ' ', contents, flags=re.S).split()
    for item in text_items:
        ref_data[item] = make_reference(None)

    return ref_data

def process_table(table, category, source_url, date_fix_released_on):
    """Produce a list of dictionaries of vulnerabilities from an HTML table"""
    rows = table.find_elements_by_tag_name('tr')
    headers = []
    for header in table.find_elements_by_tag_name('th'):
        headers.append(header.get_attribute('innerHTML'))

    table_data = dict()
    multispans = dict()
    prev_row = None
    cve = None
    # Exclude the top (title) row
    for row in rows[1:]:
        row_data = defaultdict(str)
        # Find each cell of the table
        items = row.find_elements_by_tag_name('td')
        if(len(items) + len(multispans)) != len(headers):
            raise Exception("Invalid table")
        index = 0
        for header in headers:
            if header in multispans:
                # Data from previous row needs to "spill over"
                row_data[header] = prev_row[header]
                multispans[header] -= 1
                if multispans[header] == 0:
                    del multispans[header]
            else:
                item = items[index]
                index += 1
                rowspan = item.get_attribute('rowspan')
                if rowspan != None and int(rowspan) > 1:
                    # This row needs to "spill over" into the next
                    multispans[header] = int(rowspan) -1

                if header == 'References':
                    row_data['References'] = parse_references(item)
                else:
                    row_data[header] = item.get_attribute('innerHTML')

        if 'CVE' in row_data:
            cve = row_data['CVE']
            row_data['Category'] = category
            row_data['URL'] = source_url
            row_data['Fix_released_on'] = date_fix_released_on
            prev_row = row_data
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

# Fix release dates (done per bulletin)
fix_dates = dict()

report_day_of_month = 1
today = date.today()

for year in range(2018, (today.year)+1):
    fix_dates[year] = dict()
    for month in range(1, 13):
        if date(year, month, report_day_of_month) > today:
            break
        url = 'https://source.android.com/security/bulletin/{:d}-{:02d}-{:02d}.html'.format(year, month, report_day_of_month)
        utils.fetchPage(driver, url)

        month_fix_date = None
        search_exp = '{:d}-{:02d}-[0-9][0-9]'.format(year, month)
        date_para = driver.find_elements_by_xpath('//div[contains(@class, "devsite-article-body")]/p')[1]
        date_text = re.search(search_exp, date_para.get_attribute('innerHTML'))
        if date_text != None:
            month_fix_date = date_text.group()
            fix_dates[year][month] = month_fix_date

        contents = driver.find_elements_by_xpath('//devsite-heading | //div[@class="devsite-table-wrapper"]/table')

        title = None

        for item in contents:
            if item.get_attribute('level') == 'h3':
                # If item is a title
                title = item.get_attribute('text').replace('\n', ' ')
            elif title != None:
                # If item is a table, and there hasn't been a table since the last title
                vulnerabilities.update(process_table(item, title, url, month_fix_date))
                title = None

descriptions = get_descriptions(vulnerabilities.keys())
for cve in descriptions.keys():
    vulnerabilities[cve].update(descriptions[cve])

#pprint.pprint(vulnerabilities)

# Load datasets to give descriptions
cwe_dataset = load_manual_data('attributes/cwe')

for cve, vulnerability in vulnerabilities.items():
    if(vulnerability['Severity'] == 'Critical'):
        # Get the fix date
        # Using the latest date of any of the commits as "fixed" date
        fixed = None
        fixed_ref = None
        for ref_name, reference in vulnerability['References'].items():
            if 'url' in reference.keys():
                commit_date = load_date_from_commit(reference['url'], driver)
                if fixed == None or commit_date > fixed:
                    fixed = commit_date
                    fixed_ref = ref_name
        if fixed != None:
            vulnerability['Fixed_on'] = fixed.isoformat()
            vulnerability['Fixed_on_ref'] = fixed_ref

        pprint.pprint(vulnerability)

        # If no stored submission date, assume today
        manual_data = load_manual_data(cve)
        if 'Submission' not in manual_data.keys():
            manual_data['Submission'] = submission
        for key in MANUAL_KEYS:
            if key not in manual_data:
                if key in MANUAL_KEYS_REQUIRED:
                    entered = input("Enter {key}: ".format(key=key))
                    if entered != '':
                        value = entered.split(',')
                    else:
                        value = []
                    manual_data[key] = value
                elif key == 'Vector':
                    manual_data['Vector'] = [decode_cwe(vulnerability['CWE'], cwe_dataset)]
                else:
                    manual_data[key] = []
        vulnerability.update(manual_data)
        write_manual_data(cve, manual_data)
        write_data_for_website(cve, vulnerability)

    write_data(cve, vulnerability)

@atexit.register
def cleanup():
    # Write datasets back to disk
    write_manual_data('attributes/cwe', cwe_dataset)
    utils.quitDriver(driver)
