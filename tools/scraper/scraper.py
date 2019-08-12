# Copyright (C) Daniel Carter 2019
# Licenced under the 2-clause BSD licence

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
import copy
import pprint

MANUAL_KEYS = ['Surface', 'Vector', 'Target', 'Channel', 'Condition', 'Privilege']
MANUAL_KEYS_REQUIRED = {'Surface', 'Target', 'Channel', 'Condition', 'Privilege'}
NIST_URL = 'https://nvd.nist.gov/vuln/data-feeds'
KNOWN_MANUFACTURERS = {'Qualcomm', 'NVIDIA', 'Broadcom', 'LG', 'MediaTek', 'HTC'}
REFERENCE_REGEX = r'(References)|((Android )?bug\(?s?\)?( with AOSP link(s)?)?)'
VERSION_REGEX = r'(Updated|Affected) (AOSP )?versions'

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
        try:
            with urllib.request.urlopen(url + '?format=JSON') as source:
                src = source.read()[5:]
                data = json.loads(src.decode())
                time_string = data['author']['time']
                time = datetime.strptime(time_string, '%a %b %d %H:%M:%S %Y %z')
                return time.date()
        except urllib.error.HTTPError:
            # Dealing with the fact that Google's JSON links sometimes don't work
            utils.fetchPage(driver, url)
            rows = driver.find_elements_by_xpath('//div[contains(@class, "Metadata")]/table/tbody/tr')
            for row in rows:
                if row.find_element_by_tag_name('th').get_attribute('innerHTML') != 'author':
                    continue
                time_string = row.find_elements_by_xpath('./td')[1].get_attribute('innerHTML')
                time = datetime.strptime(time_string, '%a %b %d %H:%M:%S %Y %z')
                return time.date()
    elif 'codeaurora.org' in url or 'git.kernel.org' in url:
        utils.fetchPage(driver, url)
        rows = driver.find_elements_by_xpath('//table[@class="commit-info"]/tbody/tr')
        for row in rows:
            if row.find_element_by_tag_name('th').get_attribute('innerHTML') != 'author':
                continue
            time_string = row.find_element_by_xpath('./td[@class="right"]').get_attribute('innerHTML')
            time = datetime.strptime(time_string, '%Y-%m-%d %H:%M:%S %z')
            return time.date()
    elif 'github.com' in url:
        utils.fetchPage(driver, url)
        time_string = driver.find_element_by_xpath('//div[contains(@class, "commit-meta")]//relative-time').get_attribute('datetime')
        # Assuming the date is always in UTC (Z) - this is clumsy, but Python pre-3.7 doesn't have anything better
        time = datetime.strptime(time_string, '%Y-%m-%dT%H:%M:%SZ')
        return time.date()
    # If it's not one of these sources, we don't know
    raise Exception("Don't know how to deal with " + url)

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
    versions = versions_string.replace('and', ',').replace(' ', '').replace('.', '\\.').split(',')
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
    if text == None or text == '':
        return []
    return [[text, ref]]

def decode_lookup(key, dataset, description):
    """Convert a reference to a description to be used in data files"""
    if key in dataset:
        return dataset[key]
    else:
        decoded = input("Please enter {desc} for {key}: ".format(desc=description, key=key))
        dataset[key] = decoded
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
    discovery_ref = 'Discovery-' + cve
    ref_out[discovery_ref] = make_reference(data['Discovered_by_ref'])

    discovery_date = None
    if 'Date reported' in data:
        # Use the date it was reported to Google as the (approximate) date of discovery
        try:
            discovery_date = datetime.strptime(data['Date reported'], '%b %d, %Y').date().isoformat()
        except ValueError:
            pass

    # N.B. Report date is when it was first reported publicly
    report_date = re.search(r'[0-9]{4}-[0-9]{2}-[0-9]{2}(?=\.html)', data['URL'])
    
    export['name'] = cve
    export['CVE'] = [[cve, bulletin_ref]]
    # Coordinated disclosure
    export['Coordinated_disclosure'] = "unknown"
    # Slightly different categories than in original set, but still usable
    export['Categories'] = [data['Category']]
    export['Details'] = check_blank(data['Description'], nist_ref)
    # Discovered on
    export['Discovered_on'] = []
    export['Discovered_by'] = check_blank(data['Discovered_by'], discovery_ref)
    export['Submission'] = data['Submission']
    if report_date != None:
        export['Reported_on'] = [[report_date.group(), bulletin_ref]]
    else:
        export['Reported_on'] = []
    export['Fixed_on'] = check_blank(data['Fixed_on'], data['Fixed_on_ref'])
    export['Fix_released_on'] = check_blank(data['Fix_released_on'], bulletin_ref)
    export['Affected_versions'] = check_blank(data['Affected versions'], bulletin_ref)
    # Affected devices
    export['Affected_devices'] = []
    if 'Affected_versions_regexp' in data:
        export['Affected_versions_regexp'] = [data['Affected_versions_regexp']]
    else:
        export['Affected_versions_regexp'] = [regexp_versions(data['Affected versions'])]
    # Initially assume all devices are affected
    manufacturer_affected = 'all'
    for manufacturer in KNOWN_MANUFACTURERS:
        if manufacturer in data['Category']:
            # A specific manufacturer is named, so use that
            manufacturer_affected = manufacturer
    export['Affected_manufacturers'] = [[manufacturer_affected, bulletin_ref]]
    export['Fixed_versions'] = check_blank(data['Updated AOSP versions'], bulletin_ref)
    if 'Fixed_versions_regexp' in data:
        export['Fixed_versions_regexp'] = [data['Fixed_versions_regexp']]
    else:
        export['Fixed_versions_regexp'] = [regexp_versions(data['Updated AOSP versions'])]
    export['references'] = ref_out
    export['Surface'] = data['Surface']
    export['Vector'] = data['Vector']
    export['Target'] = data['Target']
    export['Channel'] = data['Channel']
    export['Condition'] = data['Condition']
    export['Privilege'] = data['Privilege']
    export['CWE'] = check_blank(data['CWE'], nist_ref)
    
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
    regex = r'(\<a(.*?)\>(.*?)\<\/a\>)|(\<br( *)\/?\>)|(\<\/?p\>)|(\n)|\[|\]'

    contents = table_cell.get_attribute('innerHTML')
    text_items = re.sub(regex, ' ', contents, flags=re.S).split()
    for item in text_items:
        ref_data[item] = make_reference(None)

    return ref_data

def merge_rows(row1, row2):
    """Merge two rows of the table of CVE data"""
    output = copy.deepcopy(row1)
    for key in row2:
        if key not in output:
            output[key] = row2[key]
        elif output[key] == row2[key]:
            continue
        elif key == 'References':
            output['References'].update(row2['References'])
        elif key == 'Severity':
            if output['Severity'] == 'Critical' or row2['Severity'] == 'Critical':
                output['Severity'] = 'Critical'
            else:
                output[key] = '{old}, {new}'.format(old=output[key], new=row2[key])
        else:
            output[key] = '{old}, {new}'.format(old=output[key], new=row2[key])
    return output

def process_table(table, category, source_url, date_fix_released_on):
    """Produce a list of dictionaries of vulnerabilities from an HTML table"""
    rows = table.find_elements_by_tag_name('tr')
    headers = []
    for header in table.find_elements_by_tag_name('th'):
        headers.append(header.get_attribute('innerHTML'))

    table_data = dict()
    multispans = dict()
    prev_row = None
    # Exclude the top (title) row
    for row in rows[1:]:
        row_data = defaultdict(str)
        # Find each cell of the table
        items = row.find_elements_by_tag_name('td')
        if(len(items) + len(multispans)) != len(headers):
            raise Exception("Invalid table")
        index = 0
        for row_header in headers:
            header = row_header.replace('*', '')
            if header in multispans:
                # Data from previous row needs to "spill over"
                row_data[header] = prev_row[header]
                multispans[header] -= 1
                if multispans[header] == 0:
                    del multispans[header]
            else:
                # Take the appropriate column of the table
                item = items[index]
                index += 1
                rowspan = item.get_attribute('rowspan')
                if rowspan != None and int(rowspan) > 1:
                    # This row needs to "spill over" into the next
                    multispans[header] = int(rowspan) -1

                if re.search(VERSION_REGEX, header, flags=re.I) != None:
                    # Do this in addition to loading the text directly below
                    row_data['Affected versions'] = item.get_attribute('innerHTML').strip()

                if re.search(REFERENCE_REGEX, header, flags=re.I) != None:
                    row_data['References'] = parse_references(item)
                elif header == 'Updated versions':
                    row_data['Updated AOSP versions'] = item.get_attribute('innerHTML').strip()
                else:
                    row_data[header] = item.get_attribute('innerHTML').strip()

        if 'CVE' in row_data:
            cve = row_data['CVE']
            row_data['Category'] = category
            row_data['URL'] = source_url
            row_data['Fix_released_on'] = date_fix_released_on
            if prev_row != None and prev_row['CVE'] == cve:
                row_data = merge_rows(prev_row, row_data)
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

def get_discoverer_data(driver, url):
    """Loads the list of people who have discovered bugs"""
    output = defaultdict(str)
    utils.fetchPage(driver, url)
    tables = driver.find_elements_by_xpath('//div[@class="devsite-table-wrapper"]/table')

    for table in tables:
        rows = table.find_elements_by_tag_name('tr')
        for row in rows:
            cells = row.find_elements_by_tag_name('td')
            if len(cells) < 2:
                # We're on the header row, which uses <th> elements, or an invalid row
                continue
            cves = cells[1].text.split(',')
            text = cells[0].text.strip()
            for cve in cves:
                output[cve.strip()] = text
    return output

# Setup
driver = utils.getDriver()
vulnerabilities = dict()

# Submission details
submission = dict()
submission['by'] = get_submitter_name()
submission['on'] = date.today().strftime('%Y-%m-%d')

# Fix release dates (done per bulletin)
fix_dates = dict()
today = date.today()

discoverer_url = 'https://source.android.com/security/overview/acknowledgements'
discoverers = get_discoverer_data(driver, discoverer_url)

for year in range(2015, (today.year)+1):
#for year in range(2015, 2018):
    fix_dates[year] = dict()
    urls = []

    url = 'https://source.android.com/security/bulletin/{year}'.format(year=year)
    utils.fetchPage(driver, url)
    table = driver.find_element_by_xpath('//div[@class="devsite-table-wrapper"]/table')
    rows = table.find_elements_by_tag_name('tr')

    for row in rows:
        cells = row.find_elements_by_tag_name('td')
        if len(cells) == 0:
            # We're on the header row, which uses <th> elements
            continue
        links = cells[0].find_elements_by_tag_name('a')
        if len(links) == 0:
            # No links in this cell, so skip it
            continue
        url = links[0].get_attribute('href')
        urls.append(url)

    for url in urls:
        date_string = re.search(r'\d{4}-\d{2}-\d{2}(?=\.html)', url).group()
        report_date = datetime.strptime(date_string, '%Y-%m-%d').date()
        utils.fetchPage(driver, url)

        month_fix_date = None
        search_exp = '{:d}-{:02d}-[0-9][0-9]'.format(report_date.year, report_date.month)
        date_para = driver.find_elements_by_xpath('//div[contains(@class, "devsite-article-body")]/p')[1]
        date_text = re.search(search_exp, date_para.get_attribute('innerHTML'))
        if date_text != None:
            month_fix_date = date_text.group()
            fix_dates[report_date.year][report_date.month] = month_fix_date

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
version_dataset = load_manual_data('attributes/versions')

# Store previous manual data set for quick repeat operations
prev_manual_data = None

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

        vulnerability['Discovered_by'] = discoverers[cve]
        vulnerability['Discovered_by_ref'] = discoverer_url

        # If fixed versions regexp is complicated, do it manually
        affected = vulnerability['Affected versions']
        if 'below' in affected or 'above' in affected:
            vulnerability['Affected_versions_regexp'] = decode_lookup(affected.strip(), version_dataset, 'regexp')

        fixed = vulnerability['Updated AOSP versions']
        if 'below' in fixed or 'above' in fixed:
            vulnerability['Fixed_versions_regexp'] = decode_lookup(fixed.strip(), version_dataset, 'regexp')


        pprint.pprint(vulnerability)

        # If no stored submission date, assume today
        manual_data = load_manual_data(cve)
        if 'Submission' not in manual_data.keys():
            manual_data['Submission'] = [submission]
        for key in MANUAL_KEYS:
            if key not in manual_data:
                if key in MANUAL_KEYS_REQUIRED:
                    entered = input("Enter {key}: ".format(key=key))
                    if entered == '^':
                        manual_data.update(prev_manual_data)
                    elif entered != '':
                        manual_data[key] = entered.split(',')
                    else:
                        manual_data[key] = []
                elif key == 'Vector':
                    cwe = vulnerability['CWE']
                    if cwe == '' or cwe == 'NVD-CWE-Other':
                        # No specific CWE, so ask each time
                        vector = input("Please enter vector for this vulnerability: ")
                        if vector == '':
                            manual_data['Vector'] = []
                        else:
                            manual_data['Vector'] = [vector]
                    else:
                        # Otherwise, as this is automatically generated, we don't add it to manual_data
                        vector = decode_lookup(cwe, cwe_dataset, 'vector')
                        if vector == '':
                            vulnerability['Vector'] = []
                        else:
                            vulnerability['Vector'] = [vector]
                else:
                    manual_data[key] = []

        write_manual_data(cve, manual_data)
        if 'References' in manual_data:
            vulnerability['References'].update(manual_data['References'])
            del manual_data['References']
        vulnerability.update(manual_data)
        prev_manual_data = manual_data
        write_data_for_website(cve, vulnerability)

    write_data(cve, vulnerability)

@atexit.register
def cleanup():
    # Write datasets back to disk
    write_manual_data('attributes/cwe', cwe_dataset)
    write_manual_data('attributes/versions', version_dataset)
    utils.quitDriver(driver)
