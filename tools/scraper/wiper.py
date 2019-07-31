import os
import json
import sys

def load_manual_data(cve):
    """Returns manually entered data on the vulnerability, to be combined with automatically scraped data"""
    path = 'manual-data/{cve}'.format(cve=cve)
    data = dict()
    if os.path.isfile(path):
        with open(path, 'r') as f:
            rjson = json.load(f)
            for key, value in rjson.items():
                data[key] = value
    return data

def write_manual_data(cve, data):
    """Writes manually entered data out to a file"""
    with open('manual-data/{cve}'.format(cve=cve), 'w') as f:
        json.dump(data, f, indent=2)


print('This program will erase data fields from the manual data files. Please use with care')
key = input('Please enter the field to erase: ')
print('Set to erase ' + key)
response = input('Do you want to continue? (y/n) ')
if response != 'y':
    sys.exit(0)

for filename in os.listdir('manual-data/'):
    if filename != 'attributes':
        print(filename)
        data = load_manual_data(filename)
        del data[key]
        write_manual_data(filename, data)
        
