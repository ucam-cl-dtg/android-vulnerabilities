import os
import gzip
import re
import json
from collections import defaultdict
import pprint
from bisect import bisect_left
from datetime import datetime, date, timedelta
from enum import Enum

import pygraphviz as pgv

from tools.graph_analyser.graph_utils import strictify, get_score, add_backwards_edges

class VulnerabilityStatus(Enum):
    NOT_IN_USE = -1
    NOT_VULNERABLE = 0
    MAYBE = 1
    VULNERABLE = 2

class Vulnerability:
    # Test class - can probably be removed
    def __init__(self, version_regex, discovery_date):
        self.version_regex = version_regex
        self.discovery_date = discovery_date

    def exploitable_on(self, date, consider_fixes=False):
        return date > self.discovery_date

    def regex(self):
        return self.version_regex

    def manufacturers(self):
        return [['all']]

    def is_backportable(self):
        return True

class Device:
    def __init__(self, device_id):
        """Sets up a device object for OS details to be loaded into"""
        self.device_id = device_id
        self.records = dict()
        self.release_first_seen = dict()
        self.min_date = date.max
        self.max_date = date.min

    def __str__(self):
        return self.device_id

    def dict_export(self):
        """Returns a dictionary object containing the details of the device"""
        export = dict()
        export['device_id'] = self.device_id
        export['records'] = self.records
        export['release_first_seen'] = self.release_first_seen
        export['min_date'] = self.min_date
        export['max_date'] = self.max_date
        return export

    @staticmethod
    def dict_import(data):
        """Returns a Device object created from the dictionary passed"""
        device = Device(data['device_id'])
        device.records = data['records']
        device.release_first_seen = data['release_first_seen']
        for release, sdate in device.release_first_seen.items():
            date = datetime.strptime(sdate, '%Y-%m-%d').date()
            device.release_first_seen[release] = date
        device.min_date = datetime.strptime(data['min_date'], '%Y-%m-%d').date()
        device.max_date = datetime.strptime(data['max_date'], '%Y-%m-%d').date()
        return device

    @staticmethod
    def check_regex(regex, version):
        """Check whether an Android version matches the provided regex"""
        os_version = version.split(' ')[0]
        os_version = os_version.split('-')[0]
        dots = os_version.count('.')
        if dots > 2:
            raise Exception('Invalid version string: ' + os_version)
        while dots < 2:
            os_version += '.0'
            dots = os_version.count('.')
        return re.match(regex, os_version)

    def add_record(self, date, osstring, build):
        """Add details of an build seen on a particular date"""
        version = str(osstring) + " : " + str(build)
        if (version not in self.release_first_seen) or (self.release_first_seen[version] > date):
            self.release_first_seen[version] = date
        if date < self.min_date:
            self.min_date = date
        if date > self.max_date:
            self.max_date = date
        self.records[str(date)] = version

    def in_use_on(self, date):
        """Returns a boolean indicating whether a date falls inside the device's usage period"""
        if self.min_date <= date <= self.max_date:
            return True
        return False

    def version_on(self, date):
        """Return the version in use on a particular date"""
        if not self.in_use_on(date):
            return None
        if str(date) in self.records:
            return self.records[str(date)]
        prev_date = date
        while str(prev_date) not in self.records:
            prev_date -= timedelta(days=1)
        prev_version = self.records[str(prev_date)]
        future_date = date
        while str(future_date) not in self.records:
            future_date += timedelta(days=1)
        future_version = self.records[str(future_date)]
        if prev_version == future_version:
            return prev_version
        return None

    def released_after(self, version, date):
        """Checks whether a given build was released after a given date"""
        if version not in self.release_first_seen:
            return None
        return self.release_first_seen_seen[version] > date

    def vulnerable_on(self, date, vulnerability):
        """Checks whether the device was vulnerable to a particular vulnerability on a particular date"""
        version = self.version_on(date)
        if version is None:
            # No records for the device on this date
            return VulnerabilityStatus.NOT_IN_USE
        if 'all' not in map(lambda x: x[0], vulnerability.manufacturers()):
            # For now, only consider vulnerabilities affecting all manufacturers
            # TODO: add support for manufacturer-specific vulnerabilities
            return VulnerabilityStatus.NOT_VULNERABLE
        release_date = self.release_first_seen[version]
        if not self.check_regex(vulnerability.regex(), version):
            # Device's OS version is not affected
            return VulnerabilityStatus.NOT_VULNERABLE
        if not vulnerability.exploitable_on(date, consider_fixes=False):
            # Vulnerability hadn't been discovered yet
            return VulnerabilityStatus.NOT_VULNERABLE
        if not vulnerability.is_backportable():
            # For special cases (e.g. SELinux "vulnerability")
            return VulnerabilityStatus.VULNERABLE
        if vulnerability.exploitable_on(release_date, consider_fixes=False):
            # Vulnerability had been discovered when this build was released,
            # so there may be a backported fix
            return VulnerabilityStatus.MAYBE
        return VulnerabilityStatus.VULNERABLE

    def vulnerability_graph_lines(self, date, vulnerability):
        """Get the (GraphViz-format) graph lines representing a particlar vulnerability on this device"""
        status = self.vulnerable_on(date, vulnerability)
        if status != VulnerabilityStatus.VULNERABLE:
            return ''
        # Only take the actual graph lines, not the set of reached points
        lines = map(lambda x: x.get_string(), vulnerability.graphLines(False)[0])
        result = '\n'.join(lines)
        return result

PATH = '../../../export-2019-04-20/fixed-output/'
JSON_PATH = 'data/devices.json'
TIME_GAP = timedelta(hours=1)
# Number of device records to take from the file (-1 for no limit)
MAXLEN = 10000

_devices = None

def parse_line(line):
    """Get the date and information from a log file line"""
    line = line.strip('\n')
    items = line.split(';')
    if items[2] == '(invalid date)':
        date = None
    else:
        date = datetime.strptime(items[2], '%Y-%m-%dT%H:%M:%S.%f%z').date()
    data = items[4]
    return date, data

def times_within(time1, time2, gap):
    """Checks whether the gap between two times is less than gap"""
    if time1 is None or time2 is None:
        return None
    return abs(time1 - time2) < gap

def save_devices_to_file():
    """Save a set of analysed devices to a JSON file"""
    global _devices
    output = dict()
    for device in _devices:
        output[str(device)] = device.dict_export()
    with open(JSON_PATH, 'w') as f:
        json.dump(output, f, indent=2, default=str)

def get_devices_from_file():
    """Load pre-analysed device data from a JSON file"""
    global _devices
    _devices = []
    with open(JSON_PATH, 'r') as f:
        rjson = json.load(f)
        for device in rjson.values():
            _devices.append(Device.dict_import(device))

def _get_devices():
    """Load devices in from analysing Device Analyzer data"""
    global _devices
    if _devices is None:
        #_devices = []
        get_devices_from_file()
    start = len(_devices)
    if start < MAXLEN or MAXLEN == -1:
        dumps = os.listdir(PATH)
        if MAXLEN == -1:
            dumps = dumps[start:]
        else:
            dumps = dumps[start:MAXLEN]
        
        for index, dump in enumerate(dumps):
            try:
                with gzip.open(PATH+dump, 'rt') as infile:
                    device = Device(dump)
                    content = infile.readline()
                    os_string = ''
                    os_date = datetime(1970, 1, 1).date()
                    build_string = ''
                    build_date = datetime(1970, 1, 1).date()
                    os_string_found = False
                    while content:
                        if ';system|osstring;' in content:
                            if os_string_found and os_date != None:
                                device.add_record(os_date, os_string, None)
                            os_date, os_string = parse_line(content)
                            os_string_found = True
                        elif ';system|build|fingerprint;' in content:
                            build_date, build_string = parse_line(content)
                            if times_within(build_date, os_date, TIME_GAP):
                                device.add_record(build_date, os_string, build_string)
                                os_string_found = False
                        content = infile.readline()
                    pprint.pprint(device.release_first_seen)
                    _devices.append(device)
            except EOFError:
                print('Invalid file:', dump)
                continue
        save_devices_to_file()
    return _devices

def analyse_vulnerabilities(vulnerabilities, dates, string_keys=False):
    """Get the number of devices for each VulnerabilityStatus type, on each of the dates passed"""
    devices = _get_devices()
    figures_per_date = dict()
    for date in dates:
        number_per_status_type = defaultdict(int)
        for device in devices:
            # Start by assuming it's not in use
            status = VulnerabilityStatus.NOT_IN_USE
            for vulnerability in vulnerabilities:
                vulnerable = device.vulnerable_on(date, vulnerability)
                # If we get a "worse" status, then update to indicate the device is more vulnerable
                if vulnerable.value > status.value:
                    status = vulnerable
            # Store the number of devices which are of a particular status
            number_per_status_type[status] += 1
        if string_keys:
            figures_per_date[str(date)] = number_per_status_type
        else:
            figures_per_date[date] = number_per_status_type
    return figures_per_date

def analyse_vulnerability_exploits(vulnerabilities, dates, string_keys=False):
    """Get the number of devices by exploits possible on thos devices, on each of the dates passed"""
    devices = _get_devices()
    score_per_date = dict()
    for date in dates:
        number_per_score = defaultdict(int)
        for device in devices:
            if not device.in_use_on(date):
                continue
            # Construct a node-and-edge graph with edges from each vulnerability
            lines = 'digraph vulnerabilities {\n'
            for vulnerability in vulnerabilities:
                lines += device.vulnerability_graph_lines(date, vulnerability)
            lines += '}\n'
            graph = pgv.AGraph(string=lines)
            add_backwards_edges(graph)
            graph = strictify(graph)
            # Find greatest possible exploit
            number_per_score[get_score(graph)] += 1
        if string_keys:
            score_per_date[str(date)] = number_per_score
        else:
            score_per_date[date] = number_per_score
    return score_per_date
        

if __name__ == '__main__':
    # Loads vulnerabilities in up to the required amount, and saves them back to a file
    #demo_vulnerabilities = [Vulnerability('2\.[0-9]\.[0-9]', datetime(2012,1,1).date()), Vulnerability('4\.[0-9]\.[0-9]', datetime(2015,2,3).date())]
    #testdates = []
    #for year in range(2011, 2018):
    #    for month in range(1, 13):
    #        testdates.append(date(year, month, 1))
    print("Loading data and saving output")
    _get_devices()
    #get_devices_from_file()
    #print("Analysing vulnerabilities")
    #pprint.pprint(analyse_vulnerabilities(demo_vulnerabilities, testdates))
    #print("Saving devices")
    #save_devices_to_file()

