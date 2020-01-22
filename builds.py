#!/usr/bin/env python3

# Copyright (C) Daniel Carter 2019
# Licensed under the 2-clause BSD licence

# Tool to analyse Device Analyzer data and save it in more easily readable formats

import os
import gzip
import re
import json
from collections import defaultdict, OrderedDict
import heapq
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

class Device:
    global_release_first_seen = dict()

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
            # Set global_release_first_seen to have the first time this release was seen on any phone
            if (release not in Device.global_release_first_seen) or (Device.global_release_first_seen[release] > date):
                Device.global_release_first_seen[release] = date
        device.min_date = datetime.strptime(data['min_date'], '%Y-%m-%d').date()
        device.max_date = datetime.strptime(data['max_date'], '%Y-%m-%d').date()
        return device

    @staticmethod
    def check_regex(regex, version):
        """Check whether an Android version matches the provided regex"""
        os_version = version.split(' ')[0]
        os_version = os_version.split('-')[0]
        # If a version number is incomplete, extend it with zeros (e.g. 8 -> 8.0.0)
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
        # Update details of when this build was first seen
        if (version not in self.release_first_seen) or (self.release_first_seen[version] > date):
            self.release_first_seen[version] = date
        if (version not in Device.global_release_first_seen) or (Device.global_release_first_seen[version] > date):
            Device.global_release_first_seen[version] = date
        # Keep track of how long the device itself was in use
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
            # No version applicable as device wasn't in use on this date
            return None
        if str(date) in self.records:
            # Version recorded on this date
            return self.records[str(date)]
        # If nothing recorded on this date, but two dates either side have the same version number, then use that
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
        # Otherwise, we don't know when it was updated
        return None

    def short_version_on(self, date):
        """Returns the version number only (i.e. not the build string)"""
        version = self.version_on(date)
        if version is None:
            return None
        return version.split(' ')[0].split('-')[0].split('_')[0]

    def released_after(self, version, date):
        """Checks whether a given build was released after a given date"""
        if version not in self.release_first_seen:
            # Version never ran on this device
            return None
        return self.release_first_seen_seen[version] > date

    def vulnerable_on(self, date, vulnerability, global_version_list=True):
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
        global_release_date = Device.global_release_first_seen[version]
        if vulnerability.exploitable_on(global_release_date, consider_fixes=False):
            # Vulnerability had been discovered when this build was released,
            # so there may be a backported fix
            return VulnerabilityStatus.MAYBE
        if not global_version_list and vulnerability.exploitable_on(release_date, consider_fixes=False):
            # This build was first recorded on this device after the vulnerability
            # was discovered, so there may be a backported fix
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
        # Start by loading in pre-processed devices
        get_devices_from_file()
    start = len(_devices)
    if MAXLEN > 0 and start > MAXLEN:
        # If we now have enough devices, stop there
        return _devices[:MAXLEN]
    if start < MAXLEN or MAXLEN == -1:
        # If we don't have enough, start loading in from raw data
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
                    # Need to get an os_string and build number that are close enough together in time
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
                        # Read next line of file
                        content = infile.readline()
                    pprint.pprint(device.release_first_seen)
                    _devices.append(device)
            except EOFError:
                print('Invalid file:', dump)
                continue
        # Save processed data out to new JSON file
        if len(dumps) > 0: # Don't rewrite file if we didn't change it
            save_devices_to_file()
    return _devices

def get_model_details(device_id):
    """Given a device id, gets the manufacturer and model"""
    with gzip.open(PATH+device_id, 'rt') as infile:
        content = infile.readline()
        manufacturer = None
        model = None
        while content:
            if ';system|manufacturer;' in content:
                items = content.strip('\n').split(';')
                manufacturer = items[4]
            elif ';system|model;' in content:
                items = content.strip('\n').split(';')
                model = items[4]
            # Exit if we have all details
            if manufacturer is not None and model is not None:
                return manufacturer + " " + model
            # Otherwise, read next line of file
            content = infile.readline()
    return None

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
            # For the purposes of JSON export, need strings rather than datetime objects as keys
            figures_per_date[str(date)] = number_per_status_type
        else:
            figures_per_date[date] = number_per_status_type
    return figures_per_date

def analyse_vulnerability_exploits(vulnerabilities, dates, string_keys=False, stratified=False):
    """Get the number of devices by exploits possible on those devices, on each of the dates passed"""
    devices = _get_devices()
    score_per_date = dict()
    for date in dates:
        if stratified:
            number_per_score = defaultdict(lambda: defaultdict(int))
        else:
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
            strictgraph = strictify(graph)
            graph.close() # Otherwise we leak memory
            graph = strictgraph
            # Find greatest possible exploit
            score = get_score(graph)
            if stratified:
                # If stratified, output separate statistics for each version on each date
                version = device.short_version_on(date)
                if version is not None:
                    number_per_score[version][score] += 1
            else:
                number_per_score[score] += 1
            graph.close() # Otherwise we leak memory
        if string_keys:
            score_per_date[str(date)] = number_per_score
        else:
            score_per_date[date] = number_per_score
    return score_per_date

def most_updates(n):
    """Gets a list of the devices with the most updates recorded across the time period"""
    devices = _get_devices()
    return heapq.nlargest(n, devices, key=(lambda x:len(x.release_first_seen)))

def merge_usage_periods(periods, new_period):
    """Merge a time period into an existing set of usage periods"""
    outlist = []
    for period in periods:
        if new_period[0] > period[1]:
            # No overlap - past the end
            outlist.append(period)
            continue
        if new_period[1] < period[0]:
            # No overlap - before the beginning
            outlist.append(period)
            continue
        # There must now be some overlap
        merged = True
        if new_period[0] < period[0]:
            period[0] = new_period[0]
        if new_period[1] > period[1]:
            period[1] = new_period[1]
        new_period = period

    outlist.append(new_period)
    return outlist

def update_patch_dict(dict1, dict2):
    """Update the patch dictionary (dict1) with values from dict2, keeping the older date for any vulnerability"""
    for build, build_date in dict2.items():
        if build in dict1:
            if build_date < dict1[build]:
                dict1[build] = build_date
        else:
             dict1[build] = build_date

def by_updates_random_set(n):
    """Gets a random set of n devices, sorted by number of recorded updates"""
    # Remove devices with no version information, then take the first n from the list
    devices = [device for device in _get_devices() if len(device.release_first_seen) != 0][:n]
    models = dict()
    for device in devices:
        model = get_model_details(str(device))
        if model not in models:
            details = dict()
            # Period this device was in use
            details['usage_periods'] = [[device.min_date, device.max_date]]
            # Set of new releases
            details['patch_dates_dict'] = device.release_first_seen
            # Number of devices of this model
            details['device_count'] = 1
            models[model] = details
        else:
            updated_usage = merge_usage_periods(models[model]['usage_periods'], [device.min_date, device.max_date])
            models[model]['usage_periods'] = updated_usage
            update_patch_dict(models[model]['patch_dates_dict'], device.release_first_seen)
            models[model]['device_count'] += 1

    for model, model_dict in models.items():
        model_dict['usage_periods'].sort()
        # Only keep the patch dates, not the build numbers they relate to
        model_dict['patch_dates'] = sorted(models[model]['patch_dates_dict'].values())
        del model_dict['patch_dates_dict']
    return models

if __name__ == '__main__':
    print("Loading data and saving output")
    _get_devices()
    devices_out = by_updates_random_set(10000)
    sorted_devices = OrderedDict(sorted(devices_out.items(), key=lambda kv: kv[1]['device_count'], reverse=True)[:50])
    with open('data/device_patch_list.json', 'w') as f:
        json.dump(sorted_devices, f, indent=2, default=str)

