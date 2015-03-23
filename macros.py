#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Do the parsing required to get all the vulnerabilities as objects in
# memory so that we can generate the pages.

import sys
import json
import csv
import os
import dateutil.parser
import datetime
import re
import sre_constants
import numpy
from collections import defaultdict, OrderedDict
from uncertainties import ufloat
from math import sqrt

sys.path.append('')# So that we find latex_value
import latex_value
from latex_value import set_latex_value, num2word, try_shorten
latex_value.latex_value_filename('output/latex.tex')
latex_value.latex_value_prefix('avo')
sys.path.remove('')


def warning(*objs):
    print(*objs, file=sys.stderr)



python_export_file_contents = r'''#!/usr/bin/env python
# Exported data from androidvulnerabilities.org for easy inclusion in python scripts

import re
import dateutil.parser
import sre_constants
from collections import OrderedDict

def warning(*objs):
    print(*objs, file=sys.stderr)

key_vuln_labels = [('zergRush', '2011-10-06', 1.05, 0), ('APK duplicate file', '2013-02-18', 1.05, 0), ('vold asec', '2014-01-27', 1.05, 0)]
key_vuln_arrows =[('2011-10-06', 1.05), ('2013-02-18', 1.05), ('2014-01-27', 1.05)]

def expand_raw_vulnerabilities(rawvulns, vulns, vuln_nms):
    for versions, date, name, how_known in rawvulns:
        try:
            vulns.append((re.compile("\A(%s)$"%versions),dateutil.parser.parse(date).date(),name))
        except sre_constants.error as e:
            warning(versions)
            warning(e)
    for _, _, name in vulns:
        vuln_nms.append(name)


def expand_release_dates(release_dates):
    n_release_dates = OrderedDict()
    for version, release_date in release_dates:
        n_release_dates[version] = dateutil.parser.parse(release_date).date()
    return n_release_dates


def expand_api_to_os(os_to_api, release_dates):
    api_to_os = OrderedDict()
    api_release_dates = OrderedDict()
    for version, api in os_to_api.items():
        if not api in api_to_os:
            api_to_os[api] = [version]
            if version in release_dates:
                api_release_dates[api] = release_dates[version]
        else:
            api_to_os[api].append(version)
            if version in release_dates:
                release_date = release_dates[version]
                if release_date < api_release_dates[api]:
                    api_release_dates[api] = release_date
    return api_to_os, api_release_dates
'''

class DateRef:

    def __init__(self, field, vuln):
        if None == field:
            raise ValueError("Nothing to extract date from: None")
        if isinstance(field, dict):
            self.datestring = field['date']
            self.ref = field['ref']
        elif isinstance(field, list):
            if len(field) == 0:
                raise ValueError("No field to process: " + str(field))
            self.datestring = field[0]
            if len(field) == 2:
                self.ref = field[1]
            else:
                self.ref = None
        else:
            raise ValueError("Unexpected type of field %s" % (field))
        if not isinstance(self.datestring, str):
            raise ValueError("Date string not a string: " + str(
                type(self.datestring)) + " - " + str(self.datestring))
        self.date = dateutil.parser.parse(self.datestring).date()
        self.vuln = vuln

    def __str__(self):
        string = self.datestring
        if self.ref is not None:
            string += ' ' + self.vuln._str_reference(self.ref)
        else:
            string += ' \\[citation-needed\\]'
        return string


def get_submitters(submission_list):
    submitters = []
    for submission in submission_list:
        submitters.append(submission['by'])
    return submitters


class Submission:

    def __init__(self, jsn):
        self.by = jsn['by']
        self.on = jsn['on']

    def __str__(self):
        return "by: [{name}](submitters/{by}), on: {on}".format(name=submitters[self.by].name, by=self.by, on=self.on)

    def __repr__(self):
        return self.__str__()


class Submitter:

    def __init__(self, jsn):
        self.ID = jsn['id']
        self.name = jsn['name']
        self.email = jsn['email']
        self.url = jsn['url']
        self.fingerprints = jsn['fingerprints']
        self.show_photo = jsn['photo']

    def __str__(self):
        if self.show_photo:
            photostring = "![Photo of {name}](images/people/{ID}.jpg)".format(
                name=self.name, ID=self.ID)
        else:
            photostring = ""
        return """#{name} ({ID})

* Name: {name}
* Email: <{email}>
* Website: <{url}>
* GPG fingerprints: {fingerprints}

{photo}
""".format(name=self.name, ID=self.ID, email=self.email, url=self.url, fingerprints=", ".join(self.fingerprints), photo=photostring)

    def __repr__(self):
        return self.__str__()


# Class definition for a vulnerability
class Vulnerability:
    year_fields = [
        'Discovered_on', 'Reported_on', 'Fixed_on', 'Fix_released_on']

    def __init__(self, jsn):
        self.jsn = jsn
        self.name = jsn['name']
        self.urlname = self.name.replace(' ', '_')
        self._versions = None
        self._str = None

    def _years_append(self, yrs, field):
        try:
            daterefs = self._rawdateref(field)
        except ValueError as e:
            warning(e)
            return
        for dateref in daterefs:
            yrs.append(str(dateref.date.year))

    def years(self):
        yrs = []
        for year_field in self.year_fields:
            field = self.jsn[year_field]
            if len(field) > 0:
                if isinstance(field, list) and isinstance(field[0], list):
                    for entry in field:
                        self._years_append(yrs, entry)
                else:
                    self._years_append(yrs, field)
        return set(yrs)

    def _dates_append(self, dates, field):
        try:
            daterefs = self._rawdateref(field)
        except ValueError as e:
            warning(e)
            return
        for dateref in daterefs:
            dates.append(dateref.date)

    def _dates(self):
        dates = []
        fields = []
        for year_field in self.year_fields:
            field = self.jsn[year_field]
            if len(field) > 0:
                if isinstance(field, list) and isinstance(field[0], list):
                    for entry in field:
                        self._dates_append(dates, entry)
                else:
                    self._dates_append(dates, field)
                while len(dates) > len(fields):
                    fields.append(year_field)
        return list(zip(*sorted(zip(dates, fields), key=lambda x: x[0])))

    def raw_vulnerability(self):
        dates, fields = self._dates()
        regex = self.jsn['Affected_versions_regexp']
        manufacturers = self.manufacturers()
        affects_all = 'all' in  map(lambda x : x[0], manufacturers)
        if 'Severity' in self.jsn and 'uncertain' == self.jsn['Severity']:
            uncertain = True
        else:
            uncertain = False
        if len(regex) > 0 and affects_all and not uncertain:  # TODO regex is a list but we are not treating it as one.
            return (regex[0], str(dates[0].isoformat()), self.name, fields[0].replace('_', ' '))

    def first_date(self):
        dates, fields = self._dates()
        return dates[0]

    def last_date(self):
        dates, fields = self._dates()
        return dates[-1]

    def regex(self):
        affected_versions_regexp = self.jsn['Affected_versions_regexp']
        if len(affected_versions_regexp) > 0:
            re_string = r'\A(%s)$' % affected_versions_regexp[0]
            try:
                return re.compile(re_string)
            except sre_constants.error as e:
               warning(self.name, re_string)
               raise e
        else:
            return re.compile('XXXXXXXX')

    def versions(self):
        if self._versions != None:
            return self._versions
        versions = []
        regex = self.regex()
        for version in os_to_api.keys():
            if regex.match(version):
                versions.append(version)
        self._versions = versions
        return versions

    def manufacturers(self):
        return self.jsn['Affected_manufacturers']

    def submitters(self):
        submitterslist = get_submitters(self.jsn['Submission'])
        return submitterslist

    def submissions(self):
        return list(map(Submission, self.jsn['Submission']))

    def categories(self):
        return self.jsn['Categories']

    def _get_reference_url(self, reference):
        return self.jsn['references'][reference]['url']

    def _str_reference(self, reference):
        if isinstance(reference, list):
            answer = ""
            for refentry in reference:
                answer += self._str_reference(refentry)
            return answer
        url = self._get_reference_url(reference)
        if isinstance(url, list):
            answer = ""
            index = 0
            for urlelement in url:
                answer += "\\[[{reference}#{index}]({url})\\]".format(
                    reference=reference, index=index, url=urlelement)
                index += 1
            return answer
        return "\\[[{reference}]({url})\\]".format(reference=reference, url=url)

    def _print_ref_list(self, reflist, separator=", "):
        answer = []
        for itemref in reflist:
            if isinstance(itemref, list):
                itemstr = itemref[0]
                if isinstance(itemstr, list):
                    itemstr = '(' + ', '.join(itemstr) + ')'
                if len(itemref) == 2:
                    itemstr += " " + self._str_reference(itemref[1])
                else:
                    itemstr += ' \\[citation-needed\\]'
            else:
                raise ValueError("Unknown type of itemref:" + str(
                    type(itemref)) + " - " + str(itemref))
            # if isinstance(itemref, dict):
                # TODO we don't use this yet
            answer.append(itemstr)
        return separator.join(answer)

    def _print_manufacturer_list(self, reflist, separator=", "):
        answer = []
        for itemref in reflist:
            if isinstance(itemref, list):
                itemstr = "[{manufacturer}](by/manufacturer/{manufacturer})".format(
                    manufacturer=itemref[0])
                if len(itemref) == 2:
                    itemstr += " " + self._str_reference(itemref[1])
                else:
                    itemstr += ' \\[citation-needed\\]'
            else:
                raise ValueError("Unknown type of itemref:" + str(
                    type(itemref)) + " - " + str(itemref))
            answer.append(itemstr)
        return separator.join(answer)

    def _rawdateref(self, jsn):
        if isinstance(jsn, list):
            if isinstance(jsn[0], list) or isinstance(jsn[0], dict):
                return [DateRef(x[0], x[1]) for x in zip(jsn, [self] * len(jsn))]
        return [DateRef(jsn, self)]

    def _dateref(self, jsn):
        """Try and turn json into a DateRef or a string representing a list of DateRefs but if that fails Return 'Unknown'"""
        if len(jsn) == 0:
            return "Unknown"
        try:
            return ", ".join(map(str, self._rawdateref(jsn)))
        except ValueError as e:
            warning("Error in _dateref: " + str(e))
            return "Unknown"

    def __str__(self):
        if self._str != None:
            return self._str
        string = """### [{name}](/vulnerabilities/{urlname})
([json](vulnerabilities/{urlname}.json))

* CVE numbers: {cve}
* Responsibly disclosed?: {responsibly}
* Categories: {categories}
* Details: {details}
* Discovered by: {discovered_by} on: {discovered_on}
* Reported on: {reported_on}
* Fixed on: {fixed_on}
* Fix released on: {fix_released_on}
* Affected versions: {affected_versions} regex: {affected_versions_regexp}
* Affected devices: {affected_devices}
* Affected manufacturers: {affected_manufacturers}
* Fixed versions: {fixed_versions}
* Submission: {submission_list}
""".format(name=self.name, urlname=self.urlname,
           cve=self._print_ref_list(self.jsn['CVE']),
           responsibly=self.jsn['Responsibly_disclosed'],
           categories=', '.join(self.categories()),
           details=self._print_ref_list(self.jsn['Details'], separator="\n"),
           discovered_by=self._print_ref_list(self.jsn['Discovered_by']),
           discovered_on=self._dateref(self.jsn['Discovered_on']),
           reported_on=self._dateref(self.jsn['Reported_on']),
           fixed_on=self._dateref(self.jsn['Fixed_on']),
           fix_released_on=self._dateref(self.jsn['Fix_released_on']),
           affected_versions=self._print_ref_list(
               self.jsn['Affected_versions']),
           affected_versions_regexp=", ".join(
           self.jsn['Affected_versions_regexp']),
           affected_devices=self._print_ref_list(self.jsn['Affected_devices']),
           affected_manufacturers=self._print_manufacturer_list(
           self.jsn['Affected_manufacturers']),
           fixed_versions=self._print_ref_list(self.jsn['Fixed_versions']),
           submission_list="; ".join(map(str, self.submissions())),
           )
        self._str = string
        return string

    def __repr__(self):
        return self.__str__()


os_to_api = None

def hook_preconvert_00_os_to_api():
    global python_export_file_contents, os_to_api
    with open('input/os_to_api.json') as f:
        rjson = json.load(f)
        rlist = []
        for version, api in list(rjson.items()):
            rlist.append([version, int(api)])
        rlist = sorted(rlist, key=lambda x: x[0])
        os_to_api = OrderedDict(rlist)
        python_export_file_contents += '\nos_to_api = ' + str(rlist) + '\n'


vulnerabilities = []
vuln_by_name = dict()
# Key to list of vulnerability dicts
by_year = defaultdict(list)
by_version = defaultdict(list)
by_manufacturer = defaultdict(list)
by_submitter = defaultdict(list)
raw_vulnerabilities = []

def hook_preconvert_01_vulnerabilities():
    global raw_vulnerabilities, python_export_file_contents
    for filename in os.listdir('input/vulnerabilities'):
        if filename == 'template.json':  # skip over template
            continue
        if not filename.endswith('.json'):
          continue
        with open('input/vulnerabilities/' + filename, 'r') as f:
            print("processing: " + filename)
            vulnerability = Vulnerability(json.load(f))
            vulnerabilities.append(vulnerability)
            vuln_by_name[vulnerability.name] = vulnerability
            for year in vulnerability.years():
                by_year[year].append(vulnerability)
            for version in vulnerability.versions():
                by_version[version].append(vulnerability)
            manufacturers = vulnerability.manufacturers()
            for manufacturer in vulnerability.manufacturers():
                by_manufacturer[manufacturer[0]].append(vulnerability)
            if len(manufacturers) == 0:
                by_manufacturer['none'].append(vulnerability)
            for submitter in vulnerability.submitters():
                by_submitter[submitter].append(vulnerability)
            raw_vulnerability = vulnerability.raw_vulnerability()
            if raw_vulnerability != None:
                raw_vulnerabilities.append(raw_vulnerability)
    raw_vulnerabilities = sorted(raw_vulnerabilities, key=lambda x: x[1])

    python_export_file_contents += '\nraw_vulnerabilities = ' + str(raw_vulnerabilities) + '\n'


submitters = dict()

def hook_preconvert_02_submitters():
    for filename in os.listdir('input/submitters'):
        if not filename.endswith('.json'):
            continue
        with open('input/submitters/' + filename, 'r') as f:
            print("processing: " + filename)
            submitter = Submitter(json.load(f))
            submitters[submitter.ID] = submitter
    set_latex_value('NumSubmitters', len(submitters))


def hook_preconvert_03_by():
    global by_year, by_version, by_manufacturer, by_submitter
    by_year = OrderedDict(sorted(by_year.items()))
    by_version = OrderedDict(sorted(by_version.items()))
    by_manufacturer = OrderedDict(sorted(by_manufacturer.items()))
    by_submitter = OrderedDict(sorted(by_submitter.items()))

# Create a page for each vulnerability


def hook_preconvert_vulnpages():
    for vulnerability in vulnerabilities:
        p = Page("vulnerabilities/{name}.md".format(
            name=vulnerability.urlname), virtual=str(vulnerability), title=vulnerability.name)
        pages.append(p)


def hook_preconvert_submitterpages():
    for ID, submitter in list(submitters.items()):
        p = Page("submitters/{ID}.md".format(ID=ID), virtual=str(
            submitter), title="{name} ({ID})".format(name=submitter.name, ID=ID))
        pages.append(p)


def hook_preconvert_bypages():
    by_pages(by_year, 'year')
    by_pages(by_version, 'version')
    by_pages(by_manufacturer, 'manufacturer')
    by_pages(by_submitter, 'submitter')


max_vulns_per_key = 10

def by_pages(vulndict, by):
    bypagestring = '\n'  # Can't be the empty string or empty pages will cause errors
    for key, vulns in list(vulndict.items()):
        bypagestring += "##[{key}](by/{by}/{key})\n\n".format(key=key, by=by)
        vstring = "#{key}\n\n".format(key=key)
        num_vulns = len(vulns)
        for vuln in vulns:
            vulnstring = str(vuln) + '\n'
            vstring += vulnstring
            if num_vulns < max_vulns_per_key:
                bypagestring += vulnstring
            else:
                bypagestring += '* [{name}](/vulnerabilities/{urlname})\n'.format(name=vuln.name, urlname=vuln.urlname)
        p = Page("by/{by}/{key}.md".format(
            key=key, by=by), virtual=vstring, title=key)
        pages.append(p)
    p = Page("by/{by}/index.md".format(by=by),
             virtual=bypagestring, title="By {by}".format(by=by))
    pages.append(p)


def hook_preconvert_releases():
    global python_export_file_contents
    with open('input/release_dates.json') as f:
        rjson = json.load(f)
        rlist = []
        for version, info in list(rjson.items()):
            date = info[0]
            if len(date) == 0 or '?' in date:
                continue
            rlist.append([version, date])
        rlist = sorted(rlist, key=lambda x: x[0])
        python_export_file_contents += '\nrelease_dates = ' + str(rlist) + '\n'



def hook_preconvert_linux_versions():
    global python_export_file_contents
    with open('input/linux_versions.json') as f:
        rjson = json.load(f)
        rlist = []
        for version, kernelref in list(rjson.items()):
            kernel = kernelref[0]
            if len(kernel) > 0 and not '?' in kernel:
                rlist.append([version, kernel])
        rlist = sorted(rlist, key=lambda x: x[0])
        python_export_file_contents += '\nos_to_kernel = ' + str(rlist) + '\n'


tag_matcher = re.compile('android-([0-9.]+)_.*')
shortversionp = re.compile("\A[1-4]\.[0-9]$")
def tag_to_version(tag):
    '''Turn an Android git tag into the corresponding Android version'''
    match = tag_matcher.match(tag)
    if not match:
        return None
    version = match.group(1)
    if shortversionp.match(version):
        version += '.0'
    return version


project_lines = dict()
total_lines = 0
def hook_preconvert_external_linecount():
    global python_export_file_contents, total_lines
    with open('input/external_lines_of_code.json') as f:
        rjson = json.load(f)
        for project, lines in rjson.items():
            if len(project) > 0 and len(lines) > 0:
                project_lines[project] = int(lines)
    sorted_pl = sorted(project_lines.items(), key=lambda x : x[1])#Sort by lines of code
    total_lines = sum(project_lines.values())
    set_latex_value('TotalExternalLines', num2word(total_lines))
    set_latex_value('NumExternalProjects', len(sorted_pl))
    big_total_lines = sum(map(lambda x : x[1], sorted_pl[40:]))#TODO factor this 40 out
    set_latex_value('NumBigExternalLinesOfCode', num2word(big_total_lines))
    set_latex_value('BigExternalLinesOfCodePerc', big_total_lines/total_lines, t='perc')
    python_export_file_contents += '\ntotal_external_lines = ' + str(total_lines) + '\n'
    python_export_file_contents += '\nexternal_project_lines = ' + str(sorted_pl) + '\n'


def hook_preconvert_tag_versions():
    global python_export_file_contents
    #upstreams = ['openssl', 'bouncycastle', 'libogg', 'libxml2', 'openssh']
    upstreams = [
        'aac', 'kernel-headers', 'bouncycastle', 'sonivox', 'tcpdump', 'freetype', 'libnfc-nxp', 'srec', 'elfutils', 'apache-xml', 'openssh', 'stlport', 'linux-tools-perf', 'e2fsprogs', 'apache-harmony', 'eigen', 'jmonkeyengine',
        'protobuf', 'opencv', 'guava', 'libxml2', 'bluetooth', 'sqlite', 'antlr', 'bison', 'libvpx', 'wpa_supplicant_8', 'compiler-rt', 'libcxx', 'skia', 'openssl', 'qemu', 'vixl', 'icu', 'valgrind', 'mesa3d', 'llvm', 'clang', 'chromium', 'chromium_org']
    set_latex_value('NumBigExternalProjects',len(upstreams))
    existing_upstreams = upstreams[
        :]  # May need to remove ones for which we lack data
    data = dict()
    for upstream in upstreams:
        tag_versions(upstream, existing_upstreams, data)
    set_latex_value('NumAnalysedExternalProjects', len(existing_upstreams))
    analysed_lines_of_code = 0
    for upstream in existing_upstreams:
        analysed_lines_of_code += project_lines[upstream]
    set_latex_value('NumAnalysedExternalLinesOfCode', num2word(analysed_lines_of_code))
    set_latex_value('AnalysedExternalLinesOfCodePerc', analysed_lines_of_code/total_lines, t='perc')
    count_versions(data)
    python_export_file_contents += '\nupstreams = ' + str(existing_upstreams) + '\n'
    python_export_file_contents += '\nos_to_project = ' + str(data) + '\n'


def count_versions(data):
    total = 0
    totals = []
    for project, values in data.items():
        values_set = set(map(lambda x : x[1], values.items()))
        num_values = len(values_set)
        total += num_values
        totals.append(num_values)
    totals = sorted(totals)
    set_latex_value('BigExternalMedianVersions', numpy.median(numpy.array(totals)))
    set_latex_value('BigExternalMeanVersions', ufloat(numpy.mean(numpy.array(totals)), numpy.std(numpy.array(totals))))
    set_latex_value('BigExternalTotalVersions', total)


def tag_versions(name, existing_upstreams, data):
    filename = 'input/tag_to/tag_to_{}_version.json'.format(name)
    if not os.path.isfile(filename):
        existing_upstreams.remove(name)
        return
    with open(filename) as f:
        try:
            rjson = json.load(f)
        except ValueError as e:
            warning(filename)
            raise e
        rlist = []
        for tag, upstream_version in list(rjson.items()):
            android_version = tag_to_version(tag)
            if android_version != None and upstream_version != None and len(upstream_version) > 0:
                rlist.append((android_version, upstream_version))
        # Make the list unique and then sort it
        rlist = sorted(set(rlist), key=lambda x: x[0])
        data[name] = OrderedDict(rlist)


def hook_preconvert_stats():
    set_latex_value('NumVulnerabilities', len(vulnerabilities))
    num_vuln_all_android = 0
    num_vuln_specific = 0
    first_submission = None
    last_submission = None
    first_date = None
    last_date = None
    for vuln in vulnerabilities:
        manufacturers = vuln.manufacturers()
        if 'all' in [x[0] for x in manufacturers]:
            num_vuln_all_android += 1
        else:
            num_vuln_specific += 1
        for submission in vuln.submissions():
            on = submission.on
            if first_submission == None:
                first_submission = on
                last_submission = on
            else:
                if on < first_submission:
                    first_submission = on
                elif on > last_submission:
                    last_submission = on
        first = vuln.first_date()
        last = vuln.last_date()
        if first_date == None:
            first_date = first
            last_date = last
        else:
            if first < first_date:
                first_date = first
            if last > last_date:
                last_date = last
    set_latex_value('NumVulnAllAndroid', num_vuln_all_android)
    set_latex_value('NumVulnSpecific', num_vuln_specific)
    set_latex_value('StartDate', first_submission)
    set_latex_value('EndDate', last_submission)
    set_latex_value('FirstDataDate', first_date)
    set_latex_value('LastDataDate', last_date)
    set_latex_value('VulnsPerYear', (ufloat(len(vulnerabilities),sqrt(len(vulnerabilities)))/((last_date - first_date)/datetime.timedelta(1)))*365)
    set_latex_value('VulnsPerYearAllAndroid', (ufloat(num_vuln_all_android,sqrt(num_vuln_all_android))/((last_date - first_date)/datetime.timedelta(1)))*365)
    vuln_table = r'\begin{table} \centering \small \begin{tabular}{l|l|c|c} Vulnerability & How known & Date & Categories\\ \hline'
    for versions, date, name, how_known in raw_vulnerabilities:
            vuln_table += r' {} & {} & {} & {}\\'.format(try_shorten(name), how_known, date, ", ".join(vuln_by_name[name].categories()))
    vuln_table += r'\end{tabular} \caption{Critical vulnerabilities in Android} \label{tab:andvulns} \end{table}'
    set_latex_value('TabAndVulns', vuln_table)

def hook_postconvert_python_export():
    with open('output/avo.py', 'w') as f:
        f.write(python_export_file_contents.replace("u'","'"))
