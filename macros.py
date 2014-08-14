#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Do the parsing required to get all the vulnerabilities as objects in
# memory so that we can generate the pages.
from __future__ import absolute_import, division, print_function, unicode_literals
# Evil hack to make UTF-8 default
import sys
reload(sys)
sys.setdefaultencoding("UTF-8")
import json
import os
import dateutil.parser
import uncertainties
from collections import defaultdict, OrderedDict


def warning(*objs):
    print(*objs, file=sys.stderr)


def set_latex_value(key, value, t=None):
    # \newcommand{\avo$key}{$value}
    # Get the file
    filename = 'output/latex.tex'
    if not os.path.exists(filename):
        open(filename, 'a').close()  # Create file if it does not exist
    with open(filename) as rf:
        sf = rf.read()
    # Mangle the value
    if t == 'perc':
        if isinstance(value, float):
            svalue = '{:.2f}\%'.format(value)
        elif isinstance(value, uncertainties.UFloat):
            svalue = '${:.2L}\%$'.format(value)
        else:
            raise ValueError("Not a percentage")
    else:
        if isinstance(value, float):
            svalue = '{:.2f}'.format(value)
        elif isinstance(value, uncertainties.UFloat):
            svalue = '${:.2L}$'.format(value)
        else:
            svalue = str(value)
    # Set the contents
    kv_line = r'\newcommand{\avo' + key + r'}{' + svalue + r'}'
    k_part = r'\newcommand{\avo' + key + r'}'
    start_index = sf.find(k_part)
    if start_index >= 0:  # if already set, update
        startofvalue = start_index + len(k_part) + 1  # 1 for the {
        endofvalue = sf.find('}\n', startofvalue)
        sf = sf[:startofvalue] + svalue + sf[endofvalue:]
    else:
        sf += kv_line + '\n'
    # Write the updated file
    with open(filename, 'w') as wf:
        wf.write(sf)

python_export_file_contents = r'''#!/usr/bin/env python
# Exported data from androidvulnerabilities.org for easy inclusion in python scripts

import re
import dateutil
from collections import OrderedDict

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
                raise ValueError("No field to process: " + unicode(field))
            self.datestring = field[0]
            if len(field) == 2:
                self.ref = field[1]
            else:
                self.ref = None
        else:
            raise ValueError("Unexpected type of field %s" % (field))
        if not isinstance(self.datestring, basestring):
            raise ValueError("Date string not a string: " + unicode(
                type(self.datestring)) + " - " + unicode(self.datestring))
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

    def _years_append(self, yrs, field):
        try:
            daterefs = self._rawdateref(field)
        except ValueError as e:
            warning(e)
            return
        for dateref in daterefs:
            yrs.append(unicode(dateref.date.year))

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
        return zip(*sorted(zip(dates, fields), key=lambda x: x[0]))

    def raw_vulnerability(self):
        dates, fields = self._dates()
        regex = self.jsn['Affected_versions_regexp']
        if len(regex) > 0:  # TODO regex is a list but we are not treating it as one.
            return (regex[0], unicode(dates[0].isoformat()), self.name, fields[0].replace('_', ' '))

    def versions(self):
        return []  # TODO

    def manufacturers(self):
        return self.jsn['Affected_manufacturers']

    def submitters(self):
        submitterslist = get_submitters(self.jsn['Submission'])
        return submitterslist

    def submissions(self):
        return map(Submission, self.jsn['Submission'])

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
                raise ValueError("Unknown type of itemref:" + unicode(
                    type(itemref)) + " - " + unicode(itemref))
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
                raise ValueError("Unknown type of itemref:" + unicode(
                    type(itemref)) + " - " + unicode(itemref))
            answer.append(itemstr)
        return separator.join(answer)

    def _rawdateref(self, jsn):
        if isinstance(jsn, list):
            if isinstance(jsn[0], list) or isinstance(jsn[0], dict):
                return map(lambda x: DateRef(x[0], x[1]), zip(jsn, [self] * len(jsn)))
        return [DateRef(jsn, self)]

    def _dateref(self, jsn):
        """Try and turn json into a DateRef or a string representing a list of DateRefs but if that fails Return 'Unknown'"""
        if len(jsn) == 0:
            return "Unknown"
        try:
            return ", ".join(map(str, self._rawdateref(jsn)))
        except ValueError as e:
            warning("Error in _dateref: " + unicode(e))
            return "Unknown"

    def __str__(self):
        return """### [{name}](/vulnerabilities/{urlname})
([json](vulnerabilities/{urlname}.json))

* CVE numbers: {cve}
* Responsibly disclosed?: {responsibly}
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

    def __repr__(self):
        return self.__str__()


def print_by_page(vulndict):
    for key, vulns in vulndict.items():
        print("##{key}\n\n".format(key=key))
        for vuln in vulns:
            print(vuln)


vulnerabilities = []
# Key to list of vulnerability dicts
by_year = defaultdict(list)
by_version = defaultdict(list)
by_manufacturer = defaultdict(list)
by_submitter = defaultdict(list)
raw_vulnerabilities = []

for filename in os.listdir('input/vulnerabilities'):
    if filename == 'template.json':  # skip over template
        continue
    if not filename.endswith('.json'):
        continue
    with open('input/vulnerabilities/' + filename, 'r') as f:
        print("processing: " + filename)
        vulnerability = Vulnerability(json.load(f))
        vulnerabilities.append(vulnerability)
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
for filename in os.listdir('input/submitters'):
    if not filename.endswith('.json'):
        continue
    with open('input/submitters/' + filename, 'r') as f:
        print("processing: " + filename)
        submitter = Submitter(json.load(f))
        submitters[submitter.ID] = submitter

by_year = OrderedDict(sorted(by_year.items()))
by_version = OrderedDict(sorted(by_version.items()))
by_manufacturer = OrderedDict(sorted(by_manufacturer.items()))
by_submitter = OrderedDict(sorted(by_submitter.items()))

# Create a page for each vulnerability


def hook_preconvert_vulnpages():
    for vulnerability in vulnerabilities:
        p = Page("vulnerabilities/{name}.md".format(
            name=vulnerability.urlname), virtual=unicode(vulnerability), title=vulnerability.name)
        pages.append(p)


def hook_preconvert_submitterpages():
    for ID, submitter in submitters.items():
        p = Page("submitters/{ID}.md".format(ID=ID), virtual=unicode(
            submitter), title="{name} ({ID})".format(name=submitter.name, ID=ID))
        pages.append(p)


def hook_preconvert_bypages():
    by_pages(by_year, 'year')
    by_pages(by_version, 'version')
    by_pages(by_manufacturer, 'manufacturer')
    by_pages(by_submitter, 'submitter')


def by_pages(vulndict, by):
    bypagestring = '\n'  # Can't be the empty string or empty pages will cause errors
    for key, vulns in vulndict.items():
        bypagestring += "##[{key}](by/{by}/{key})\n\n".format(key=key, by=by)
        vstring = "#{key}\n\n".format(key=key)
        for vuln in vulns:
            vulnstring = unicode(vuln) + '\n'
            vstring += vulnstring
            bypagestring += vulnstring
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
        for version, info in rjson.items():
            date = info[0]
            if len(date) == 0 or '?' in date:
                continue
            rlist.append([version, date])
        rlist = sorted(rlist, key=lambda x: x[0])
        python_export_file_contents += '\nrelease_dates = ' + str(rlist) + '\n'


def hook_preconvert_os_to_api():
    global python_export_file_contents
    with open('input/os_to_api.json') as f:
        rjson = json.load(f)
        rlist = []
        for version, api in rjson.items():
            rlist.append([version, int(api)])
        rlist = sorted(rlist, key=lambda x: x[0])
        python_export_file_contents += '\nos_to_api = ' + str(rlist) + '\n'


def hook_preconvert_linux_versions():
    global python_export_file_contents
    with open('input/linux_versions.json') as f:
        rjson = json.load(f)
        rlist = []
        for version, kernelref in rjson.items():
            kernel = kernelref[0]
            if len(kernel) > 0 and not '?' in kernel:
                rlist.append([version, kernel])
        rlist = sorted(rlist, key=lambda x: x[0])
        python_export_file_contents += '\nos_to_kernel = ' + str(rlist) + '\n'



def hook_preconvert_stats():
    set_latex_value('NumVulnerabilities', len(vulnerabilities))
    num_vuln_all_android = 0
    num_vuln_specific = 0
    first_submission = None
    last_submission = None
    for vuln in vulnerabilities:
        manufacturers = vuln.manufacturers()
        if 'all' in map(lambda x: x[0], manufacturers):
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
    set_latex_value('NumVulnAllAndroid', num_vuln_all_android)
    set_latex_value('NumVulnSpecific', num_vuln_specific)
    set_latex_value('StartDate', first_submission)
    set_latex_value('EndDate', last_submission)
    vuln_table = r'\begin{table} \centering \begin{tabular}{l|c|l} Vulnerability & Date known & How known \\ \hline'
    for versions, date, name, how_known in raw_vulnerabilities:
            vuln_table += r' {} & {} & {} \\'.format(name, date, how_known)
    vuln_table += r'\end{tabular} \caption{Root equivalent vulnerabilities in Android} \label{tab:andvulns} \end{table}'
    set_latex_value('TabAndVulns', vuln_table)

def hook_postconvert_python_export():
    with open('output/avo.py', 'w') as f:
        f.write(python_export_file_contents.replace("u'","'"))
