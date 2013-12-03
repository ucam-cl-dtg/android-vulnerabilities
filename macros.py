#!/usr/bin/env python
# Do the parsing required to get all the vulnerabilities as objects in memory so that we can generate the pages.
import json
import os
import dateutil.parser
from collections import defaultdict,OrderedDict

class DateRef:
	def __init__(self, field, vuln):
		if None == field:
			raise ValueError("Nothing to extract date from: None")
		if isinstance(field, dict):
			self.datestring = field['date']
			self.ref = field['ref']
		elif isinstance(field, list):
			self.datestring = field[0]
			if len(field) == 2:
				self.ref = field[1]
			else:
				self.ref = None
		else:
			raise ValueError("Unexpected type of field %s: %s" % (year_field, field))
		self.date = dateutil.parser.parse(self.datestring)
		self.vuln = vuln
	def __str__(self):
		string = self.datestring
		if self.ref is not None:
			string += ' ' + self.vuln._str_reference(self.ref)
		return string
	
# Class definition for a vulnerability
class Vulnerability:
	year_fields = ['Discovered_on','Reported_on','Fixed_on','Fix_released_on']#'Submitted_on',
	def __init__(self,jsn):
		self.jsn = jsn
		self.name = jsn['name']
	def years(self):
		yrs = []
		for year_field in self.year_fields:
			field = self.jsn[year_field]
			try:
				dateref = DateRef(field, self)
			except ValueError as e:
				print e #TODO stderr
				continue
			yrs.append(str(dateref.date.year))
		return set(yrs)
	def versions(self):
		return []#TODO
	def manufacturers(self):
		return self.jsn['Affected_manufacturers']
	def submitters(self):
		submitterslist = self.jsn['Submitted_by']
		return submitterslist
	def _get_reference_url(self,reference):
		return self.jsn['references'][reference]['url']
	def _str_reference(self,reference):
		return "\\[[{reference}]({url})\\]".format(reference=reference,url=self._get_reference_url(reference))
	def _print_ref_list(self,reflist,separator=","):
		answer = []
		for itemref in reflist:
			if isinstance(itemref, list):
				itemstr = itemref[0]
				if len(itemref) == 2:
					itemstr += " " + self._str_reference(itemref[1])
			else:
				raise ValueError("Unknown type of itemref:" + str(type(itemref)) + " - "+ str(itemref))
			#if isinstance(itemref, dict):
				#TODO we don't use this yet
			answer.append(itemstr)
		return separator.join(answer)

	def __str__(self):
		return """### {name}

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
* Submitted by: {submitted_by} on: {submitted_on}
""".format(name=self.name,
		cve=self._print_ref_list(self.jsn['CVE']),
		responsibly=self.jsn['Responsibly_disclosed'],
		details=self._print_ref_list(self.jsn['Details'], separator="\n"),
		discovered_by=self._print_ref_list(self.jsn['Discovered_by']),
		discovered_on=DateRef(self.jsn['Discovered_on'], self),
		reported_on=DateRef(self.jsn['Reported_on'], self),
		fixed_on=DateRef(self.jsn['Fixed_on'], self),
		fix_released_on=DateRef(self.jsn['Fix_released_on'], self),
		affected_versions=self._print_ref_list(self.jsn['Affected_versions']),
		affected_versions_regexp=", ".join(self.jsn['Affected_versions_regexp']),
		affected_devices=self._print_ref_list(self.jsn['Affected_devices']),
		affected_manufacturers=self._print_ref_list(self.jsn['Affected_manufacturers']),
		fixed_versions=self._print_ref_list(self.jsn['Fixed_versions']),
		submitted_by=", ".join(self.jsn['Submitted_by']),
		submitted_on=", ".join(self.jsn['Submitted_on'])
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
# TODO these need sorting
by_year = defaultdict(list)
by_version = defaultdict(list)
by_manufacturer = defaultdict(list)
by_submitter = defaultdict(list)

for filename in os.listdir('vulnerabilities'):
	if filename == 'template.json':# skip over template
		continue
	with open('input/vulnerabilities/' + filename) as f:
		vulnerability = Vulnerability(json.load(f))
		vulnerabilities.append(vulnerability)
		for year in vulnerability.years():
			by_year[year].append(vulnerability)
		for version in vulnerability.versions():
			by_version[version].append(vulnerability)
		for manufacturer in vulnerability.manufacturers():
			by_manufacturer[manufacturer[0]].append(vulnerability)
		for submitter in vulnerability.submitters():
			by_submitter[submitter].append(vulnerability)

by_year = OrderedDict(sorted(by_year.items()))
by_version = OrderedDict(sorted(by_version.items()))
by_manufacturer = OrderedDict(sorted(by_manufacturer.items()))
by_submitter = OrderedDict(sorted(by_submitter.items()))
