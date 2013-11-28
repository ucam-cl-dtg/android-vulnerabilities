#!/usr/bin/env python
# Do the parsing required to get all the vulnerabilities as objects in memory so that we can generate the pages.
import json
import os
import dateutil.parser
from collections import defaultdict

# Class definition for a vulnerability
class Vulnerability:
	year_fields = ['Discovered_on','Submitted_on','Reported_on','Fixed_on','Fix_released_on']
	def __init__(self,jsn):
		self.jsn = jsn
		self.name = jsn['name']
	def years(self):
		yrs = []
		for year_field in self.year_fields:
			field = self.jsn[year_field]
			if None == field:
				continue
			if isinstance(field, dict):
				datestring = field['date']
			elif isinstance(field, list):
				datestring = field[0]
			else:
				print("Unexpected type of field %s: %s" % (year_field, field))
				continue
			date = dateutil.parser.parse(datestring)
			yrs.append(str(date.year))
		return yrs
	def versions(self):
		return []#TODO
	def manufacturers(self):
		return []#TODO
	def submitters(self):
		return []#TODO

vulnerabilities = []
# Key to list of vulnerability dicts TODO these need sorting
by_year = defaultdict(list)
by_version = defaultdict(list)
by_manufacturer = defaultdict(list)
by_submitter = defaultdict(list)

for filename in os.listdir('vulnerabilities'):
	if filename == 'template.json':# skip over template
		continue
	with open('vulnerabilities/' + filename) as f:
		vulnerability = Vulnerability(json.load(f))
		vulnerabilities.append(vulnerability)
		for year in vulnerability.years():
			by_year[year].append(vulnerability)
		for version in vulnerability.versions():
			by_version[version].append(vulnerability)
		for manufacturer in vulnerability.manufacturers():
			by_manufacturer[manufacturer].append(vulnerability)
		for submitter in vulnerability.submitters():
			by_submitter[submitter].append(vulnerability)

print(by_year)
