#!/usr/bin/env python
# Do the parsing required to get all the vulnerabilities as objects in memory so that we can generate the pages.
import json
import os

vulnerabilities = []

for filename in os.listdir('vulnerabilities'):
	if filename == 'template.json':# skip over template
		continue
	with open('vulnerabilities/' + filename) as f:
		vulnerability = json.load(f)
		vulnerabilities.append(vulnerability)

print(vulnerabilities)
