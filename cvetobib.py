#!/usr/bin/env python3

import datetime

cves = ["CVE-2011-1149","CVE-2009-1185", "CVE-2011-1350", "CVE-2011-1352", "CVE-2011-1823", "CVE-2011-3874", "CVE-2013-4787", "CVE-2014-3153", "CVE-2014-7911", "CVE-2015-1538", "CVE-2015-1539", "CVE-2015-3824", "CVE-2015-3826", "CVE-2015-3827", "CVE-2015-3828", "CVE-2015-3829", "CVE-2015-6602", "CVE-2015-3876", "CVE-2015-3825", "CVE-2015-3837"]

cves.sort()

def cvetobib(cve):
    cveyear = cve[4:8]
    today = datetime.date.today().isoformat()
    print(r'''@online{{{0},
  title = {{{0}}},
  howpublished = "Available from MITRE, {{CVE-ID}} {0}.",
  publisher = "MITRE",
  year = {{{1}}},
  url={{http://cve.mitre.org/cgi-bin/cvename.cgi?name={0}}},
  urldate={{{2}}}
}}'''.format(cve,cveyear,today))

for cve in cves:
    cvetobib(cve)
