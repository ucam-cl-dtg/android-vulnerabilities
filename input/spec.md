
title: Specification
---

Specification of json file format for vulnerabilities
=====================================================

In the [vulnerabilities](vulnerabilities/) directory there is one [json](http://json.org/) file for each vulnerability.
There is one called template.json which is a good starting point for new files and the rest are named according to the name of the vulnerability (with spaces replaced with underscores).
All facts need citations, where none is currently available then a \[citation-needed\] will be printed in the html.
As many citations will be reused for multiple facts citations are specified by a reference string and there is a references object with all the details for each reference.

The references object is stored under the key 'references' in the json file.
It has a series of key -> object pairs where the key is the reference id and the object is a reference object.
The reference object contains key -> string or key -> list string pairs.
It contains a url key which lists the url for the reference and may also contain:

* A commit key giving the git commit refered to and a component key giving the component in android which the commit is for. e.g. `"commit":"79b579c92afc08ab12c0a5788d61f2dd2934836f", "component":"platform/system/netd/"`.

In the vulnerability json object dates are either lists of 1 or 2 elements (first being the ISO format date YYYY-MM-DD and second the reference) or they are a date object with a date key pointing to the ISO date string and optionally a bound and a ref key.

Other elements are specified either as a string/list of strings (for authoritative facts like name and submission details) or as 1/2 element lists of value and reference id.

### Keys

Keys are as follows:

* version="1.0"
* name : string
* CVE : list of string-refs
* Responsibly_disclosed : list of bool-refs
* Categories : list of strings from : 'kernel' (a kernel vulnerability), 'signature' (errors processing signatures on APKs), 'system' (a vulnerability in the system libraries or processes), 'network' (a vulnerability exploitable by a network attacker), 'permissions' (incorrect permissions on a file)
* Severity : string
* Details : list of string-refs
* Discovered_by : list of date-refs
* Discovered_on : list of date-refs
* Submission : submission object
* Reported_on: list of date-refs
* Fixed_on: list of date-refs
* Fix_released_on : list of date-refs
* Affected_versions : list of string-refs
* Affected_devices : list of string-refs
* Affected_versions_regexp : list of strings
* Affected_manufacturers : list of string-refs
* Fixed_versions : list of string-refs
* references : object of reference objects
