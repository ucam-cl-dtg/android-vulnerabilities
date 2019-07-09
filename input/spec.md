
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
* An archiveurl key containing a url that archives the url in the url field.

In the vulnerability json object dates are either lists of 1 or 2 elements (first being the ISO format date YYYY-MM-DD and second the reference) or they are a date object with a date key pointing to the ISO date string and optionally a bound and a ref key.

Other elements are specified either as a string/list of strings (for authoritative facts like name and submission details) or as 1/2 element lists of value and reference id.

### Keys

Keys are as follows:

* version="1.0"
* name : string
* CVE : list of string-refs
* Coordinated_disclosure : string ("true", "false", or "unknown")
* Categories : list of strings from : 'kernel' (a kernel vulnerability), 'signature' (errors processing signatures on APKs), 'system' (a vulnerability in the system libraries or processes), 'network' (a vulnerability exploitable by a network attacker), 'permissions' (incorrect permissions on a file), 'app' (exploitable app with elevated permissions)
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

#### Exploitation details

These are obtained from various sources, and give details of the type of vulnerability:

* Surface:
  * `local` - this vulnerability can be exploited by a user with physical access to the device
  * `remote` - this vulnerability does not need physical access to the device
  * `app` - this vulnerability can be exploited by a malicious application
  * `webpage` - this vulnerability can be exploited by malicious code on a webpage
  * `usb` - this vulnerability requires use of USB debugging to exploit
  * `filesystem` - this vulnerability can be exploited by placing crafted files into a specific place in the filesystem
  * `system-call` - this vulnerability can be exploited through system calls
  * `sms` - this vulnerability can be exploited by sending the victim a malicious SMS message
  * `mms` - this vulnerability can be exploited by sending the victim a malicious multimedia message
* Vector:
  * `insufficient-standards-verification` - a system component does not properly check standards, which allows a non-compliant app or feature to exploit the vulnerability
  * `insufficient-memory-protection` - an app is allowed to access memory which it should not have access to
  * `improper-verification` - a malicious app is able to impersonate a privileged app because the system does not properly verify whether it (or a message sent by it) is genuine
  * `memory-corruption` - attacks via buffer overflows and similar methods
  * `daemon-abusing` - exploiting a vulnerability in a daemon to gain privileged access to the system
  * `property-space` - use of the system property space to escape the sandboxed environment
  * `vulnerable-driver` - a device which driver can be exploited
  * `file-permissions` - improperly set file permissions allow malicious apps to access or modify files which they should not have access to
  * `kernel-vulnerability` - a vulnerability in the Linux kernel which can be exploited
  * `shared-memory-remapping` - modifying the access rights on a piece of shared memory
  * `return-not-checked` - the return code of a call is not checked, allowing errors to be masked
  * `bruteforce` - attempting a large number of exploits until one works
  * `symbolic-link` - crafted symbolic links can override filesystem protection
  * `buffer-overflow` - form of memory corruption attack
  * `use-after-free` - attempting to use a piece of memory after it has been returned to the OS
  * `remote-shell-control` - attempting to control the OS shell from a remote location
* Target:
  * `apps` - a local application
  * `browser` - the Android web browser
  * `system-component` - a component of the core OS
  * `kernel` - the Linux kernel
  * `driver` - a device driver
  * `tee` - Trusted Execution Environment
  * `other` - miscellaneous or not known
* Channel:
  * `app-execution` - running an application which exploits the vulnerability
  * `remote` - attacked over a network by a remote user
  * `physical-access` - requires physical access to the device
  * `shell` - can be exploited via the ADB shell
  * `file-placement` - placement of a crafted file in a particular location on the filesystem
* Condition:
  * `affected-app-installed` - an app which can exploit the vulnerability has been installed onto the device
  * `unknown-source-install-allowed` - the option to install apps from non-Google Play sources has been enabled
  * `attacker-on-same-network` - the attacker has a device connected to the same local network as the victim
  * `usb-debug` - USB debugging is enabled on the device
  * `file-placed-onto-device` - a crafted file has been placed onto the device's filesystem
  * `app-uses-vulnerable-api-functions` - an app in use makes calls to vulnerable API functions
  * `user-visits-webpage` - the user visits a malicious webpage
  * `none` - attack can be performed with no other access to the device, or use of vulnerable apps
* Privilege:
  * `root` - gain root privileges
  * `user` - get access to user-mode
  * `modify-apps` - allows other apps on the device to be modified
  * `access-to-data` - allows an attacker access to a user's personal data
  * `system` - gain access as the system user
  * `unlock-bootloader` - allows the device's bootloader to be unlocked
  * `control-hardware` - take control of hardware devices
  * `service` - takes the privilege level of system services
