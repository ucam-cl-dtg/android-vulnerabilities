
title: Home
menu-position: 0
---

<div id="graph">
 <h2>Proportion of devices running vulnerable versions of Android</h2>
 <div style="width:720px; margin:auto;">
 {% insert_svg('images/norm_versionsecurity', 'Proportion of devices affected by critical vulnerabilities', '720px', '360px')  %}
 </div>
 <p>This figure shows our estimate of the proportion of Android devices running <em>insecure</em>, <em>maybe secure</em> and <em>secure</em> versions of Android over time.
<a href="graph">More details</a>.
 </p>
</div>

## Why?

We are collating all the root equivalent vulnerabilities in Android and storing all the information about them in a [machine reable format (json)](spec) with references for each fact.
This allows for analysis of what proportion of Android devices are vulnerable to different vulerabilities by using the [Device Analyzer](https://deviceanalyzer.cl.cam.ac.uk/) data.
It should also allow us to compare different manufacturers and network operators in terms of the time it takes them to supply updates to customers.
This work is being coordinated by [Daniel Thomas](submitters/drt24).

At the moment we are only tracking 'root equivalent vulnerabilities' which an application could exploit.
This means vulnerabilities which allow an application (malicious or compromised) to either directly gain root or gain privlieges which can then be used to obtain root.

## [List of vulnerabilities](all)
* [by manufacturer](by/manufacturer)
* [by year](by/year)
* [by Android version](by/version)
* [by submitter](by/submitter)
* [by category](by/category)

## [Submit a new vulnerability](submit)

## Further information
 * ["Security metrics for the Android ecosystem" by Daniel R. Thomas, Alastair R. Beresford and Andrew Rice in ACM CCS Workshop on Security and Privacy in Smartphones and Mobile Devices (SPSM) 2015](https://www.cl.cam.ac.uk/~drt24/papers/spsm-scoring.pdf)
 * ["The lifetime of Android API vulnerabilities: case study on the JavaScript-to-Java interface" by Daniel R. Thomas, Alastair R. Beresford, Thomas Coudray, Tom Sutcliffe and Adrian Taylor in the Proceedings of the Security Protocols Workshop 2015](https://www.cl.cam.ac.uk/~drt24/papers/spw15-07-Thomas.pdf)
