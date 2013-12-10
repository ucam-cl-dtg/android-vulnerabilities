
title: Home
menu-position: 0
---

## Work in progress: This is not finished yet

<div id="graph">
<img src="images/norm_versionsecurity.png" alt="Proportion of devices affected by root vulnerabilities"/>
<p>Proportion of devices running vulnerable versions of Android</p>
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

## [Submit a new vulnerability](submit)

