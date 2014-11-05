
title: Historical Android API version distribution

---

Historical information on which versions of Android were in use is hard to come by.
The authoritative source of information is Google's [Android developers dashboard](https://developer.android.com/about/dashboards/index.html) but that lacks historical information.
There is a [graph on Wikimedia commons](https://commons.wikimedia.org/wiki/File:Android_historical_version_distribution.png) which shows the changes over time and has links for many of the data points.

We have gone through and made a [spreadsheet](play/androiddevolperdashboardhistory.ods) of all this information along with citations for each value.
This is also available as a [CSV file](play/androiddevolperdashboardhistory.csv).

Google also [publishes some additional information about build numbers and code names](https://source.android.com/source/build-numbers.html).

{%
with open('input/play/androiddevolperdashboardhistory.csv') as csvfile:
	reader = csv.reader(csvfile)
	# TODO parse the CSV file and produce a html table
%}
