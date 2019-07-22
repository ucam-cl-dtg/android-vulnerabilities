Web scraper for androidvulnerabilities.org

To use:
First download the NVD Data Feeds (https://nvd.nist.gov/vuln/data-feeds), decompress them, and place the decompressed files into the cve-data directory. Note that this is organised by the year in which the CVE number was issued, not the year the vulnerability appeared on a Google bulletin, and so some vulnerabilities have CVE numbers from previous years and several data feed files are required for a single year's set of bulletins.
The scraper can then be run (using python3 scraper.py) to collect data from the bulletins.

Manual data entry:
The scraper will combine details found in the manual-data directory with those located from the bulletins and NVD data. For critical vulnerabilities which do not have exploitation details, the scraper will prompt for these as it processes the vulnerability. These details will then be saved back to the manual-data folder (to allow it to be re-applied if the scraper is run again on the same dataset) as well as to the main data files.

Website data:
The website-data directory contains JSON files in the format for the androidvulnerabilities website to use (currently missing dates, but otherwise most information is present). These are slightly different from the standard JSON exported files, which are in the data directory.

Submitter details:
You may wish to enter your name (as it should show as the name of submitter on androidvulnerabilities.org) into a file named 'submitter' in this directory. This is not required, but speeds up the processing as the name does not then have to be entered each time the program is run.
