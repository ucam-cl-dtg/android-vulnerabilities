# AndroidVulnerabilities.org
The https://androidvulnerabilities.org/ website and source data.

## To run
* Download [Poole](https://bitbucket.org/obensonne/poole/src/default/) and set it up on your system
* Clone this repository onto your system
* In the root directory of this repository, run:
    - `poole.py --build --md-ext=markdown.extensions.extra` to build the source code (may take a long time)
	- `poole.py --serve` to run the website
* Then go to [http://localhost:8080] to view the site

## Other utilities
* The web scraper (`tools/scraper/scraper.py`) will take vulnerability details from Google's Android Security Bulletins. Please see `tools/scraper/README.md` for more details.
* Graph analysis tools:
    - `analyser.py` plots a month-by-month matrix of how different Android versions can be exploited
	- `actual_usage.py` uses the Google Play Dashboard usage data to estimate the number of devices which can be exploited in different ways over time
	- `device_analyzer_usage.py` does a similar process using data gathered by the Device Analyzer project
	- `scorer.py` plots an overall vulnerability score over time for different versions of Android

Data on vulnerability storage format is in `input/vulnerabilities`.
