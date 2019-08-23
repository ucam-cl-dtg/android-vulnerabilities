#!/usr/bin/env python3

# Copyright (C) Daniel Carter 2019
# Licensed under the 2-clause BSD licence

# Analysis of Device Analyzer usage data, stratified by OS version in use

import numpy as np
import pandas
import matplotlib.pyplot as plt
from datetime import date

from pyplot_utils import load_graph_colours
from data_utils import get_usage_statistics, load_device_analyzer_data, get_os_to_api, get_score

pandas.plotting.register_matplotlib_converters()

# Path to read data from
#PATH = '../../input/'

usage_statistics = get_usage_statistics('../../input/play/androiddevolperdashboardhistory.csv')
da_data = load_device_analyzer_data('../../data/exploitable_devices_stratified.json')
os_to_api = get_os_to_api('../../input/os_to_api.json')

# Uncomment to only use data from August 2015 onwards (date of first Android Security Bulletin)
#da_data = {month:counts for month, counts in da_data.items() if month >= date(2015,8,1)}

scores, colours, legend = load_graph_colours()

# Dataframe for output data
scored_output = pandas.DataFrame(columns=scores, index=sorted(da_data.keys()), data=0.0)

for date, device_counts in da_data.items():
    for version, device_scores in device_counts.items():
        for score, devices in device_scores.items():
            # Give version a minor release number if it doesn't have one already
            dots = version.count('.')
            if dots > 2:
                raise Exception('Invalid version string: ' + version)
            while dots < 2:
                version += '.0'
                dots = version.count('.')
            if version not in os_to_api:
                continue
            api = os_to_api[version]
            version_usage = get_score(date, api, usage_statistics.transpose())
            scored_output.at[date, int(score)] += devices * version_usage

# Display the whole table when printing the results
pandas.set_option('display.max_rows', None)
print(scored_output)

# Write data to output file
#scored_output.to_csv('da_stratified_vulnerable_device_proportion.csv', index=True)

# Normalise data so graph is constant height
percent_output = scored_output.divide(scored_output.sum(axis=1), axis=0)

plt.rc('font', size=20)
plt.rc('legend', fontsize=14)

plt.stackplot(percent_output.index, percent_output.transpose(), colors=colours.keys())
plt.legend(handles=legend, loc='lower left')
# Line below works better if using August 2015 onwards only
#plt.legend(handles=legend, loc='upper left')
plt.title('Proportion of devices vulnerable (Device Analyzer data, stratified by version)')
plt.xlabel('Date')
plt.ylabel('Proportion of devices')
plt.autoscale(enable=True, tight=True)
plt.show()
