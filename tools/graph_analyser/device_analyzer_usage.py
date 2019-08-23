#!/usr/bin/env python3

# Copyright (C) Daniel Carter 2019
# Licensed under the 2-clause BSD licence

# Analysis of Device Analyzer usage data to plot a graph of the proportion of vulnerable devices

import pandas
import matplotlib.pyplot as plt
from datetime import date

from pyplot_utils import load_graph_colours
from data_utils import load_device_analyzer_data

pandas.plotting.register_matplotlib_converters()

PATH = '../../data/exploitable_devices.json'

records = load_device_analyzer_data(PATH)

# Uncomment to only use data from August 2015 onwards (date of first Android Security Bulletin)
#records = {month:counts for month, counts in records.items() if month >= date(2015,8,1)}

scores, colours, legend = load_graph_colours()

# Dataframe for output
scored_output = pandas.DataFrame(columns=scores, index=sorted(records.keys()), data=0.0)

for date, device_counts in records.items():
    for score, devices in device_counts.items():
        scored_output.at[date, int(score)] = devices

# Display the whole table when printing the results
pandas.set_option('display.max_rows', None)
print(scored_output)

# Write data to output file
#scored_output.to_csv('da_vulnerable_device_proportion.csv', index=True)

# Normalise data so graph is constant height
percent_output = scored_output.divide(scored_output.sum(axis=1), axis=0)

plt.rc('font', size=20)
plt.rc('legend', fontsize=14)

plt.stackplot(percent_output.index, percent_output.transpose(), colors=colours.keys())
plt.legend(handles=legend, loc='lower left')
# Line below works better if using August 2015 onwards only
#plt.legend(handles=legend, loc='upper left')
plt.title('Proportion of devices vulnerable (best-case, using Device Analyzer data)')
plt.xlabel('Date')
plt.ylabel('Proportion of devices')
plt.autoscale(enable=True, tight=True)
plt.show()
