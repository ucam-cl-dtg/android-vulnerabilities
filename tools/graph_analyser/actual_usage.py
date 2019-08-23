#!/usr/bin/env python3

# Copyright (C) Daniel Carter 2019
# Licensed under the 2-clause BSD licence

# Analysis of usage data to plot a graph of the proportion of vulnerable devices

import numpy as np
import pandas
import matplotlib.pyplot as plt

from pyplot_utils import load_graph_colours
from data_utils import get_usage_statistics, get_api_to_os, get_score

pandas.plotting.register_matplotlib_converters()

# Path to read data from
PATH = '../../input/'

values = get_usage_statistics(PATH + 'play/androiddevolperdashboardhistory.csv')

# Load in vulnerability scores for each version
version_scores = pandas.read_csv('version_scores.csv', index_col=0)
version_scores.columns = pandas.to_datetime(version_scores.columns)

# Convert API versions from spreadsheet into (estimated) OS versions
api_to_os = get_api_to_os(PATH + 'os_to_api.json')
values.columns = np.vectorize(lambda x: api_to_os[x])(values.columns)

scores, colours, legend = load_graph_colours()

# Dataframe for output data
scored_output = pandas.DataFrame(columns=scores, index=values.index, data=0.0)

for date in scored_output.index:
    for index, version in enumerate(values.columns):
        if version == '4.4W':
            # No data for Android Wear
            score = -1
        else:
            score = get_score(date, version, version_scores)
        usage = values.at[date, version]
        scored_output.at[date, score] += usage

# Display the whole table when printing the results
pandas.set_option('display.max_rows', None)
print(scored_output)

# Write data to output file
scored_output.to_csv('vulnerable_device_proportion.csv', index=True)

# Normalise data so graph is constant height
# (original data may not add up to 100% due to rounding errors)
percent_output = scored_output.divide(scored_output.sum(axis=1), axis=0)

plt.rc('font', size=20)
#plt.rc('figure', titlesize=30)
plt.rc('legend', fontsize=14)

plt.stackplot(percent_output.index, percent_output.transpose(), colors=colours.keys())
plt.legend(handles=legend)
plt.title('Proportion of devices vulnerable to attack')
plt.xlabel('Date')
plt.ylabel('Proportion of devices')
plt.autoscale(enable=True, tight=True)
plt.show()
