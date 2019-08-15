#!/usr/bin/env python

# Copyright (C) Daniel Carter 2019
# Licenced under the 2-clause BSD licence

# Analysis of usage data to plot a graph of the proportion of vulnerable devices

import os
import json

import numpy as np
import pandas
import matplotlib.pyplot as plt

from pyplot_utils import load_graph_colours

def get_api_to_os(path):
    '''Load in a JSON dictionary mapping API versions to OS versions'''
    if not os.path.isfile(path):
        raise Exception('OS to API data not found')
    data = dict()
    with open(path, 'r') as f:
        rjson = json.load(f)
        for key, value in rjson.items():
            # Deliberately reversing the order
            if value in data and data[value] < key:
                pass
            else:
                data[value] = key
    return data

def get_score(date, version, scores):
    '''Get the exploitation score of a given version on a given date'''
    if version == '4.4W':
        return -1
    # Get the number of the column with the nearest date
    col = scores.columns.get_loc(date, method='backfill')
    # Get the date associated with this column number
    lookup_date = scores.columns[col]
    # Look this column up in the table
    score_col = scores[lookup_date]
    # Get the coorect row
    return score_col.loc[version]

pandas.plotting.register_matplotlib_converters()

# Path to read data from
PATH = '../../input/'

# Read data in, remove unnecessary columns and replace blank cells with zeros
values = pandas.read_csv(PATH+'play/androiddevolperdashboardhistory.csv', header=1, skiprows=[2],
                         usecols=(lambda x: 'Unnamed' not in x), parse_dates=[0], index_col=0)
#values.rename(columns = {'API version:':'Date'}, inplace = True)
values.fillna(0, inplace=True)

# Load in vulnerability scores for each version
version_scores = pandas.read_csv('version_scores.csv', index_col=0)
version_scores.columns = pandas.to_datetime(version_scores.columns)

# Convert API versions from spreadsheet into (estimated) OS versions
api_to_os = get_api_to_os(PATH + 'os_to_api.json')
values.columns = np.vectorize(lambda x: api_to_os[x])(values.columns)

scores, colours, legend = load_graph_colours()

scored_output = pandas.DataFrame(columns=scores, index=values.index, data=0.0)

for date in scored_output.index:
    for index, version in enumerate(values.columns):
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
