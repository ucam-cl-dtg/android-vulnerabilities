#!/usr/bin/env python3

# Copyright (C) Daniel Carter 2019
# Licensed under the 2-clause BSD licence

# Plots dates when each device in the sample was updated

import json
from datetime import datetime

import numpy as np
import matplotlib.pyplot as plt

from graph_utils import dates_to_today

def date_index(start_year, date):
    """Returns the number of months that have passed since January of start_year"""
    return (date.year - start_year) * 12 + (date.month - 1)

START_YEAR = 2009
PATCH_PATH = '../../data/device_patch_dates.json'

# Months to plot data for
dates = dates_to_today(START_YEAR)
#date_length = date_index(START_YEAR, datetime.now())

# Load patching data from file
with open(PATCH_PATH, 'r') as f:
    devices = json.load(f)

grid = np.zeros((len(devices), len(dates)), dtype=int)

for dindex, device in enumerate(devices):
    for sdate in device:
        date = datetime.strptime(sdate, '%Y-%m-%d')
        date_pos = date_index(START_YEAR, date)
        grid[dindex, date_pos] = 1

datepoints = [str(date) if index % 3 == 0 else '' for index, date in enumerate(dates)]

plt.rc('axes', titlesize=24)
plt.rc('axes', labelsize=18)
plt.rc('legend', fontsize=14)

plt.matshow(grid)#, cmap=cmap, norm=norm)
plt.gca().xaxis.tick_bottom()
plt.title('Android device patching dates')
plt.xticks(np.arange(len(datepoints)), datepoints, rotation=-45, ha='left')
#plt.yticks(np.arange(len(versions)), versions)
plt.xlabel('Date')
plt.ylabel('Device')
#plt.legend(handles=legend)

plt.show()
