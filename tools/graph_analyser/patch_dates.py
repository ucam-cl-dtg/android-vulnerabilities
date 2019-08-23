#!/usr/bin/env python3

# Copyright (C) Daniel Carter 2019
# Licensed under the 2-clause BSD licence

# Plots dates when each device in the sample was updated

import json
from datetime import datetime

import numpy as np
import matplotlib.pyplot as plt
from matplotlib import colors

from graph_utils import dates_to_today

def date_index(start_year, date):
    """Returns the number of months that have passed since January of start_year"""
    return (date.year - start_year) * 12 + (date.month - 1)

def in_date_set(date_set, check_date):
    """Checks whether check_date is within any of the bounds in date_set"""
    check_month = datetime(year=check_date.year, month=check_date.month, day=1).date()
    for pair in date_set:
        p0 = datetime.strptime(pair[0], '%Y-%m-%d').date()
        p1 = datetime.strptime(pair[1], '%Y-%m-%d').date()
        if p0 <= check_month <= p1:
            return True
    return False

START_YEAR = 2010
PATCH_PATH = '../../data/device_patch_list.json'

# Months to plot data for
dates = dates_to_today(START_YEAR)
#date_length = date_index(START_YEAR, datetime.now())

# Load patching data from file
with open(PATCH_PATH, 'r') as f:
    devices = json.load(f)

grid = np.zeros((len(devices), len(dates)), dtype=int)

for dindex, dname in enumerate(devices):
    device = devices[dname]
    for mindex, month in enumerate(dates):
        if not in_date_set(device['usage_periods'], month):
            grid[dindex, mindex] = -2
    for sdate in device['patch_dates']:
        patch_date = datetime.strptime(sdate, '%Y-%m-%d')
        if patch_date > datetime.now():
            raise Exception('Patch date {d} is in the future'.format(d=str(patch_date)))
        date_pos = date_index(START_YEAR, patch_date)
        grid[dindex, date_pos] = 2

# Set up colour mapping
cmap = colors.ListedColormap(['gray', 'white', 'black'])
norm = colors.BoundaryNorm([-10, -1, 1, 10], cmap.N)

datepoints = [str(date) if index % 3 == 0 else '' for index, date in enumerate(dates)]

plt.rc('axes', titlesize=24)
plt.rc('axes', labelsize=18)
plt.rc('legend', fontsize=14)

plt.matshow(grid, cmap=cmap, norm=norm)
plt.subplots_adjust(bottom=0.15)
plt.gca().xaxis.tick_bottom()
plt.title('Android device patching dates')
plt.xticks(np.arange(len(datepoints)), datepoints, rotation=-45, ha='left')
plt.yticks(np.arange(len(devices.keys())), devices.keys())
plt.xlabel('Date')
plt.ylabel('Devices')

#plt.legend(handles=legend)

plt.show()
