#!/usr/bin/env python3

# Copyright (C) Daniel Carter 2019
# Licensed under the 2-clause BSD licence

# Tools to load usage data

import os
import json

import pandas
from datetime import datetime

def load_device_analyzer_data(path):
    """Load Device Analyzer Data from file"""
    if not os.path.isfile(path):
        raise Exception('Device Analyzer data not found')

    records = dict()
    with open(path, 'r') as f:
        rjson = json.load(f)
        for sdate, counts in rjson.items():
            date = datetime.strptime(sdate, '%Y-%m-%d').date()
            records[date] = counts
    return records

def get_usage_statistics(path):
    """Load Android version usage data"""
    if not os.path.isfile(path):
        raise Exception('Usage data not found')
    # Read data in, remove unnecessary columns and replace blank cells with zeros
    values = pandas.read_csv(path, header=1, skiprows=[2],
                             usecols=(lambda x: 'Unnamed' not in x), parse_dates=[0], index_col=0)
    #values.rename(columns = {'API version:':'Date'}, inplace = True)
    values.fillna(0, inplace=True)
    return values

def get_os_to_api(path):
    """Load in a JSON dictionary mapping OS versions to API versions"""
    if not os.path.isfile(path):
        raise Exception('OS to API data not found')
    with open(path, 'r') as f:
        return json.load(f)
    return None
    

def get_api_to_os(path):
    """Load in a JSON dictionary mapping API versions to OS versions"""
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
    # Get the number of the column with the nearest date
    col = scores.columns.get_loc(date, method='backfill')
    # Get the date associated with this column number
    lookup_date = scores.columns[col]
    # Look this column up in the table
    score_col = scores[lookup_date]
    # Get the coorect row
    return score_col.loc[version]
