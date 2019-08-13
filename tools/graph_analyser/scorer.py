# Copyright (C) Daniel Carter 2019
# Licenced under the 2-clause BSD licence

import pygraphviz as pgv
import numpy as np
import matplotlib.pyplot as plt
from matplotlib import colors, patches
import datetime
import os
import json
import math
import re
from collections import OrderedDict

START_YEAR = 2009

def strictify(graph, directed=True):
    result = pgv.AGraph(strict=True, directed=directed)
    result.add_edges_from(graph.edges())
    return result

def dfs(graph, start, end):
    visited = set()
    to_visit = [start]
    while len(to_visit) != 0:
        item = to_visit.pop()
        if item == end:
            return True
        visited.add(item)
        for neighbor in graph.out_neighbors(item):
            if neighbor not in visited:
                to_visit.append(neighbor)
    return False

def print_search(graph, start, end):
    print('{start} -> {end}: {result}'.format(start=start, end=end, result=dfs(graph, start, end)))

def dates_to_today(start_year):
    today = datetime.date.today()
    dates = []
    for year in range(start_year, today.year + 1):
        for month in range(1, 13):
            date = datetime.date(year, month, 1)
            if date > today:
                return dates
            dates.append(date)

def count_edge(edge):
    '''Count the number of vulnerabilities represented by a given edge'''
    text = edge.attr['label']
    if text == '':
        return 0
    # Look for a number on the label
    number = re.search(r'(?<=\()[0-9]*(?=\ vulnerabilities\))', text)
    if number == None:
        # If there isn't one, it's only for one vulnerability
        return 1
    else:
        return int(number.group())

path = '../../input/release_dates.json'
versions = []
if os.path.isfile(path):
    with open(path, 'r') as f:
        rjson = json.load(f)
        versions = list(rjson.keys())

#versions.append('all')
dates = dates_to_today(START_YEAR)

#prev = ['','','']
#for version in reversed(versions):
    #nums = version.split('.')
    #if len(nums) == 3 and nums[0] == prev[0] and nums[1] == prev[1]:
    #    continue
    #prev = nums

# Don't use any versions prior to 5.0.0
found = False
for version in versions:
    if version == '5.0.0':
        found = True
    if not found:
        continue

    print('Analysing version {v}'.format(v=version))
    line = np.zeros(len(dates))

    for dindex, date in enumerate(dates):
        path = '../../output/graphs/{:s}/graph-{:d}-{:02d}.gv'.format(version, date.year, date.month)
        if not os.path.isfile(path):
            line[dindex] = -1
            continue

        # Import graph
        graph = pgv.AGraph(path)

        # Remove red (device-specific) edges
        graph.delete_edges_from([edge for edge in graph.edges() if edge.attr['color'] == 'red'])

        # Make a copy and remove patched edges
        unpatched = graph.copy()
        unpatched.delete_edges_from([edge for edge in unpatched.edges() if edge.attr['style'] == 'dashed'])

        # Count the number of vulnerabilities, and double-weight unpatched ones (which are in both lists)
        score = sum([count_edge(edge) for edge in graph.edges()]) + sum([count_edge(edge) for edge in unpatched.edges()])
        line[dindex] = 2.0 / (1.0 + math.exp(0.01 * score))

        # Add 'backwards' edges
        hierarchy = ['remote', 'proximity', 'network', 'user', 'access-to-data', 'modify-apps', 'control-hardware', 'system', 'unlock-bootloader', 'tee', 'root', 'kernel']
        for start in hierarchy:
            for end in hierarchy:
                if start == end:
                    break
                graph.add_edge(start, end)

        # Remove duplicate edges
        sgraph = strictify(graph)

        # Add a value to the score based on the level of possible exploitation (by chaining exploits or otherwise)
        if dfs(sgraph, 'remote', 'kernel'):
            line[dindex] += 0.0
            continue
        if dfs(sgraph, 'remote', 'system'):
            line[dindex] += 0.1
            continue
        if dfs(sgraph, 'remote', 'user'):
            line[dindex] += 0.2
            continue
        if dfs(sgraph, 'network', 'kernel'):
            line[dindex] += 0.3
            continue
        if dfs(sgraph, 'network', 'system'):
            line[dindex] += 0.4
            continue
        if dfs(sgraph, 'network', 'user'):
            line[dindex] += 0.5
            continue
        if dfs(sgraph, 'user', 'kernel'):
            line[dindex] += 0.6
            continue
        if dfs(sgraph, 'user', 'system'):
            line[dindex] += 0.7
            continue
        line[dindex] += 1

    indices = line>0
    plt.plot(np.array(dates)[line>0], line[line>0], label=version)

plt.legend()

plt.show()
