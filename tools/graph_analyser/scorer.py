#!/usr/bin/env python

# Copyright (C) Daniel Carter 2019
# Licenced under the 2-clause BSD licence

import math

import numpy as np
import matplotlib.pyplot as plt

from graph_utils import *

def get_score(date, version):
    """Calculates a vulnerability score for a given version on a given date"""
    path = '../../output/graphs/{:s}/graph-{:d}-{:02d}.gv'.format(version, date.year, date.month)
    graph = import_graph(path)
    if graph is None:
        return -1

    # Remove patched edges
    unpatched = remove_patched(graph)

    # Count the number of vulnerabilities, and double-weight unpatched ones (which are in both lists)
    counts = sum([count_edge(edge) for edge in graph.edges()]) + sum([count_edge(edge) for edge in unpatched.edges()])
    score = 2.0 / (1.0 + math.exp(0.01 * counts))

    add_backwards_edges(graph)

    # Remove duplicate edges
    sgraph = strictify(graph)

    # Add a value to the score based on the level of possible exploitation (by chaining exploits or otherwise)
    if dfs(sgraph, 'remote', 'kernel'):
        score += 0.0
    elif dfs(sgraph, 'remote', 'system'):
        score += 0.1
    elif dfs(sgraph, 'remote', 'user'):
        score += 0.2
    elif dfs(sgraph, 'network', 'kernel'):
        score += 0.3
    elif dfs(sgraph, 'network', 'system'):
        score += 0.4
    elif dfs(sgraph, 'network', 'user'):
        score += 0.5
    elif dfs(sgraph, 'user', 'kernel'):
        score += 0.6
    elif dfs(sgraph, 'user', 'system'):
        score += 0.7
    else:
        score += 1

    return score

def process_set(versions, dates, version_releases):
    """Take a set of releases with the same major version number, and plot them onto a line of the graph"""
    line = np.zeros(len(dates))
    # Keeps track of next item in the list
    next_item = 1
    for dindex, date in enumerate(dates):
        # Keep going through list, and stop just before reaching a version not yet released
        while next_item < len(versions) and date > version_releases[versions[next_item]]:
            next_item += 1
        # This is the most recent version in the set which has been released on this date
        version = versions[next_item - 1]
        # Calculate a score for the version and store it in the graph line
        line[dindex] = get_score(date, version)
    return line


START_YEAR = 2009
plt.rc('font', size=20)

# Load in version release dates
releases = load_version_dates('../../input/release_dates.json')
dates = dates_to_today(START_YEAR)

# Keep track of previous version so major version number changes can be identified
prev = ['','','']
current_set = []

# Don't use any versions prior to 5.0.0
found = False
for version in releases.keys():
    if version == '5.0.0':
        found = True
    if not found:
        continue

    print('Analysing version {v}'.format(v=version))

    nums = version.split('.')
    if len(nums) == 3 and nums[0] == prev[0] and nums[1] == prev[1]:
        # Just a minor release, so just add it to the set for this major version
        current_set.append(version)
    else:
        # New major version, so plot the previous major version and then start a new current set
        if len(current_set) != 0:
            line = process_set(current_set, dates, releases)
            plt.plot(np.array(dates)[line > 0], line[line > 0], label='{a}.{b}.x'.format(a=prev[0], b=prev[1]))
        current_set = [version]
        prev = nums

# Plot the last remaining major version
if len(current_set) != 0:
    line = process_set(current_set, dates, releases)
    plt.plot(np.array(dates)[line > 0], line[line > 0], label='{a}.{b}.x'.format(a=prev[0], b=prev[1]))

# Set slightly above maximum score (2.0) to so lines have a definite starting point
# and don't appear to come in from the top of the graph
plt.ylim([0, 2.25])

plt.rc('legend', fontsize=14)
plt.legend()
plt.title('Android Version Security Metric')
plt.xlabel('Date')
plt.ylabel('Score')

plt.show()
