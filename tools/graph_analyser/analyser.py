import pygraphviz as pgv
import numpy as np
import matplotlib.pyplot as plt
from matplotlib import colors, patches
import datetime
import os
import json
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

path = '../../input/release_dates.json'
versions = []
if os.path.isfile(path):
    with open(path, 'r') as f:
        rjson = json.load(f)
        versions = list(rjson.keys())

#versions.append('all')
dates = dates_to_today(START_YEAR)
grid = np.zeros((len(versions), len(dates)))


for vindex, version in enumerate(versions):
    print('Analysing version {v}'.format(v=version))

    for dindex, date in enumerate(dates):
        path = '../../output/graphs/{:s}/graph-{:d}-{:02d}.gv'.format(version, date.year, date.month)
        if not os.path.isfile(path):
            grid[vindex, dindex] = -1
            continue

        # Import graph
        graph = pgv.AGraph(path)

        # Remove red (device-specific) edges
        graph.delete_edges_from([edge for edge in graph.edges() if edge.attr['color'] == 'red'])

        # Experimental: remove fixed edges
        #graph.delete_edges_from([edge for edge in graph.edges() if edge.attr['style'] == 'dashed'])

        # Add 'backwards' edges
        hierarchy = ['remote', 'proximity', 'network', 'user', 'access-to-data', 'modify-apps', 'control-hardware', 'system', 'unlock-bootloader', 'tee', 'root', 'kernel']
        for start in hierarchy:
            for end in hierarchy:
                if start == end:
                    break
                graph.add_edge(start, end)

        # Remove duplicate edges
        sgraph = strictify(graph)

        # Sequence of odd numbered 'priorities' as they are unambiguously between even numbered limits below
        if dfs(sgraph, 'remote', 'kernel'):
            grid[vindex, dindex] = 17
            continue
        if dfs(sgraph, 'remote', 'system'):
            grid[vindex, dindex] = 15
            continue
        if dfs(sgraph, 'remote', 'user'):
            grid[vindex, dindex] = 13
            continue
        if dfs(sgraph, 'network', 'kernel'):
            grid[vindex, dindex] = 11
            continue
        if dfs(sgraph, 'network', 'system'):
            grid[vindex, dindex] = 9
            continue
        if dfs(sgraph, 'network', 'user'):
            grid[vindex, dindex] = 7
            continue
        if dfs(sgraph, 'user', 'kernel'):
            grid[vindex, dindex] = 5
            continue
        if dfs(sgraph, 'user', 'system'):
            grid[vindex, dindex] = 3
            continue
        grid[vindex, dindex] = 1

# Store colours
colours = OrderedDict()
colours['gray'] = 'Not yet released'
colours['white'] = 'No known serious vulnerabilities'
colours['skyblue'] = 'user mode -> system user'
colours['aqua'] = 'user mode -> kernel'
colours['blue'] = 'local network -> user mode'
colours['yellow'] = 'local network -> system user'
colours['orange'] = 'local network -> kernel'
colours['red'] = 'remote -> user mode'
colours['darkred'] = 'remote -> system user'
colours['black'] = 'remote -> kernel'


# Set up mapping of values to colours
cmap = colors.ListedColormap(colours.keys())
bounds = [-2, 0, 2, 4, 6, 8, 10, 12, 14, 16, 18]
norm = colors.BoundaryNorm(bounds, cmap.N)

# Prepare legend
legend = []
for key, value in colours.items():
    legend.append(patches.Patch(color=key, label=value))

# Only show every third date
datepoints = [str(date) if index % 3 == 0 else '' for index, date in enumerate(dates)]

plt.matshow(grid, cmap=cmap, norm=norm)
plt.xticks(np.arange(len(datepoints)), datepoints, rotation=45, ha='left')
plt.yticks(np.arange(len(versions)), versions)
plt.legend(handles=legend)

plt.show()
