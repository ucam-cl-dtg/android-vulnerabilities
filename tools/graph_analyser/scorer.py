# Copyright (C) Daniel Carter 2019
# Licenced under the 2-clause BSD licence

import math

import numpy as np
import matplotlib.pyplot as plt

from graph_utils import *

#def make_color_map(size):
    # Not currently used and needs more work
    #colormap = plt.cm.tab20
    #colors = [colormap(i) for i in np.linspace(0, 1, size)]
    #return colors

START_YEAR = 2009

versions = load_version_list('../../input/release_dates.json')
dates = dates_to_today(START_YEAR)

#prev = ['','','']
#for version in reversed(versions):
    #nums = version.split('.')
    #if len(nums) == 3 and nums[0] == prev[0] and nums[1] == prev[1]:
    #    continue
    #prev = nums

# Don't use any versions prior to 5.0.0
found = False
for vindex, version in enumerate(versions):
    if version == '5.0.0':
        found = True
    if not found:
        continue

    print('Analysing version {v}'.format(v=version))
    line = np.zeros(len(dates))

    for dindex, date in enumerate(dates):
        path = '../../output/graphs/{:s}/graph-{:d}-{:02d}.gv'.format(version, date.year, date.month)
        graph = import_graph(path)
        if graph is None:
            line[dindex] = -1
            continue

        # Remove patched edges
        unpatched = remove_patched(graph)

        # Count the number of vulnerabilities, and double-weight unpatched ones (which are in both lists)
        score = sum([count_edge(edge) for edge in graph.edges()]) + sum([count_edge(edge) for edge in unpatched.edges()])
        line[dindex] = 2.0 / (1.0 + math.exp(0.01 * score))

        add_backwards_edges(graph)

        # Remove duplicate edges
        sgraph = strictify(graph)

        # Add a value to the score based on the level of possible exploitation (by chaining exploits or otherwise)
        if dfs(sgraph, 'remote', 'kernel'):
            line[dindex] += 0.0
        elif dfs(sgraph, 'remote', 'system'):
            line[dindex] += 0.1
        elif dfs(sgraph, 'remote', 'user'):
            line[dindex] += 0.2
        elif dfs(sgraph, 'network', 'kernel'):
            line[dindex] += 0.3
        elif dfs(sgraph, 'network', 'system'):
            line[dindex] += 0.4
        elif dfs(sgraph, 'network', 'user'):
            line[dindex] += 0.5
        elif dfs(sgraph, 'user', 'kernel'):
            line[dindex] += 0.6
        elif dfs(sgraph, 'user', 'system'):
            line[dindex] += 0.7
        else:
            line[dindex] += 1

    plt.plot(np.array(dates)[line > 0], line[line > 0], label=version)

plt.ylim([0, 2])
plt.legend()

plt.show()
