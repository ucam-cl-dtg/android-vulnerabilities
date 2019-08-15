# Copyright (C) Daniel Carter 2019
# Licenced under the 2-clause BSD licence

import numpy as np
import pandas
import matplotlib.pyplot as plt
from matplotlib import colors

from graph_utils import *
from pyplot_utils import load_graph_colours, get_bounds

START_YEAR = 2009

versions = load_version_list('../../input/release_dates.json')

#versions.append('all')
dates = dates_to_today(START_YEAR)
grid = np.zeros((len(versions), len(dates)), dtype=int)


for vindex, version in enumerate(versions):
    print('Analysing version {v}'.format(v=version))

    for dindex, date in enumerate(dates):
        path = '../../output/graphs/{:s}/graph-{:d}-{:02d}.gv'.format(version, date.year, date.month)
        graph = import_graph(path)
        if graph is None:
            grid[vindex, dindex] = -1
            continue

        # Experimental: remove fixed edges
        #graph = remove_patched(graph)

        # Add "backwards" edges and remove duplicates
        add_backwards_edges(graph)
        sgraph = strictify(graph)

        # Sequence of odd numbered 'priorities' as they are unambiguously between even numbered limits below
        if dfs(sgraph, 'remote', 'kernel'):
            grid[vindex, dindex] = 17
        elif dfs(sgraph, 'remote', 'system'):
            grid[vindex, dindex] = 15
        elif dfs(sgraph, 'remote', 'user'):
            grid[vindex, dindex] = 13
        elif dfs(sgraph, 'network', 'kernel'):
            grid[vindex, dindex] = 11
        elif dfs(sgraph, 'network', 'system'):
            grid[vindex, dindex] = 9
        elif dfs(sgraph, 'network', 'user'):
            grid[vindex, dindex] = 7
        elif dfs(sgraph, 'user', 'kernel'):
            grid[vindex, dindex] = 5
        elif dfs(sgraph, 'user', 'system'):
            grid[vindex, dindex] = 3
        else:
            grid[vindex, dindex] = 1

# Export table as csv
data = pandas.DataFrame(grid, columns=dates, index=versions)
data.to_csv('version_scores.csv')

scores, colours, legend = load_graph_colours()

# Set up mapping of values to colours
cmap = colors.ListedColormap(colours.keys())
bounds = get_bounds(scores)
norm = colors.BoundaryNorm(bounds, cmap.N)

# Only show every third date
datepoints = [str(date) if index % 3 == 0 else '' for index, date in enumerate(dates)]

plt.matshow(grid, cmap=cmap, norm=norm)
plt.xticks(np.arange(len(datepoints)), datepoints, rotation=45, ha='left')
plt.yticks(np.arange(len(versions)), versions)
plt.legend(handles=legend)

plt.show()
