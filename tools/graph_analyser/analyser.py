#!/usr/bin/env python3

# Copyright (C) Daniel Carter 2019
# Licensed under the 2-clause BSD licence

# Plots a coloured matrix of Android versions over time, showing the types of exploit possible per month per version

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

        # Get level of possible exploit
        grid[vindex, dindex] = get_score(sgraph)

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

plt.rc('axes', titlesize=24)
plt.rc('axes', labelsize=18)
plt.rc('legend', fontsize=14)

plt.matshow(grid, cmap=cmap, norm=norm)
plt.gca().xaxis.tick_bottom()
plt.title('Android versions vulnerable to attack')
plt.xticks(np.arange(len(datepoints)), datepoints, rotation=-45, ha='left')
plt.yticks(np.arange(len(versions)), versions)
plt.xlabel('Date')
plt.ylabel('Android version')
plt.legend(handles=legend)

plt.show()
