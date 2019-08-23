# Copyright (C) Daniel Carter 2019
# Licensed under the 2-clause BSD licence

# Helper functions for pyplot graph plotting

import os
import json
from collections import OrderedDict

from matplotlib import patches

_COLOUR_PATH = 'graph_colours.json'

def load_graph_colours():
    '''Import graph colour details from a JSON file, and create a legend panel'''
    if not os.path.isfile(_COLOUR_PATH):
        raise Exception('Colour data file not found')
    with open(_COLOUR_PATH, 'r') as f:
        # Read in json file and keep in order
        rjson = json.load(f, object_pairs_hook=OrderedDict)
        # List of possible vulnerability scores
        scores = []
        # Mapping of colours to descriptions
        colours = OrderedDict()
        # Items to be put onto graph legend panel
        legend = []
        for score, colour_set in rjson.items():
            scores.append(int(score))
            colour = colour_set['Colour']
            desc = colour_set['Description']
            colours[colour] = desc
            # Create a colour block for the legend panel
            legend.append(patches.Patch(color=colour, label=desc))
    return scores, colours, legend

def export_graph_colours(scores, colours):
    '''Export graph colours to a JSON file'''
    colout = OrderedDict()
    for index, key in enumerate(colours.keys()):
        score = scores[index]
        val = dict()
        val['Colour'] = key
        val['Description'] = colours[key]
        colout[score] = val
    with open(_COLOUR_PATH, 'w') as f:
        json.dump(colout, f, indent=2)

def get_bounds(scores):
    '''Given a set of scores for vulnerability levels, calculate bounds that fall between them'''
    bounds = []
    # Lower bound is below first value
    bounds.append(scores[0] - 1)
    for index, score in enumerate(scores[1:]):
        # Average of two adjacent values
        # By looping over scores[1:] rather than scores, scores[index] is the element before score
        bounds.append((scores[index] + score) // 2)
    # Upper bound is above last value
    bounds.append(scores[-1] + 1)
    return bounds
