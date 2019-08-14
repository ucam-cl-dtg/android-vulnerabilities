# Copyright (C) Daniel Carter 2019
# Licenced under the 2-clause BSD licence

from matplotlib import patches
from collections import OrderedDict
import os
import json

COLOUR_PATH = 'graph_colours.json'

def load_graph_colours():
    '''Import graph colour details from a JSON file, and create a legend panel'''
    if not os.path.isfile(COLOUR_PATH):
        raise Exception('Colour data file not found')
    with open(COLOUR_PATH, 'r') as f:
        rjson = json.load(f, object_pairs_hook=OrderedDict)
        scores = []
        colours = OrderedDict()
        legend = []
        for score, colour_set in rjson.items():
            scores.append(int(score))
            colour = colour_set['Colour']
            desc = colour_set['Description']
            colours[colour] = desc
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
    with open(COLOUR_PATH, 'w') as f:
        json.dump(colout, f, indent=2)
