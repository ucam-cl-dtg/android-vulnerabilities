# Copyright (C) Daniel Carter 2019
# Licenced under the 2-clause BSD licence

import datetime
import json
import os
import re

import pygraphviz as pgv

_DEVICE_SPECIFIC_COLOR = 'red'
_PATCHED_VULNERABILITY_STYLE = 'dashed'

def strictify(graph, directed=True):
    '''Make a non-strict graph into a strict graph (with no duplicate edges)'''
    result = pgv.AGraph(strict=True, directed=directed)
    result.add_edges_from(graph.edges())
    return result

def dfs(graph, start, end):
    '''Run depth-first search on graph from start to end'''
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

def dates_to_today(start_year):
    '''Generate a list of dates from the beginning of start_year to the current date'''
    today = datetime.date.today()
    dates = []
    for year in range(start_year, today.year + 1):
        for month in range(1, 13):
            date = datetime.date(year, month, 1)
            if date > today:
                return dates
            dates.append(date)
    return dates

def count_edge(edge):
    '''Count the number of vulnerabilities represented by a given edge'''
    text = edge.attr['label']
    if text == '':
        return 0
    # Look for a number on the label
    number = re.search(r'(?<=\()[0-9]*(?=\ vulnerabilities\))', text)
    if number is None:
        # If there isn't one, it's only for one vulnerability
        return 1
    return int(number.group())

def load_version_list(path):
    '''Load the list of Android versions from the path given'''
    if os.path.isfile(path):
        with open(path, 'r') as f:
            rjson = json.load(f)
            return list(rjson.keys())
    return []

def import_graph(path, device_specific=False):
    '''Import a GraphViz file'''
    if not os.path.isfile(path):
        return None
    graph = pgv.AGraph(path)
    if not device_specific:
        # Remove red (device-specific) edges
        graph.delete_edges_from([edge for edge in graph.edges()
                                 if edge.attr['color'] == _DEVICE_SPECIFIC_COLOR])
    return graph

def add_backwards_edges(graph):
    '''Add edges which lower privileges (e.g. an attacker with root access can access user mode'''
    hierarchy = ['remote', 'proximity', 'network', 'user', 'access-to-data', 'modify-apps',
                 'control-hardware', 'system', 'unlock-bootloader', 'tee', 'root', 'kernel']
    for start in hierarchy:
        for end in hierarchy:
            if start == end:
                break
            graph.add_edge(start, end)

def remove_patched(graph):
    '''Returns a copy of the graph with only unpatched vulnerabilities'''
    unpatched = graph.copy()
    unpatched.delete_edges_from([edge for edge in unpatched.edges()
                                 if edge.attr['style'] == _PATCHED_VULNERABILITY_STYLE])
    return unpatched

def get_score(graph):
    '''Gives a score based on the exploits possible for a particular graph'''
    # Sequence of odd numbered 'priorities' as they are unambiguously between even numbered limits below
    if dfs(graph, 'remote', 'kernel'):
        return 17
    elif dfs(graph, 'remote', 'system'):
        return 15
    elif dfs(graph, 'remote', 'user'):
        return 13
    elif dfs(graph, 'network', 'kernel'):
        return 11
    elif dfs(graph, 'network', 'system'):
        return 9
    elif dfs(graph, 'network', 'user'):
        return 7
    elif dfs(graph, 'user', 'kernel'):
        return 5
    elif dfs(graph, 'user', 'system'):
        return 3
    return 1

