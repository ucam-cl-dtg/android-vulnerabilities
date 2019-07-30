import pygraphviz as pgv

# Currently non-functional

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
        for neighbor in graph.neighbors(item):
            if neighbor not in visited:
                to_visit.append(neighbor)
    return False

def print_search(graph, start, end):
    print('{start} -> {end}: {result}'.format(start=start, end=end, result=dfs(graph, start, end)))

for year in range(2010, 2019):
    for month in range(1, 13):
        if year == 2019 and month > 7:
            # Nasty way to do this, but works for now
            break

        # Import graph
        graph = pgv.AGraph('../../output/graphs/all/graph-{:d}-{:02d}.gv'.format(year, month))

        # Add 'backwards' edges
        hierarchy = ['remote', 'proximity', 'network', 'user', 'access-to-data', 'modify-apps', 'control-hardware', 'system', 'unlock-bootloader', 'tee', 'root', 'kernel']
        for start in hierarchy:
            for end in hierarchy:
                if start == end:
                    break
                graph.add_edge(start, end)

        # Remove duplicate edges
        sgraph = strictify(graph)
        
        if dfs(sgraph, 'remote', 'system'):
            print('{month}/{year}: black'.format(month=month, year=year))
            continue
        if dfs(sgraph, 'remote', 'user'):
            print('{month}/{year}: red'.format(month=month, year=year))
            continue
        if dfs(sgraph, 'network', 'system'):
            print('{month}/{year}: orange'.format(month=month, year=year))
            continue
        if dfs(sgraph, 'network', 'user'):
            print('{month}/{year}: yellow'.format(month=month, year=year))
            continue
        if dfs(sgraph, 'user', 'system'):
            print('{month}/{year}: blue'.format(month=month, year=year))
            continue
        print('{month}/{year}: white'.format(month=month, year=year))

#print(graph.edges())
#print(strictify(graph).edges())
