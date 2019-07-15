#!/bin/bash

# Takes a folder of .DOT graph files and produces an animated GIF of the graph data
# Default delay between frames of 80 units (= 800ms)
DELAY=${1:-80}

echo "Script to produce animated GIF of graph data"
echo "Creating images of graph data..."
cd graphs
mkdir -p graph_temp/sized
find *.gv | xargs -I {} dot -Gsize=15,10\! -Gdpi=100 -Tgif {} -o ./graph_temp/{}.gif
echo "Resizing images..."
find *.gv | xargs -I {} convert ./graph_temp/{}.gif -gravity center -background white -extent 1500x1000 ./graph_temp/sized/{}.gif
echo "Combining into one animated GIF..."
convert -delay $DELAY -loop 0 ./graph_temp/sized/*.gif time.gif
echo "Clearing up..."
rm -r graph_temp
echo "Done"