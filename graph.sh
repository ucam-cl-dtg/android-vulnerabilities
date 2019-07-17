#!/usr/bin/env bash

# Takes a folder of .DOT graph files and produces an animated GIF of the graph data
# By default, works on folder of all vulnerabilities
VERSION=${1:-all}
# Default delay between frames of 80 units (= 800ms)
DELAY=${2:-80}

if [ ! -d "output/graphs/$VERSION" ]; then
    echo "No files found for this Android version"
    exit 1
fi

cd output/graphs/$VERSION

if [ -z "$(ls -A | grep .gv)" ]; then
    echo "No data to plot"
    exit 0
fi

echo "Creating images of graph data..."
mkdir -p graph_temp
find *.gv | xargs -I {} dot -Gsize=15,10\! -Gdpi=100 -Tgif {} -o ./graph_temp/{}.gif
echo "Combining into one animated GIF..."
convert -delay $DELAY -loop 0 ./graph_temp/*.gif -gravity center -background white -extent 1500x1000 graphs.gif
echo "Creating thumbnail version..."
convert graphs.gif -scale 150x100 graphs-small.gif
echo "Clearing up..."
rm -r graph_temp
echo "Done"
