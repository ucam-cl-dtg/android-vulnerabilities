#!/usr/bin/env bash

# Takes a folder of .DOT files and produces PDF files with a graph of each one

# By default, works on folder of all vulnerabilities
VERSION=${1:-all}

echo "Script to produce PDF files of graph data"
if [ ! -d "graphs/$VERSION" ]; then
    echo "No files found for this Android version"
    exit 1
fi

echo "Producing individual graphs..."
cd graphs/$VERSION
find *.gv | xargs dot -Tpdf -O
echo "Combining into one file..."
pdfunite *.gv.pdf all.pdf
echo "Done"
