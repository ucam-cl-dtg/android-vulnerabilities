#!/bin/bash

set -e

android_external=~/git/upstreams/android/external/
output=`dirname $(readlink -f $0)`"/input/external_lines_of_code.json"
echo '{' >> $output
for project in `ls $android_external`
do
	lines=`sloccount $android_external"/"$project | grep 'Total Physical Source Lines of Code (SLOC)' | sed 's/ //g' | cut -d'=' -f 2 | sed 's/,//g'`
	echo "    \"$project\" : \"$lines\"," >> $output
done
echo '}' >> $output
