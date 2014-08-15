#!/bin/bash

# Run this script inside a checkout of android/external/openssl to generate a json file
# containing the android tag to openssl version mapping

project_id=$1
project_key=`echo $project_id | tr a-z A-Z`"_VERSION"

output=`dirname $(readlink -f $0)`"/input/tag_to_${project_id}_version.json"
echo '{' > $output 
for tag in `git tag`
do
	git checkout --quiet $tag
	if [ -f "${project_id}.version" ]
	then
		version=`cat "${project_id}.version" | grep $project_key | cut -d'=' -f 2 | grep -v '#'`
		echo "    \"$tag\" : \"$version\"," >> $output
	fi
done
echo '}' >> $output
