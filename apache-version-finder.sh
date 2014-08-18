#!/bin/bash

# Run this script inside a checkout of android/external/openssl to generate a json file
# containing the android tag to openssl version mapping

set -e
 
project_id=$1

version_file=$2

output=`dirname $(readlink -f $0)`"/input/tag_to_${project_id}_version.json"

#echo $project_id $version_file $project_key $version_sed $output

function get_version_element {
	file=$1
	method=$2
	method_start=`grep -n "int $method" $file | cut -d':' -f 1`
	version_element=`tail --lines=+$method_start $file | grep return | head -n 1 | tr -s '[:space:];' ' ' | cut -d' ' -f 3`
	echo $version_element
}

echo '{' > $output 
for tag in `git tag`
do
	git checkout --quiet $tag
	if [ -f $version_file ]
	then
		major=`get_version_element $version_file getMajorVersionNum`
		release=`get_version_element $version_file getReleaseVersionNum`
		maintenance=`get_version_element $version_file getMaintenanceVersionNum`
		version="${major}.${release}.${maintenance}"
		echo "    \"$tag\" : \"$version\"," >> $output
	else
		echo "File not found: $version_file for $tag"
	fi
done
echo '}' >> $output
