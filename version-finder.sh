#!/bin/bash

# Run this script inside a checkout of android/external/openssl to generate a json file
# containing the android tag to openssl version mapping

set -e
 
project_id=$1

if [ -z "$2" ]
then
	version_file="${project_id}.version"
else
	version_file=$2
fi

if [ -z "$3" ]
then
	project_key=`echo $project_id | tr a-z A-Z`"_VERSION"
else
	project_key=$3
fi

version_sed=$4

output=`dirname $(readlink -f $0)`"/input/tag_to_${project_id}_version.json"
echo '{' > $output 
for tag in `git tag`
do
	git checkout --quiet $tag
	if [ -f $version_file ]
	then
		version=`cat $version_file | grep $project_key | cut -d'=' -f 2 | grep -v '#' | grep -e '^[0-9.]\+$'`
		if [ -n "$version_sed" ]
		then
			version=`echo $version | sed $version_sed`
		fi
		echo "    \"$tag\" : \"$version\"," >> $output
	fi
done
echo '}' >> $output