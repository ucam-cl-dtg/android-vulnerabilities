#!/bin/bash

# Run this script inside a checkout of android/external/openssl to generate a json file
# containing the android tag to openssl version mapping

set -e

project_id=$1
version_file=$2
project_key=$3
version_sed=$4

output=`dirname $(readlink -f $0)`"/input/tag_to_${project_id}_version.json"
echo '{' > $output 
for tag in `git tag`
do
	git checkout --quiet $tag
	if [ -f "${version_file}" ] &&  grep $project_key $version_file >/dev/null
	then
		version=`cat "${version_file}" | grep -e "\s$project_key" | tr -s ' ' | tr '	' ' ' | sed 's/, /,/g' | cut -d' ' -f 3 | sed 's/"//g' | grep -e '[0-9]' | uniq`
		if [ -n "$version_sed" ]
		then
			version=`echo $version | sed $version_sed`
		fi
		version=`echo $version | grep '\.' | sed 's/\s//g'`
		echo "    \"$tag\" : \"$version\"," >> $output
	else
		echo "File or key not found: ${version_file} in $tag"
	fi
done
echo '}' >> $output
