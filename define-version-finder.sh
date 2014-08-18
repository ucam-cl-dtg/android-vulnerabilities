#!/bin/bash

# Run this script inside a checkout of android/external/openssl to generate a json file
# containing the android tag to openssl version mapping

set -e

project_id=$1
version_file=$2
project_key="$3"
version_sed=$4

#echo $project_id $version_file $project_key $version_sed

output=`dirname $(readlink -f $0)`"/input/tag_to_${project_id}_version.json"
echo '{' > $output 
for tag in `git tag`
do
	git checkout --quiet $tag
	version=""
	# support multiple possible version file locations
	for real_version_file in `echo $version_file | tr '£' ' '`
	do
	if [ -f "${real_version_file}" ] &&  grep "$project_key" $real_version_file >/dev/null
	then
		version=`cat "${real_version_file}" | grep -e "\s$project_key" | tr -s ' ' | tr '	' ' ' | sed 's/, /,/g' | cut -d' ' -f 3 | sed 's/"//g' | grep -e '[0-9]' | uniq`
#		echo $version $version_sed
		if [ -n "$version_sed" ]
		then
			version=`echo $version | sed $version_sed`
		fi
		version=`echo $version | grep '\.' | sed 's/\s//g'`
		if [ -n "$version" ]
		then
			echo "    \"$tag\" : \"$version\"," >> $output
			break
		fi
	fi
	done
	if [ -z "$version" ]
	then
		echo "File or key not found: ${version_file} for $tag"
	fi
done
echo '}' >> $output
