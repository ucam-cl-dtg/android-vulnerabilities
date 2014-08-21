#!/bin/bash

# Run this script inside a checkout of android/external/openssl to generate a json file
# containing the android tag to openssl version mapping

set -e
 
project_id=$1

if [ -z "$2" ]
then
    version_file="pom.xml"
else
    version_file=$2
fi

output=`dirname $(readlink -f $0)`"/input/tag_to_${project_id}_version.json"


echo '{' > $output 
for tag in `git tag`
do
	git checkout --quiet $tag
	#echo $tag
	if [ -f $version_file ]
	then
		version=`xmlstarlet sel -T -t -m '//_:project/_:version' -v '.' -n $version_file`
		echo "    \"$tag\" : \"$version\"," >> $output
	else
		echo "File not found: $version_file for $tag"
	fi
done
echo '}' >> $output
