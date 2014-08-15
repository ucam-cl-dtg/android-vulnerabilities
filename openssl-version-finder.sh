#!/bin/bash

# Run this script inside a checkout of android/external/openssl to generate a json file
# containing the android tag to openssl version mapping

output=`dirname $(readlink -f $0)`'/input/tag_to_openssl_version.json'
echo '{' > $output 
for tag in `git tag`
do
	git checkout --quiet $tag
	if [ -f openssl.version ]
	then
		version=`cat openssl.version | cut -d'=' -f 2 | grep -v '#'`
		echo "    \"$tag\" : \"$version\"," >> $output
	fi
done
echo '}' >> $output
