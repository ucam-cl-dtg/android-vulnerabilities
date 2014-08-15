#!/bin/bash

set -e

android_external=~/git/upstreams/android/external/
version_finder=`dirname $(readlink -f $0)`"/version-finder.sh"
define_version_finder=`dirname $(readlink -f $0)`"/define-version-finder.sh"

entries="$version_finder|openssl
$version_finder|bouncycastle|bouncycastle.version|BOUNCYCASTLE_VERSION|s/\([0-9]\)\([0-9]\+\)/\1.\2/
$version_finder|libogg|configure|VERSION
$define_version_finder|libxml2|config.h|VERSION
$define_version_finder|openssh|version.h|SSH_VERSION|s/OpenSSH_\([0-9.]\+\)/\1/"

for entry in $entries
do
  entry=`echo $entry | tr '|' ' '`
  project_id=`echo $entry | cut -d' ' -f 2`
  pushd $android_external$project_id
  echo $entry
  $entry
  popd
done
