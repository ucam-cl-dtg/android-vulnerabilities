#!/bin/bash

set -e

android_external=~/git/upstreams/android/external/
basedir=`dirname $(readlink -f $0)`
version_finder="$basedir/version-finder.sh"
define_version_finder="$basedir/define-version-finder.sh"
apache_version_finder="$basedir/apache-version-finder.sh"
pom_version_finder="$basedir/pom-version-finder.sh"

entries="$version_finder&openssl
$version_finder&bouncycastle&bouncycastle.version&BOUNCYCASTLE_VERSION&s/\([0-9]\)\([0-9]\+\)/\1.\2/
$version_finder&libogg&configure&VERSION
$define_version_finder&libxml2&config.h&VERSION
$define_version_finder&openssh&version.h&SSH_VERSION&s/OpenSSH_\([0-9.]\+\)/\1/
$define_version_finder&sonivox&arm-fm-22k/host_src/eas.h&LIB_VERSION&s/MAKE_LIB_VERSION(\([0-9]\+\),\([0-9]\+\),\([0-9]\+\),\([0-9]\+\))/\1.\2.\3.\4/
$version_finder&tcpdump&version.c&version
$define_version_finder&freetype&include/freetype/freetype.h&FREETYPE_&s/\s/./g
$define_version_finder&libnfc-nxp&src/phHal4Nfc.h&\(PH_HAL4NFC_VERSION\)\|\(PH_HAL4NFC_REVISION\)\|\(PH_HAL4NFC_PATCH\)\|\(PH_HAL4NFC_BUILD\)&s/\s/./g
$define_version_finder&elfutils&elfutils/version.h£version.h£config.h&\(_ELFUTILS_VERSION\s\)\|\(PACKAGE_VERSION\)&s/^\([0-9]\+\)$/0.\1/
$apache_version_finder&apache-xml&src/main/java/org/apache/xalan/Version.java
$define_version_finder&stlport&stlport/stl/_stlport_version.h&_STLPORT_VERSION\s&s/0x\([0-9]\)\([0-9]\)\([0-9]\)/\1.\2.\3/
$version_finder&linux-tools-perf&PERF-VERSION-FILE&PERF_VERSION
$define_version_finder&e2fsprogs&version.h&E2FSPROGS_VERSION
$define_version_finder&eigen&Eigen/src/Core/util/Macros.h&\(EIGEN_WORLD_VERSION\)\|\(EIGEN_MAJOR_VERSION\)\|\(EIGEN_MINOR_VERSION\)&s/\s/./g&cat
$version_finder&jmonkeyengine&engine/src/core/com/jme3/system/JmeVersion.java&FULL_NAME&s/jMonkeyEngine\(.*\)/\1/
$define_version_finder&protobuf&android/config.h&PACKAGE_VERSION
$define_version_finder&opencv&cxcore/include/cvver.h&CV_VERSION
$pom_version_finder&guava
$define_version_finder&sqlite&dist/sqlite3.h&SQLITE_VERSION\s
$define_version_finder&antlr&build.gradle&version
$define_version_finder&bison&linux-lib/config.h£config.h&PACKAGE_VERSION
$define_version_finder&libvpx&x86/vpx_version.h£vpx_version.h£generic/vpx_version.h&VERSION_STRING_NOSP&s/v\([0-9.]*\)\(-.*\)\?/\1/
$define_version_finder&wpa_supplicant_8&src/common/version.h&VERSION_STR
$define_version_finder&libcxx&include/__config&_LIBCPP_VERSION&s/\(\d\+\)/\1./
$define_version_finder&skia&include/core/SkTypes.h&SKIA_VERSION&s/\([0-9]\)\s\([0-9]\)\s\([0-9]\)/\1.\2.\3/&cat
$define_version_finder&qemu&android/config/linux-x86/config-host.h&QEMU_VERSION
$define_version_finder&valgrind&main/config.h&PACKAGE_VERSION
$define_version_finder&mesa3d&src/mesa/main/version.h&MESA_VERSION_STRING
$define_version_finder&llvm&host/include/llvm/Config/config.h&PACKAGE_VERSION"

for entry in $entries
do
  entry=`echo $entry | tr '&' ' '`
  project_id=`echo $entry | cut -d' ' -f 2`
  pushd $android_external$project_id
  echo "$entry"
  $entry
  popd
done
