#!/bin/bash
#  Created by FangYuan Gui on 13.01.16.
#  Copyright 2011 FangYuan Gui. All rights reserved.
#
#  Licensed under the Apache License

set -u

# -h-'-#-e-N-K-g-<-)-e-P-N-g-Z-D-f-V-G-d-;-6-e-P--o-<-H-e--3-e-N-;-f-N-I-e-N-K-g-<-)-e-P-N-g-<-@ .tar*-o-<-I
OPENSSL_SRC_DIR=${PWD}
#echo "${OPENSSL_SRC_DIR}"

# ${PWD}-o-<-Z-e-=-S-e-I--f-I-@-e-\-(-f-V-G-d-;-6-g-[-.-e-=-U
# -g-<-V-h-/-Q-g-[-.-e-=-U
OPENSSL_BUILD_DIR=${PWD}/tassl-ios-build
#echo "${OPENSSL_BUILD_DIR}"

# -g-<-V-h-/-Q-g-[-.-e-=-U-d-8-K-g-Z-Dlog-f-W-%-e-?-W-g-[-.-e-=-U
OPENSSL_BUILD_LOG_DIR=${OPENSSL_BUILD_DIR}/log
#echo "${OPENSSL_BUILD_LOG_DIR}"

# -g-<-V-h-/-Q-g-[-.-e-=-U-d-8-K-f-\-@-e-P-N-g-T-_-f-H-P-i-@-Z-g-T-(-e-:-S-g-Z-D-g-[-.-e-=-U
OPENSSL_BUILD_UNIVERSAL_DIR=${OPENSSL_BUILD_DIR}/universal
#echo "${OPENSSL_BUILD_UNIVERSAL_DIR}"

# -i-@-Z-g-T-(-e-:-S-g-[-.-e-=-U-d-8-K-g-Z-Dlib-g-[-.-e-=-U
OPENSSL_UNIVERSAL_LIB_DIR=${OPENSSL_BUILD_UNIVERSAL_DIR}/lib
#echo "${OPENSSL_UNIVERSAL_LIB_DIR}"


# -e-H- -i-Y-$-h-'-#-e-N-K-g-<-)-e-P-N-g-Z-D-f-V-G-d-;-6
rm -rf ${OPENSSL_BUILD_DIR}

# -h-'-#-e-N-K-g-<-)tar-f-V-G-d-;-6-o-<-L-e-$-1-h-4-%-e-H-Y-i-@-@-e-G-:
#tar xfz ${OPENSSL_COPRESSED_FN} || exit 1

# -e-H-[-e-;-:-g-[-.-e-=-U
if [ ! -d "${OPENSSL_BUILD_UNIVERSAL_DIR}" ]; then
mkdir -p "${OPENSSL_BUILD_UNIVERSAL_DIR}"
fi

if [ ! -d "${OPENSSL_BUILD_LOG_DIR}" ]; then
mkdir "${OPENSSL_BUILD_LOG_DIR}"
fi

if [ ! -d "${OPENSSL_UNIVERSAL_LIB_DIR}" ]; then
mkdir "${OPENSSL_UNIVERSAL_LIB_DIR}"
fi


pushd .
# -h-?-[-e-E-%OPENSSL_SRC_DIR-g-[-.-e-=-U
#cd ${OPENSSL_SRC_DIR}

# -f-_-%-f-I-> clang -g-<-V-h-/-Q-e-Y-( -g-[-.-e-=-U
# /Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang
CLANG=$(xcrun --find clang)

# -f-_-%-f-I-> iPhone SDK -g-[-.-e-=-U
# /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS10.1.sdk
IPHONE_OS_SDK_PATH=$(xcrun -sdk iphoneos --show-sdk-path)

# IPHONE_OS_SDK_PATH -g-[-.-e-=-U-d-8-- SDKs -g-Z-D-d-8-J-g-:-'-g-[-.-e-=-U
# /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer
IPHONE_OS_CROSS_TOP=${IPHONE_OS_SDK_PATH//\/SDKs*/}

# IPHONE_OS_SDK_PATH -g-[-.-e-=-U-d-8---f-\-@-e-P-N-d-8-@-g-:-'-g-[-.-e-=-U
# iPhoneOS10.1.sdk
IPHONE_OS_CROSS_SDK=${IPHONE_OS_SDK_PATH##*/}

# iPhone -f-(-!-f-K-_-e-Y-( sdk -g-[-.-e-=-U
# /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator10.1.sdk
IPHONE_SIULATOR_SDK_PATH=$(xcrun -sdk iphonesimulator --show-sdk-path)

# IPHONE_SIULATOR_SDK_PATH -g-[-.-e-=-U-d-8-- SDKs -g-Z-D-d-8-J-g-:-'-g-[-.-e-=-U
# /Applications/Xcode.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer
IPHONE_SIULATOR_CROSS_TOP=${IPHONE_SIULATOR_SDK_PATH//\/SDKs*/}

# IPHONE_SIULATOR_SDK_PATH -g-[-.-e-=-U-d-8---f-\-@-e-P-N-d-8-@-g-:-'-g-[-.-e-=-U
# iPhoneSimulator10.1.sdk
IPHONE_SIULATOR_CROSS_SDK=${IPHONE_SIULATOR_SDK_PATH##*/}


# -i-\-@-h-&-A-g-<-V-h-/-Q-g-Z-D-f--6-f--D-e-9-3-e-O-0-e-H-W-h-!-(
#ARCH_LIST=("armv7" "armv7s" "arm64" "i386" "x86_64")
ARCH_LIST=("arm64")
# -i-\-@-h-&-A-g-<-V-h-/-Q-g-Z-D-e-9-3-e-O-0-f-U-0-i-G-O
ARCH_COUNT=${#ARCH_LIST[@]}
# -e-P-D-f--6-f--Dsdk-f-I-@-e-\-(-g-Z-D-g-[-.-e-=-U
CROSS_TOP_LIST=(${IPHONE_OS_CROSS_TOP} ${IPHONE_OS_CROSS_TOP} ${IPHONE_OS_CROSS_TOP} ${IPHONE_SIULATOR_CROSS_TOP} ${IPHONE_SIULATOR_CROSS_TOP})

# -e-P-D-f--6-f--Dsdk-e-P-
CROSS_SDK_LIST=(${IPHONE_OS_CROSS_SDK} ${IPHONE_OS_CROSS_SDK} ${IPHONE_OS_CROSS_SDK} ${IPHONE_SIULATOR_CROSS_SDK} ${IPHONE_SIULATOR_CROSS_SDK})

# -g-<-V-h-/-Q-i-E--g-=-.
config_make()
{
# -f-N-%-f-T-6-g-,-,-d-8-@-d-8-*-e-O-B-f-U-0
ARCH=$1;
# -f-N-%-f-T-6-g-,-,-d-:-L-d-8-*-e-O-B-f-U-0-o-<-L-e-/-<-e-E-%-i-E--g-=-.-f-V-G-d-;-6
export CROSS_TOP=$2
# -f-N-%-f-T-6-g-,-,-d-8-I-d-8-*-e-O-B-f-U-0-o-<-L-e-/-<-e-E-%-i-E--g-=-.-f-V-G-d-;-6
export CROSS_SDK=$3

# -miphoneos-version-min-i-@-I-i-!-9-f-L-G-e-.-Z-f-\-@-e-0-O-f-T-/-f-L-A-g-Z-DiOS-g-I-H-f-\-,-o-<-[
# -fembed-bitcode-i-@-I-i-!-9-e-<-@-e-P-/bitcode-g-Z-D-f-T-/-f-L-A-o-<-L-e-N-;-f-N-I-e-0-1-d-8--f-T-/-f-L-Abitcode
#export CC="${CLANG} -arch ${ARCH} -miphoneos-version-min=6.0 -fembed-bitcode"
export CC="${CLANG} -arch ${ARCH} -miphoneos-version-min=6.0"

make clean &> ${OPENSSL_BUILD_LOG_DIR}/make_clean.log


# -i-E--g-=-.-g-<-V-h-/-Q-f-]-!-d-;-6
echo "configure for ${ARCH}..."
if [ "x86_64" == ${ARCH} ]; then
# -g-<-V-h-/-Qx86_64-e-9-3-e-O-0-g-Z-Dopenssl-o-<-LConfigure-f-W-6-i-\-@-h-&-A-f-L-G-e-.-Zno-asm-i-@-I-i-!-9-o-<-L-e-P-&-e-H-Y-d-<-Z-f-J-%-i-T-Y-o-<-[
./Configure iphoneos-cross --prefix=${OPENSSL_BUILD_DIR}/${ARCH} no-asm &> ${OPENSSL_BUILD_LOG_DIR}/${ARCH}-conf.log
else
./Configure iphoneos-cross --prefix=${OPENSSL_BUILD_DIR}/${ARCH} no-engine &> ${OPENSSL_BUILD_LOG_DIR}/${ARCH}-conf.log
fi


# -g-<-V-h-/-Q
echo "build for ${ARCH}..."
make &> ${OPENSSL_BUILD_LOG_DIR}/${ARCH}-make.log
make install_sw &> ${OPENSSL_BUILD_LOG_DIR}/${ARCH}-make-install.log

# unset-e-Q-=-d-;-$-g-T-(-d-:-N-e-H- -i-Y-$-e-7-2-e-.-Z-d-9-I-g-Z-Dshell-e-O-X-i-G-O-o-<-H-e-L-E-f-K-,-g-N-/-e-"-C-e-O-X-i-G-O-o-<-I-e-R-Lshell-e-G-=-f-U-0-c-@-Bunset-e-Q-=-d-;-$-d-8--h-C-=-e-$-_-e-H- -i-Y-$-e-E-7-f-\-I-e-O-*-h-/-;-e-1--f-@-'-g-Z-Dshell-e-O-X-i-G-O-e-R-L-g-N-/-e-"-C-e-O-X-i-G-O-c-@-B
unset CC
unset CROSS_SDK
unset CROSS_TOP

echo -e "\n"
}

# -f-I-'-h-!-Lconfig_make()-e-G-=-f-U-0-o-<-L-h-?-[-h-!-L-i-E--g-=-.-d-8-N-g-<-V-h-/-Q
# -d-<- -e-E-%-d-8-I-d-8-*-e-O-B-f-U-0${ARCH_LIST[i]} ${CROSS_TOP_LIST[i]} ${CROSS_SDK_LIST[i]}
for ((i=0; i < ${ARCH_COUNT}; i++))
do
config_make ${ARCH_LIST[i]} ${CROSS_TOP_LIST[i]} ${CROSS_SDK_LIST[i]}
done

# -e-H-[-e-;-:lib-e-:-S
create_lib()
{
LIB_SRC=lib/$1
LIB_DST=${OPENSSL_UNIVERSAL_LIB_DIR}/$1
LIB_PATHS=( ${ARCH_LIST[@]/#/${OPENSSL_BUILD_DIR}/} )
LIB_PATHS=( ${LIB_PATHS[@]/%//${LIB_SRC}} )
lipo ${LIB_PATHS[@]} -create -output ${LIB_DST}
}

create_lib "libssl.a"
create_lib "libcrypto.a"

cp -R ${OPENSSL_BUILD_DIR}/armv7/include ${OPENSSL_BUILD_UNIVERSAL_DIR}

popd

# rm -rf ${OPENSSL_BUILD_DIR}

echo "done."

