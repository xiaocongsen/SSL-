#!/bin/bash
 
# 设置编译器
export CC="clang -arch arm64" 
 
# 设置工具链路径
export PATH="/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin:$PATH"
 
# 设置开发环境目录
export CROSS_TOP=/Applications/Xcode.app/Contents/Developer/Platforms/iPhoneOS.platform/Developer
 
# 设置SDK
export CROSS_SDK=iPhoneOS15.2.sdk
 
# 设置最小依赖版本
export IPHONEOS_DEPLOYMENT_TARGET=8.0
 
# 生成makefile
# ./Configure iphoneos-cross no-shared

make clean

make -j4

echo "complied arm64"