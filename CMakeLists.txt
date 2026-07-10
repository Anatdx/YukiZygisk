# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk - Userspace build entry point for standalone components.
#
# License: Apache-2.0
#
# Author: Anatdx

cmake_minimum_required(VERSION 3.22)
project(YukiZygisk VERSION 0.1 LANGUAGES C CXX ASM)

option(YZ_BUILD_ZYGISKD "Build the standalone YukiZygisk daemon" ON)
option(YZ_BUILD_RUNTIME "Build the YukiZygisk runtime payloads" ON)

if(YZ_BUILD_RUNTIME)
  add_subdirectory(userspace/zygisk/core)
endif()
if(YZ_BUILD_ZYGISKD)
  add_subdirectory(userspace/zygisk/daemon)
endif()
