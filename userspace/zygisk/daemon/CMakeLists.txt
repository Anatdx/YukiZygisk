# SPDX-License-Identifier: Apache-2.0
#
# YukiZygisk daemon build target.
#
# License: Apache-2.0
#
# Author: Anatdx

add_executable(zygiskd
  root_policy.cpp
  zygiskd.cpp
)

target_compile_features(zygiskd PRIVATE cxx_std_17)
target_include_directories(
  zygiskd
  PRIVATE
    ${PROJECT_SOURCE_DIR}
    ${PROJECT_SOURCE_DIR}/userspace/common
)
target_compile_definitions(zygiskd PRIVATE _GNU_SOURCE)

if(ANDROID)
  target_link_libraries(zygiskd PRIVATE dl)
else()
  find_package(Threads REQUIRED)
  target_link_libraries(zygiskd PRIVATE dl Threads::Threads)
endif()
