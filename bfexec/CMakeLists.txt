#
# Copyright (C) 2018 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

cmake_minimum_required(VERSION 3.6)
project(bfexec C CXX)

init_project(bfexec INTERFACE)
target_include_directories(bfexec INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/../bfvmm/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/../bfsdk/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>
)

string(TOLOWER ${BUILD_TARGET_OS} OS)

add_executable(bfexec-binary)
target_include_directories(bfexec-binary PRIVATE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/src/platform/${OS}>
)
target_sources(bfexec-binary PRIVATE
    src/platform/${OS}/ioctl.cpp
    src/platform/${OS}/ioctl_private.cpp
    src/main.cpp
)
target_link_libraries(bfexec-binary PRIVATE
    bfexec
    userspace::bfintrinsics
    $<$<OR:$<BOOL:${CYGWIN}>,$<BOOL:${WIN32}>>:setupapi>
    $<$<BOOL:${UNIX}>:pthread>
)

set_target_properties(bfexec-binary PROPERTIES OUTPUT_NAME bfexec)
install(TARGETS bfexec-binary DESTINATION bin EXPORT bfexec-${PREFIX}-targets)

fini_project()
