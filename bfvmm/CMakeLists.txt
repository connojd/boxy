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
project(boxy C CXX)

# ------------------------------------------------------------------------------
# Generator expressions
# ------------------------------------------------------------------------------

set(CXX $<COMPILE_LANGUAGE:CXX>)
set(X64 $<STREQUAL:${BUILD_TARGET_ARCH},x86_64>)
set(BUILD $<BOOL:$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>>)
set(BUILD_INCLUDE $<AND:${CXX},${BUILD}>)

# ------------------------------------------------------------------------------
# Project
# ------------------------------------------------------------------------------

init_project(boxy INTERFACE)

target_link_libraries(boxy INTERFACE vmm::eapis)
target_include_directories(boxy INTERFACE
    $<${BUILD_INCLUDE}:${PROJECT_SOURCE_DIR}/include>
    $<${BUILD_INCLUDE}:${PROJECT_SOURCE_DIR}/../include>
    $<${BUILD_INCLUDE}:${PROJECT_SOURCE_DIR}/../bfsdk/include>
)

# ------------------------------------------------------------------------------
# Libraries
# ------------------------------------------------------------------------------

add_library(boxy_domain)
add_library(boxy_hve)

target_link_libraries(boxy_domain PUBLIC boxy)
target_link_libraries(boxy_hve PUBLIC boxy)
target_sources(boxy_domain PRIVATE src/domain/domain.cpp)
target_sources(boxy_hve PRIVATE
    $<${X64}:src/hve/arch/intel_x64/apic/x2apic.cpp>
    $<${X64}:src/hve/arch/intel_x64/pci/pci_configuration_space.cpp>
    $<${X64}:src/hve/arch/intel_x64/vmexit/cpuid.cpp>
    $<${X64}:src/hve/arch/intel_x64/vmexit/external_interrupt.cpp>
    $<${X64}:src/hve/arch/intel_x64/vmexit/io_instruction.cpp>
    $<${X64}:src/hve/arch/intel_x64/vmexit/msr.cpp>
    $<${X64}:src/hve/arch/intel_x64/vmexit/vmcall.cpp>
    $<${X64}:src/hve/arch/intel_x64/vmexit/yield.cpp>
    $<${X64}:src/hve/arch/intel_x64/vmcall/domain_op.cpp>
    $<${X64}:src/hve/arch/intel_x64/vmcall/run_op.cpp>
    $<${X64}:src/hve/arch/intel_x64/vmcall/vcpu_op.cpp>
    $<${X64}:src/hve/arch/intel_x64/domain.cpp>
    $<${X64}:src/hve/arch/intel_x64/uart.cpp>
)

# -----------------------------------------------------------------------------
# Executable
# -----------------------------------------------------------------------------

add_executable(boxy_vmm)
target_link_libraries(boxy_vmm PRIVATE boxy_domain boxy_hve)
target_sources(boxy_vmm PRIVATE
    src/main/arch/intel_x64/domain_factory.cpp
    src/main/arch/intel_x64/vcpu_factory.cpp
)

# -----------------------------------------------------------------------------
# Install
# -----------------------------------------------------------------------------

install(TARGETS boxy_domain DESTINATION lib EXPORT boxy-vmm-targets)
install(TARGETS boxy_hve DESTINATION lib EXPORT boxy-vmm-targets)
install(TARGETS boxy_vmm DESTINATION bin EXPORT boxy-vmm-targets)
install(DIRECTORY include/ DESTINATION include/boxy)

fini_project()
