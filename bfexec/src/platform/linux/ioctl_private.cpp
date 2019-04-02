//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-vararg
//
// Reason:
//    The Linux APIs require the use of var-args, so this test has to be
//    disabled.
//

#include <iostream>
#include <ioctl_private.h>

#include <bfgsl.h>
#include <bfdriverinterface.h>
#include <bfvisr.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

// -----------------------------------------------------------------------------
// Unit Test Seems
// -----------------------------------------------------------------------------

int
bfm_ioctl_open()
{
    return open("/dev/bareflank_builder", O_RDWR);
}

int64_t
bfm_write_ioctl(int fd, unsigned long request, const void *data)
{
    return ioctl(fd, request, data);
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

ioctl_private::ioctl_private()
{
    if ((builder_fd = bfm_ioctl_open()) < 0) {
        throw std::runtime_error("failed to open to the builder driver");
    }

    if ((visr_fd = open("/dev/visr", O_RDWR)) < 0) {
        throw std::runtime_error("failed to open to the visr driver");
    }
}

ioctl_private::~ioctl_private()
{
    close(builder_fd);
    close(visr_fd);
}

void
ioctl_private::call_ioctl_create_vm_from_bzimage(
    create_vm_from_bzimage_args &args)
{
    if (bfm_write_ioctl(builder_fd, IOCTL_CREATE_VM_FROM_BZIMAGE, &args) < 0) {
        throw std::runtime_error("ioctl failed: IOCTL_CREATE_VM_FROM_BZIMAGE");
    }
}

void
ioctl_private::call_ioctl_destroy(domainid_t domainid) noexcept
{
    if (bfm_write_ioctl(builder_fd, IOCTL_DESTROY, &domainid) < 0) {
        std::cerr << "[ERROR] ioctl failed: IOCTL_DESTROY\n";
    }
}

void
ioctl_private::call_ioctl_map_mcfg() noexcept
{
    if (ioctl(visr_fd, IOCTL_MAP_MCFG) < 0) {
        std::cerr << "[ERROR] ioctl failed: IOCTL_MAP_MCFG\n";
    }
}

void
ioctl_private::call_ioctl_emulate(uint64_t bdf) noexcept
{
    if (ioctl(visr_fd, IOCTL_EMULATE, &bdf) < 0) {
        std::cerr << "[ERROR] ioctl failed: IOCTL_EMULATE\n";
    }
}

void
ioctl_private::call_ioctl_enable() noexcept
{
    if (ioctl(visr_fd, IOCTL_ENABLE) < 0) {
        std::cerr << "[ERROR] ioctl failed: IOCTL_ENABLE\n";
    }
}
