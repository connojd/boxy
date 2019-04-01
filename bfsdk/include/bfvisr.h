/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef BFVISR_H
#define BFVISR_H

#include <bftypes.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Common                                                                     */
/* -------------------------------------------------------------------------- */

#ifndef VISR_NAME
#define VISR_NAME "visr"
#endif

#ifndef VISR_DEVICE
#define VISR_DEVICE 0xBEEF
#endif

#ifndef VISR_VENDOR
#define VISR_VENDOR 0xF00D
#endif

#ifndef VISR_MAGIC
#define VISR_MAGIC 0xBF
#endif

#define IOCTL_MAP_MCFG_CMD 0x01
#define IOCTL_EMULATE_CMD 0x02

/* -------------------------------------------------------------------------- */
/* Linux Interfaces                                                           */
/* -------------------------------------------------------------------------- */

#ifdef __linux__

#define IOCTL_MAP_MCFG _IO(VISR_MAGIC, IOCTL_MAP_MCFG_CMD)
#define IOCTL_EMULATE _IOW(VISR_MAGIC, IOCTL_EMULATE_CMD, uint64_t)

#endif

/* -------------------------------------------------------------------------- */
/* Windows Interfaces                                                         */
/* -------------------------------------------------------------------------- */

//#if defined(_WIN32) || defined(__CYGWIN__)
//
//#include <initguid.h>
//
//DEFINE_GUID(GUID_DEVINTERFACE_builder,
//    0x0156f59a, 0xdf90, 0x4ac6, 0x85, 0x3d, 0xcf, 0xd9, 0x3e, 0x25, 0x65, 0xc2);
//
//#define IOCTL_CREATE_VM_FROM_BZIMAGE CTL_CODE(VISR_DEVICETYPE, IOCTL_CREATE_VM_FROM_BZIMAGE_CMD, METHOD_IN_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)
//#define IOCTL_DESTROY CTL_CODE(VISR_DEVICETYPE, IOCTL_DESTROY_CMD, METHOD_IN_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)
//
//#endif

#ifdef __cplusplus
}
#endif

#endif
