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

#ifndef VERBOSE_H
#define VERBOSE_H

#define dump_vm_create_verbose()                                                                                                             \
    do { \
        if (verbose) {                                                                                                                       \
            const std::string type = (ioctl_args.file_type == VM_FILE_VMLINUX) ? std::string("vmlinux") : std::string("bzImage"); \
            const std::string mode = (ioctl_args.exec_mode == VM_EXEC_XENPVH) ? std::string("xenpvh") : std::string("native"); \
            std::cout << '\n';                                                                                                                  \
            std::cout << bfcolor_cyan    "Created VM:\n" bfcolor_end;                                                             \
            std::cout << bfcolor_magenta "--------------------------------------------------------------------------------\n" bfcolor_end;      \
            std::cout << "    kernel" bfcolor_yellow " | " << bfcolor_green << kernel.path() << bfcolor_end "\n";                                 \
            std::cout << "    initrd" bfcolor_yellow " | " << bfcolor_green << initrd.path() << bfcolor_end "\n";                                 \
            std::cout << " domain id" bfcolor_yellow " | " << bfcolor_green << ioctl_args.domainid << bfcolor_end "\n";                         \
            std::cout << "  ram size" bfcolor_yellow " | " << bfcolor_green << (ram / 0x100000U) << "MB" << bfcolor_end "\n";                  \
            std::cout << "   cmdline" bfcolor_yellow " | " << bfcolor_green << cmdl.data() << bfcolor_end "\n";                                 \
            std::cout << " file type" bfcolor_yellow " | " << bfcolor_green << type << bfcolor_end "\n";                                 \
            std::cout << " exec mode" bfcolor_yellow " | " << bfcolor_green << mode << bfcolor_end "\n";                                 \
        } \
    } while (0)

#define output_vm_uart_verbose()                                                                                                            \
    do { \
        if (verbose) {                                                                                                                          \
            std::cout << '\n';                                                                                                                  \
            std::cout << bfcolor_cyan    "Output from VM's UART:\n" bfcolor_end;                                                                \
            std::cout << bfcolor_magenta "--------------------------------------------------------------------------------\n" bfcolor_end;      \
            std::cout << '\n';                                                                                                                  \
            \
            u = std::thread(uart_thread);                                                                                                       \
        } \
    } while (0)


#endif
