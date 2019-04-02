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

#ifndef VISR_INTEL_X64_BOXY_H
#define VISR_INTEL_X64_BOXY_H

#include <bfvmm/hve/arch/intel_x64/vmexit/cpuid.h>
#include <bfvmm/hve/arch/intel_x64/vmexit/io_instruction.h>

#include <acpi.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/pci/pci_dev.h>

//------------------------------------------------------------------------------
// Definition
//------------------------------------------------------------------------------

namespace boxy::intel_x64
{

static uint32_t visr_save_phys = 0xf00dbeef;
static uint32_t visr_post_virt = 0xcafebabe;

class visr
{
public:

    using io_handler = bfvmm::intel_x64::io_instruction_handler;

    /// Get the visr instance
    ///
    static visr *instance() noexcept;

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~visr() = default;

    /// Add a device to emulate
    ///
    /// @param v the vcpu the device is bound to
    /// @param b the bus of the emulated device
    /// @param d the device of the emulated device
    /// @param f the function of the emulated device
    ///
    /// @return SUCCESS if emulation becomes active
    ///
    int emulate(vcpu *v, uint32_t b, uint32_t d, uint32_t f);

    /// Enable
    ///
    /// Enable emulation on the given vcpu. This installs the exit
    /// handlers needed for each device that has been added with
    /// emulate prior to this call.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu to enable this on
    ///
    void enable(vcpu *vcpu);

    /// Save physical vector
    ///
    /// Save the vector for later remapping to a guest vcpu.
    /// This is currently implemented as a cpuid emulator
    /// at leaf visr_save_phys. It is called from the visr
    /// driver in the host VM when the OS gives it a vector.
    ///
    /// @expects vcpu->rax() == visr_save_phys
    /// @expects vcpu->rcx() == vector >= vector_min
    ///
    /// @param vcpu the vcpu the visr driver is calling from
    /// @return true always
    ///
    bool save_phys_vector(vcpu_t *vcpu);

    /// Post virtual vector
    ///
    /// Forward the virtual vector to whatever vcpu was bound in
    /// the previous bind_virt_vector call. This is implemented as a
    /// cpuid emulator at leaf visr_post_virt. The visr driver in
    /// the host VM calls this whenever a physical interrupt associated
    /// with the virtual vector arrives.
    ///
    /// @expects vcpu->rax() == visr_post_virt
    /// @expects vcpu->rcx() == vector >= vector_min
    ///
    /// @param vcpu the vcpu the visr driver is calling from
    /// @return true always
    ///
    bool post_virt_vector(vcpu_t *vcpu);

    /// Bind a physical vector for guest usage
    ///
    /// @param vcpuid the id of the vcpu to bind the vector to
    /// @return a physical vector bound to the vcpu
    ///
    uint32_t bind_phys_vector(uint64_t vcpuid);

    /// Bind a virtual vector to the given vcpu
    ///
    /// Map the virtual vector to the given vcpu. This is the last
    /// step required before the physical interrupt can be injected
    /// by visr via post_virt_vector.
    ///
    /// @param vcpuid the id of the vcpu acquiring the vector
    /// @param vec the vector the guest vcpu is expecting
    ///
    void bind_virt_vector(uint64_t vcpuid, uint32_t vec);

    /// @cond

    /// We use portio *handlers* rather than emulators because the common
    /// case will be passthrough since the host VM owns the majority of
    /// devices. Since we use handlers, the caller will populate the hardware
    /// with the in/out values for us.
    ///
    bool handle_in(vcpu_t *vcpu, io_handler::info_t &info);
    bool handle_out(vcpu_t *vcpu, io_handler::info_t &info);

    /// @endcond

private:

    /// @cond

    bool is_emulating(uint32_t cf8) const;
    void init_cfg_space(vcpu *vcpu, struct pci_dev *dev);

    static constexpr auto vector_min = 32;
    static constexpr auto vector_max = 255;

    std::mutex m_mutex{};
    std::unordered_map<uint32_t, std::unique_ptr<struct pci_dev>> m_devs{};
    std::unordered_map<uint32_t, struct pci_dev *> m_vector_map{};

    visr() = default;
    visr(visr &&) noexcept = delete;
    visr &operator=(visr &&) noexcept = delete;
    visr(const visr &) = delete;
    visr &operator=(const visr &) = delete;

    /// @endcond
};
}

/// visr access
///
/// @expects
/// @ensures g_visr != nullptr
///
#define g_visr boxy::intel_x64::visr::instance()

#endif
