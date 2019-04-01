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

#ifndef PCI_DEV_INTEL_X64_BOXY_H
#define PCI_DEV_INTEL_X64_BOXY_H

#include <bfhypercall.h>
#include <bfvmm/hve/arch/intel_x64/vcpu.h>
#include <bfvmm/hve/arch/intel_x64/vmexit/io_instruction.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

class vcpu;

class pci_dev
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    explicit pci_dev(uint32_t bus, uint32_t dev, uint32_t fun);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~pci_dev() = default;

    /// Dump the MMCFG of this device
    ///
    /// This prints the first 256 bytes of the device's MMCFG space.
    /// The output is in the same form as lspci -x
    ///
    void dump_mmcfg() const;

    /// Bind vcpu
    ///
    /// Associate the vcpu referenced by the given id with this PCI dev.
    ///
    /// @param id the vcpuid to bind
    ///
    void bind_vcpu(vcpuid_t id);

    /// Set physical vector
    ///
    /// @param phys the vector received from the visr driver
    ///
    void set_phys_vector(uint64_t phys);

    /// Set virtual vector
    ///
    /// @param virt the vector received from the guest VM
    ///
    void set_virt_vector(uint64_t virt);

    /// Set MMCFG
    ///
    /// Set this device's memory-mapped config space gpa and unique_map
    /// The gpa is used to emulate with EPT and the map is used to talk to
    /// the actual config space
    ///
    /// @param gpa the guest-physical address of the MMCFG page
    /// @param map the map containing the hva of the MMCFG page
    ///
    void set_mmcfg(uintptr_t gpa, bfvmm::x64::unique_map<uint32_t> &&map);

    /// Set bus/device/function
    ///
    /// @param bus the bus of this device
    /// @param dev the device of this device
    /// @param fun the function of this device
    ///
    void set_bdf(uint32_t bus, uint32_t dev, uint32_t fun);

    /// Set register value
    ///
    /// @param off the offset of the register to set
    /// @param val the value to set it to
    ///
    void set_reg(uint32_t off, uint32_t val);

    /// Get bus
    ///
    /// @return the bus of this device
    ///
    uint32_t bus() const;

    /// Get dev
    ///
    /// @return the dev of this device
    ///
    uint32_t dev() const;

    /// Get function
    ///
    /// @return the function of this device
    ///
    uint32_t fun() const;

    /// Get register
    ///
    /// @param offset the register offset to read
    /// @return the value of the register at offset
    ///
    uint32_t reg(uint32_t offset) const;

    /// Physical vector
    ///
    /// @return the physical vector of this device
    ///
    uint64_t phys_vector() const;

    /// Virtual vector
    ///
    /// @return the virtual vector of this device
    ///
    uint64_t virt_vector() const;

    /// vcpuid
    ///
    /// @return the id of the vcpu bound to this device
    ///
    uint64_t vcpuid() const;

    /// domid
    ///
    /// @return the id of the domain bound to this device
    ///
    uint64_t domid() const;

    /// Is bar
    ///
    /// @param offset the register offset to test
    /// @return true iff the register at the offset is a BAR of a normal
    ///         (non-bridge) PCI device
    ///
    bool is_bar(uint32_t offset) const;

    /// Bound to vcpu
    ///
    /// @param id the vcpu to check
    /// @return true iff this is bound to the vcpu referenced by the id
    ///
    bool bound_to_vcpu(vcpuid_t id) const;

private:

    static constexpr auto nr_convent_regs = 256 / sizeof(uint32_t);
    static constexpr auto nr_express_regs = 4096 / sizeof(uint32_t);

    uint32_t m_bus{};
    uint32_t m_dev{};
    uint32_t m_fun{};
    uint32_t m_phys_vector{};
    uint32_t m_virt_vector{};
    vcpuid_t m_vcpuid{INVALID_VCPUID};
    domainid_t m_domid{INVALID_DOMAINID};
    page_ptr<uint32_t> m_cfg_page;
    gsl::span<uint32_t> m_cfg;
    bfvmm::x64::unique_map<uint32_t> m_mmcfg_map{};
    uintptr_t m_mmcfg_gpa{};

public:

    /// @cond

    pci_dev(pci_dev &&) = default;
    pci_dev &operator=(pci_dev &&) = default;

    pci_dev(const pci_dev &) = delete;
    pci_dev &operator=(const pci_dev &) = delete;

    /// @endcond
};

}

#endif
