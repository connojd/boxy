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

#include <hve/arch/intel_x64/pci/pci_cfg.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/visr.h>

//--------------------------------------------------------------------------
// Implementation
//--------------------------------------------------------------------------

#define make_delegate(a,b) \
    bfvmm::intel_x64::a::handler_delegate_t::create<visr, &visr::b>(this)

#define handle_io(a,b,c) vcpu->add_io_instruction_handler( \
    a, \
    make_delegate(io_instruction_handler, b), \
    make_delegate(io_instruction_handler, c))

#define emulate_cpuid(l,h) vcpu->add_cpuid_emulator( \
    l, \
    handler_delegate_t::create<visr, &visr::h>(this))

namespace boxy::intel_x64
{
using namespace ::pci;

static void overwrite(visr::io_handler::info_t &info, uint32_t val)
{
    using namespace vmcs_n::exit_qualification::io_instruction;

    const auto size = info.size_of_access;
    const auto port = info.port_number;

    switch (size) {
        case size_of_access::four_byte:
            expects(port == 0xCFC);
            info.val = val;
            break;
        case size_of_access::two_byte:
            expects(port == 0xCFC || port == 0xCFE);
            info.val = (port == 0xCFE) ? val >> 16 : val & 0xFFFF;
            break;
        case size_of_access::one_byte:
            expects(port >= 0xCFC && port <= 0xCFF);
            info.val = (val >> ((port - 0xCFC) * 8)) & 0xFF;
            break;
        default:
            throw std::runtime_error("overwrite: invaid size");
    }
}

visr *visr::instance() noexcept
{
    static visr self;
    return &self;
}

void visr::init_cfg_space(vcpu *v, struct pci_dev *dev)
{
    expects(v->is_dom0());

    const auto cf8 = bdf_to_cf8(dev->bus(), dev->dev(), dev->fun());

    // Only normal (non-bridge) devices with capability lists are supported
    expects(is_normal(cf8));
    expects((cf8_read_reg(cf8, 0x1) & 0x100000) != 0);

    // Only PCIe devices supported
    const auto [pcie_reg, pcie_val] = find_cap(cf8, capid_pcie);
    expects(pcie_reg != 0);

    // PCIe implies MSI but check anyway for sanity
    const auto [msi_reg, msi_val] = find_cap(cf8, capid_msi);
    expects(msi_reg != 0);

    dev->set_reg(0x0, 0xBEEF'F00D);
    dev->set_reg(0x1, cf8_read_reg(cf8, 0x1) | 0x400);
    dev->set_reg(0x2, cf8_read_reg(cf8, 0x2));
    dev->set_reg(0x3, cf8_read_reg(cf8, 0x3));
    dev->set_reg(0xF, (cf8_read_reg(cf8, 0xF) | 0xFF) & 0xFFFF00FF);

    // Advertise the MSI capability only
    dev->set_reg(0xD, msi_reg << 2);

    // Here we terminate the capability list,
    // clear MSI enable, clear multi-message capable/enable,
    // passthrough 64-bit address capable, and clear rsvd bits
    dev->set_reg(msi_reg, msi_val & 0x0080'00'05);

    // Now we store the gpa of the device's extended config space
    expects(g_mcfg_allocs.size() >= 1);

    const auto b = dev->bus();
    const auto d = dev->dev();
    const auto f = dev->fun();

    for (const auto &mca : g_mcfg_allocs) {
        if (b < mca.startbus || b > mca.endbus) {
            continue;
        }

        auto off = ((b - mca.startbus) << 20) | (d << 15) | (f << 12);
        auto map = v->map_gpa_4k<uint32_t>(mca.base + off);
        dev->set_mmcfg(mca.base + off, std::move(map));
        dev->dump_mmcfg();

        return;
    }

    throw std::runtime_error("PCI dev not in any MCFG alloc entry");
}

void visr::emulate(vcpu *v, uint32_t b, uint32_t d, uint32_t f)
{
    auto cf8 = bdf_to_cf8(b, d, f);
    if (this->is_emulating(cf8)) {
        v->set_rax(SUCCESS);
        return;
    }

    auto dev = std::make_unique<struct pci_dev>(b, d, f);
    this->init_cfg_space(v, dev.get());

    std::lock_guard<std::mutex> lock(m_mutex);
    m_devs.emplace(std::make_pair(cf8, std::move(dev)));

    v->set_rax(SUCCESS);
}

void visr::enable(vcpu *vcpu)
{
    expects(vcpu->is_dom0());

    handle_io(0xCFC, handle_in, handle_out);
    handle_io(0xCFD, handle_in, handle_out);
    handle_io(0xCFE, handle_in, handle_out);
    handle_io(0xCFF, handle_in, handle_out);

    emulate_cpuid(visr_save_phys, save_phys_vector);
    emulate_cpuid(visr_post_virt, post_virt_vector);
}

bool visr::save_phys_vector(vcpu_t *vcpu)
{
    const auto leaf = vcpu->rax();
    const auto phys = vcpu->rcx();

    expects(leaf == visr_save_phys);
    expects(phys >= vector_min);
    expects(phys <= vector_max);

    std::lock_guard<std::mutex> lock(m_mutex);

    for (auto &p : m_devs) {
        auto dev = p.second.get();
        if (dev->phys_vector() == 0) {
            dev->set_phys_vector(phys);
            m_vector_map[phys] = dev;
            return true;
        }
    }

    return false;
}

bool visr::post_virt_vector(vcpu_t *vcpu)
{
    const auto leaf = vcpu->rax();
    const auto phys = vcpu->rcx();

    expects(leaf == visr_post_virt);
    expects(phys >= vector_min);
    expects(phys <= vector_max);

    const auto dev = m_vector_map.at(phys);
    expects(dev);

    //const auto vid = dev->vcpuid();
    //get_vcpu(vid)->post_external_interrupt(phys);

    return true;
}

bool visr::handle_in(vcpu_t *vcpu, io_handler::info_t &info)
{
    auto cf8 = ::x64::portio::ind(0xCF8);
    auto itr = m_devs.find(cf8 & 0xFFFFFF00);

    // At this point, the caller has populated info with the hardware
    // value. To pass through, we just have to return true. If the
    // device is being emulated, we need to sanitize info.val
    // with the proper value from struct pci_dev.

    if (itr == m_devs.end()) {
        return true;
    }

    auto dev = itr->second.get();
    auto reg = cf8_to_reg(cf8);

    if (dev->is_bar(reg)) {
        return true;
    }

    overwrite(info, dev->reg(reg));
    return true;
}

bool visr::handle_out(vcpu_t *vcpu, io_handler::info_t &info)
{
    auto cf8 = ::x64::portio::ind(0xCF8);
    auto itr = m_devs.find(cf8 & 0xFFFFFF00);

    if (itr == m_devs.end()) {
        return true;
    }

    auto dev = itr->second.get();
    auto reg = cf8_to_reg(cf8);

    if (dev->is_bar(reg)) {
        return true;
    }

    info.ignore_write = true;
    return true;
}

bool visr::is_emulating(uint32_t cf8) const
{
    cf8 &= 0xFFFFFF00UL;
    cf8 |= (1UL << 31);
    return m_devs.count(cf8) == 1;
}

}
