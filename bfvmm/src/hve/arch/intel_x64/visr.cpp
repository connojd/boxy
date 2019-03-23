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

#include <bfvmm/util/arch/x64/pci.h>
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
using namespace ::x64::pci;

visr *visr::instance() noexcept
{
    static visr self;
    return &self;
}

void visr::init_config_space(struct pci_dev *dev)
{
    auto cf8 = bdf_to_cf8(dev->bus(), dev->dev(), dev->fun());

    // Only normal (non-bridge) device emulation is supported for now
    expects(is_normal(cf8));

    dev->set_reg(0x0, 0xBEEF'F00D);
    dev->set_reg(0x1, cf8_read_reg(cf8, 0x1) | 0x400);
    dev->set_reg(0x2, cf8_read_reg(cf8, 0x2));
    dev->set_reg(0x3, cf8_read_reg(cf8, 0x3));
    dev->set_reg(0xF, (cf8_read_reg(cf8, 0xF) | 0xFF) & 0xFFFF00FF);

    if ((dev->reg(0x1) & 0x10'0000) == 0) {
        return;
    }

    // Advertise only the MSI capability
    auto reg = (cf8_read_reg(cf8, 0xD) & 0xFF) >> 2;
    while (reg != 0) {
        const auto cap = cf8_read_reg(cf8, reg);
        if ((cap & 0xFF) == 5) {
            dev->set_reg(0xD, reg << 2);

            // Here we terminate the capability list,
            // clear MSI enable, clear multi-message capable/enable,
            // passthrough 64-bit address capable, and clear rsvd bits
            dev->set_reg(reg, cap & 0x0080'00'05);
        }
        reg = (cap & 0xFF00) >> (8 + 2);
    }
}

void visr::emulate(uint32_t bus, uint32_t dev, uint32_t fun)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    auto cf8 = bdf_to_cf8(bus, dev, fun);
    auto ptr = std::make_unique<struct pci_dev>(bus, dev, fun);

    this->init_config_space(ptr.get());
    m_devs.emplace(std::make_pair(cf8, std::move(ptr)));
}

void visr::enable(gsl::not_null<vcpu *> vcpu)
{
    expects(vcpu->is_dom0());

    handle_io(0xCFC, handle_cfc_in, handle_cfc_out);
    handle_io(0xCFD, handle_cfd_in, handle_cfd_out);
    handle_io(0xCFE, handle_cfe_in, handle_cfe_out);
    handle_io(0xCFF, handle_cff_in, handle_cff_out);

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

    const auto vid = dev->vcpuid();
    get_vcpu(vid)->post_external_interrupt(phys);

    return true;
}

bool visr::handle_cfc_in(vcpu_t *vcpu, io_handler::info_t &info)
{
    auto cf8 = ::x64::portio::ind(0xCF8);
    auto itr = m_devs.find(cf8 & 0xFFFFFF00);
    if (itr == m_devs.end()) {
        return true;
    }

    auto dev = itr->second.get();

    return true;
}

bool visr::handle_cfd_in(vcpu_t *vcpu, io_handler::info_t &info) { return true; }
bool visr::handle_cfe_in(vcpu_t *vcpu, io_handler::info_t &info) { return true; }
bool visr::handle_cff_in(vcpu_t *vcpu, io_handler::info_t &info) { return true; }

bool visr::handle_cfc_out(vcpu_t *vcpu, io_handler::info_t &info) { return true; }
bool visr::handle_cfd_out(vcpu_t *vcpu, io_handler::info_t &info) { return true; }
bool visr::handle_cfe_out(vcpu_t *vcpu, io_handler::info_t &info) { return true; }
bool visr::handle_cff_out(vcpu_t *vcpu, io_handler::info_t &info) { return true; }

bool visr::is_emulating(uint32_t cf8) const
{
    cf8 &= 0xFFFFFF00UL;
    cf8 |= (1UL << 31);
    return m_devs.count(cf8) == 1;
}

}
