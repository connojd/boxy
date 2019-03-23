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

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/pci/pci_dev.h>

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

pci_dev::pci_dev(uint32_t bus, uint32_t dev, uint32_t fun) :
    m_bus{bus},
    m_dev{dev},
    m_fun{fun},
    m_cfg_page{make_page<uint32_t>()},
    m_cfg{gsl::span<uint32_t>(m_cfg_page.get(), nr_express_regs)}
{ }

uint32_t pci_dev::bus() const { return m_bus; }
uint32_t pci_dev::dev() const { return m_dev; }
uint32_t pci_dev::fun() const { return m_fun; }
uint32_t pci_dev::reg(uint32_t off) const { return m_cfg.at(off); }
vcpuid_t pci_dev::vcpuid() const { return m_vcpuid; }

// Assume normal (non-bridge) devices for now
bool pci_dev::is_bar(uint32_t offset) const
{
    return offset >= 4 && offset <= 9;
}

void pci_dev::set_reg(uint32_t off, uint32_t val)
{
    m_cfg.at(off) = val;
}

void pci_dev::bind_vcpu(vcpuid_t id)
{
    m_vcpuid = id;
}

bool pci_dev::bound_to_vcpu(vcpuid_t id) const
{
    return id == m_vcpuid;
}

void pci_dev::set_phys_vector(uint64_t phys)
{
    m_phys_vector = phys;
}

void pci_dev::set_virt_vector(uint64_t virt)
{
    m_virt_vector = virt;
}

uint64_t pci_dev::phys_vector() const
{
    return m_phys_vector;
}

uint64_t pci_dev::virt_vector() const
{
    return m_virt_vector;
}

void pci_dev::set_bdf(uint32_t bus, uint32_t dev, uint32_t fun)
{
    m_bus = bus;
    m_dev = dev;
    m_fun = fun;
}

}
