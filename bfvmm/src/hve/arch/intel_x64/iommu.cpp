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

#include <bfgsl.h>
#include <intrinsics.h>
#include <bfvmm/memory_manager/memory_manager.h>
#include <bfvmm/memory_manager/arch/x64/cr3.h>
#include <bfvmm/hve/arch/x64/unmapper.h>
#include <bfvmm/hve/arch/intel_x64/vtd/iommu.h>
#include <hve/arch/intel_x64/iommu.h>

using namespace bfvmm::x64;

namespace boxy::intel_x64
{

iommu::iommu() noexcept : m_root{make_page<entry_t>()}
{
    /// Map in registers
    ///
    auto hva = g_mm->alloc_map(iommu::page_size);

    g_cr3->map_4k(
            hva,
            iommu::hpa,
            cr3::mmap::attr_type::read_write,
            cr3::mmap::memory_type::uncacheable);

    m_reg_map = bfvmm::x64::unique_map<uint8_t>(
            static_cast<uint8_t *>(hva),
            bfvmm::x64::unmapper(hva, iommu::page_size)
    );
}

iommu *iommu::instance() noexcept
{
    static iommu self;
    return &self;
}

void iommu::set_dom0_eptp(uintptr_t eptp)
{ m_dom0_eptp = eptp; }

void iommu::set_domU_eptp(uintptr_t eptp)
{ m_domU_eptp = eptp; }

void iommu::set_dom0_cte(iommu::entry_t *cte)
{
//    // TODO check TT against dev tlb support

    cte->data[0] = m_dom0_eptp | 1U;  // present, points to dom0 ept
    cte->data[1] = (1ULL << 8U) | 2U; // DID 1, 4-level EPT
}

void iommu::set_domU_cte(iommu::entry_t *cte)
{
//    // TODO check TT against dev tlb support

    cte->data[0] = m_domU_eptp | 1U;  // present, points to domU ept
    cte->data[1] = (2ULL << 8U) | 2U; // DID 2, 4-level EPT
}

static constexpr uint32_t devfn(uint32_t dev, uint32_t fn)
{ return (dev << 3) | fn; }

// Called once from {dom0, vcpu0}
//
void iommu::init_dom0_mappings()
{
    // Alloc ctxt table for each bus
    m_ctxt.push_back(make_page<entry_t>());
    m_ctxt.push_back(make_page<entry_t>());
    m_ctxt.push_back(make_page<entry_t>());

    // Setup root entries
    entry_t *rte = m_root.get();
    rte[0].data[0] = g_mm->virtptr_to_physint(m_ctxt[0].get()) | 1U;
    rte[1].data[0] = g_mm->virtptr_to_physint(m_ctxt[1].get()) | 1U;

    // Bus 0 for gigabyte board
    entry_t *cte = m_ctxt[0].get();
    this->set_dom0_cte(&cte[devfn(0x00, 0)]); // Host bridge
    this->set_dom0_cte(&cte[devfn(0x02, 0)]); // VGA
    this->set_dom0_cte(&cte[devfn(0x08, 0)]); // Gaussian model
    this->set_dom0_cte(&cte[devfn(0x14, 0)]); // USB
    this->set_dom0_cte(&cte[devfn(0x16, 0)]); // Comms
    this->set_dom0_cte(&cte[devfn(0x17, 0)]); // SATA
    this->set_dom0_cte(&cte[devfn(0x1B, 0)]); // PCI Bridge to bus 1
    this->set_dom0_cte(&cte[devfn(0x1C, 0)]); // PCI Bridge to bus 2
    this->set_dom0_cte(&cte[devfn(0x1C, 5)]); // PCI Bridge to bus 3
    this->set_dom0_cte(&cte[devfn(0x1C, 6)]); // PCI Bridge to bus 4
    this->set_dom0_cte(&cte[devfn(0x1C, 7)]); // PCI Bridge to bus 5
    this->set_dom0_cte(&cte[devfn(0x1D, 0)]); // PCI Bridge to bus 6
    this->set_dom0_cte(&cte[devfn(0x1D, 1)]); // PCI Bridge to bus 7
    this->set_dom0_cte(&cte[devfn(0x1D, 2)]); // PCI Bridge to bus 8
    this->set_dom0_cte(&cte[devfn(0x1D, 3)]); // PCI Bridge to bus 9
    this->set_dom0_cte(&cte[devfn(0x1F, 0)]); // ISA bridge
    this->set_dom0_cte(&cte[devfn(0x1F, 2)]); // Memory controller
    this->set_dom0_cte(&cte[devfn(0x1F, 3)]); // Audio controller
    this->set_dom0_cte(&cte[devfn(0x1F, 4)]); // SMBus controller

    // Bus 1 for GB board
    cte = m_ctxt[1].get();
    this->set_dom0_cte(&cte[devfn(0x00, 0)]); // NVMe controller

    ::x64::cache::wbinvd();
}

void iommu::init_domU_mappings()
{
    entry_t *rte = m_root.get();
    rte[2].data[0] = g_mm->virtptr_to_physint(m_ctxt[2].get()) | 1U;

    // Bus 2 for GB board
    entry_t *cte = m_ctxt[2].get();
    this->set_domU_cte(&cte[devfn(0x00, 0)]); // Ethernet controller

    ::x64::cache::wbinvd();
}

void iommu::enable()
{
    expects(m_dom0_eptp != 0);
    expects(m_domU_eptp != 0);

    // Update the hva from the VMM's cr3.
    // Any access to this member between now and
    // VMX-root will fault.
    //
    m_hva = m_reg_map.get();

//    auto cap = this->read64(0x8);
    auto ecap = this->read64(0x10);
    auto gsts = this->read32(0x1C);
    auto rtar = this->read64(0x20);

//    ::intel_x64::vtd::iommu::cap_reg::dump(0, cap);
//    ::intel_x64::vtd::iommu::ecap_reg::dump(0, ecap);
//    ::intel_x64::vtd::iommu::rtaddr_reg::dump(0, rtar);
//    ::intel_x64::vtd::iommu::gsts_reg::dump(0, gsts);

    expects(::intel_x64::vtd::iommu::gsts_reg::tes::is_disabled(gsts));
    expects(::intel_x64::vtd::iommu::gsts_reg::qies::is_disabled(gsts));
    expects(::intel_x64::vtd::iommu::gsts_reg::ires::is_disabled(gsts));
    expects(::intel_x64::vtd::iommu::rtaddr_reg::ttm::get(rtar) == 0);

    //
    // Set the root address with legacy translation mode
    //

    this->write64(0x20, g_mm->virtptr_to_physint(m_root.get()));
    ::intel_x64::barrier::mb();
    gsts = this->read32(0x1C);
    uint32_t gcmd = (gsts & 0x96FFFFFFU) | (1UL << 30);
    this->write32(0x18, gcmd);

    ::intel_x64::barrier::mb();
    while ((this->read32(0x1C) | (1UL << 30)) == 0) {
        ::intel_x64::pause();
    }

    //
    // Once the RTAR is set, the context-cache and IOTLB must be invalidated
    //

    uint64_t ctxcmd = this->read64(0x28);
    expects((ctxcmd & 0x8000000000000000U) == 0);
    ctxcmd &= ~0x6000000000000000U;
    ctxcmd |= (1ULL << 61); // global invalidation
    ctxcmd |= (1ULL << 63); // do it
    this->write64(0x28, ctxcmd);

    ::intel_x64::barrier::mb();
    while ((this->read64(0x28) & (1ULL << 63)) != 0) {
        ::intel_x64::pause();
    }

    uint64_t iva = ::intel_x64::vtd::iommu::ecap_reg::iro::get(ecap);
    expects(iva == 0x50);
    uint64_t iotlb = this->read64(iva + 0x8);
    iotlb &= ~0x3000000000000000U;
    iotlb |= (1ULL << 60); // global invalidation
    iotlb |= (1ULL << 63); // do it
    this->write64(iva + 0x8, iotlb);

    ::intel_x64::barrier::mb();
    while ((this->read64(iva + 0x8) & (1ULL << 63)) != 0) {
        ::intel_x64::pause();
    }

    //
    // Enable DMA remapping
    //

    gsts = this->read32(0x1C);
    gcmd = (gsts & 0x96FFFFFFU) | (1UL << 31);
    this->write32(0x18, gcmd);

    ::intel_x64::barrier::mb();
    while ((this->read32(0x1C) | (1UL << 31)) == 0) {
        ::intel_x64::pause();
    }

    bfdebug_info(0, "DMA remapping enabled");
}

void iommu::disable()
{
    uint32_t gsts = this->read32(0x1C);
    uint32_t gcmd = (gsts & 0x96FFFFFFU) | (0UL << 31);
    this->write32(0x18, gcmd);

    ::intel_x64::barrier::mb();
    while ((this->read32(0x1C) | (1UL << 31)) != 0) {
        ::intel_x64::pause();
    }
}


/// Register access
///
uint64_t iommu::read64(uintptr_t off)
{
    uint64_t *addr = reinterpret_cast<uint64_t *>(m_hva + off);
    return *addr;
}

uint32_t iommu::read32(uintptr_t off)
{
    uint32_t *addr = reinterpret_cast<uint32_t *>(m_hva + off);
    return *addr;
}

void iommu::write64(uintptr_t off, uint64_t val)
{
    uint64_t *addr = reinterpret_cast<uint64_t *>(m_hva + off);
    *addr = val;
}

void iommu::write32(uintptr_t off, uint64_t val)
{
    uint32_t *addr = reinterpret_cast<uint32_t *>(m_hva + off);
    *addr = gsl::narrow_cast<uint32_t>(val);
}

}