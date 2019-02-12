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

#ifndef XEN_OP_INTEL_X64_BOXY_H
#define XEN_OP_INTEL_X64_BOXY_H

#include "../uart.h"

#include <xen/public/xen.h>
#include <xen/public/vcpu.h>
#include <xen/public/grant_table.h>
#include <xen/public/arch-x86/cpuid.h>

#include "xen.h"
#include "evtchn_op.h"
#include "gnttab_op.h"

#include <bfvmm/hve/arch/x64/unmapper.h>
#include <bfvmm/hve/arch/intel_x64/vmexit/cpuid.h>
#include <bfvmm/hve/arch/intel_x64/vmexit/wrmsr.h>
#include <bfvmm/hve/arch/intel_x64/vmexit/rdmsr.h>
#include <bfvmm/hve/arch/intel_x64/vmexit/io_instruction.h>
#include <bfvmm/hve/arch/intel_x64/vmexit/ept_violation.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_BOXY_HVE
#ifdef SHARED_BOXY_HVE
#define EXPORT_BOXY_HVE EXPORT_SYM
#else
#define EXPORT_BOXY_HVE IMPORT_SYM
#endif
#else
#define EXPORT_BOXY_HVE
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace boxy::intel_x64
{

class vcpu;

class EXPORT_BOXY_HVE xen_op_handler
{
public:

    xen_op_handler(vcpu_t *vcpu, domain *domain);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~xen_op_handler() = default;

    shared_info_t *shared_info();

private:

    void run_delegate(bfobject *obj);
    bool exit_handler(vcpu_t *vcpu);
    bool handle_hlt(vcpu_t *vcpu);
    bool handle_vmx_pet(vcpu_t *vcpu);

    // -------------------------------------------------------------------------
    // MSRS
    // -------------------------------------------------------------------------

    void isolate_msr(uint32_t msr);

    bool rdmsr_zero_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info);
    bool wrmsr_ignore_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info);

    bool rdmsr_pass_through_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info);
    bool wrmsr_pass_through_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info);

    bool wrmsr_store_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info);

    bool dom0_apic_base(
        vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info);

    bool ia32_misc_enable_rdmsr_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info);
    bool ia32_misc_enable_wrmsr_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info);

    bool ia32_apic_base_rdmsr_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::rdmsr_handler::info_t &info);
    bool ia32_apic_base_wrmsr_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info);

    bool xen_hypercall_page_wrmsr_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info);
    bool xen_debug_ndec_wrmsr_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info);
    bool xen_debug_nhex_wrmsr_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info);

    bool handle_tsc_deadline(
        vcpu_t *vcpu, bfvmm::intel_x64::wrmsr_handler::info_t &info);

    // -------------------------------------------------------------------------
    // CPUID
    // -------------------------------------------------------------------------

    bool cpuid_zero_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::cpuid_handler::info_t &info);
    bool cpuid_pass_through_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::cpuid_handler::info_t &info);

    bool cpuid_leaf1_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::cpuid_handler::info_t &info);
    bool cpuid_leaf4_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::cpuid_handler::info_t &info);
    bool cpuid_leaf6_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::cpuid_handler::info_t &info);
    bool cpuid_leaf7_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::cpuid_handler::info_t &info);
    bool cpuid_leaf15_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::cpuid_handler::info_t &info);

    bool cpuid_leaf80000001_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::cpuid_handler::info_t &info);
    bool xen_cpuid_leaf1_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::cpuid_handler::info_t &info);
    bool xen_cpuid_leaf2_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::cpuid_handler::info_t &info);
    bool xen_cpuid_leaf3_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::cpuid_handler::info_t &info);
    bool xen_cpuid_leaf5_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::cpuid_handler::info_t &info);

    // -------------------------------------------------------------------------
    // IO Instructions
    // -------------------------------------------------------------------------

    bool io_zero_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool io_ones_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool io_ignore_handler(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);

    bool io_cf8_in(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool io_cf8_out(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    // Note: Linux should only write to CFB the value 1, one time, and
    // it should never read from CFB. The direct probe code writes here first
    // in order to determine type 1 config access.
    //
    bool io_cfb_in(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool io_cfb_out(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool io_cfc_in(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool io_cfc_out(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool io_cfd_in(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool io_cfd_out(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool io_cfe_in(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool io_cfe_out(
        vcpu_t *vcpu, bfvmm::intel_x64::io_instruction_handler::info_t &info);

    bool pci_in(bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool pci_hdr_pci_bridge_in(bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool pci_hdr_normal_in(bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool pci_host_bridge_in(bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool pci_owned_in(bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool pci_msix_cap_prev_in(bfvmm::intel_x64::io_instruction_handler::info_t &info);

    bool pci_out(bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool pci_hdr_pci_bridge_out(bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool pci_hdr_normal_out(bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool pci_host_bridge_out(bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool pci_owned_out(bfvmm::intel_x64::io_instruction_handler::info_t &info);
    bool pci_owned_msi_out(bfvmm::intel_x64::io_instruction_handler::info_t &info);

    // -------------------------------------------------------------------------
    // VMCalls
    // -------------------------------------------------------------------------

    bool HYPERVISOR_memory_op(gsl::not_null<vcpu *> vcpu);
    void XENMEM_decrease_reservation_handler(gsl::not_null<vcpu *> vcpu);
    void XENMEM_add_to_physmap_handler(gsl::not_null<vcpu *> vcpu);
    void XENMEM_memory_map_handler(gsl::not_null<vcpu *> vcpu);

    bool HYPERVISOR_xen_version(gsl::not_null<vcpu *> vcpu);
    void XENVER_get_features_handler(gsl::not_null<vcpu *> vcpu);

    bool HYPERVISOR_grant_table_op(gsl::not_null<vcpu *> vcpu);
    void GNTTABOP_query_size_handler(gsl::not_null<vcpu *> vcpu);
    void GNTTABOP_set_version_handler(gsl::not_null<vcpu *> vcpu);

    bool HYPERVISOR_vcpu_op(gsl::not_null<vcpu *> vcpu);
    void VCPUOP_register_vcpu_info_handler(gsl::not_null<vcpu *> vcpu);
    void VCPUOP_stop_periodic_timer_handler(gsl::not_null<vcpu *> vcpu);
    void VCPUOP_stop_singleshot_timer_handler(gsl::not_null<vcpu *> vcpu);
    void VCPUOP_set_singleshot_timer_handler(gsl::not_null<vcpu *> vcpu);

    bool HYPERVISOR_hvm_op(gsl::not_null<vcpu *> vcpu);
    void HVMOP_set_param_handler(gsl::not_null<vcpu *> vcpu);
    void HVMOP_get_param_handler(gsl::not_null<vcpu *> vcpu);
    void HVMOP_pagetable_dying_handler(gsl::not_null<vcpu *> vcpu);

    bool HYPERVISOR_event_channel_op(gsl::not_null<vcpu *> vcpu);
    void EVTCHNOP_init_control_handler(gsl::not_null<vcpu *> vcpu);
    void EVTCHNOP_expand_array_handler(gsl::not_null<vcpu *> vcpu);
    void EVTCHNOP_alloc_unbound_handler(gsl::not_null<vcpu *> vcpu);
    void EVTCHNOP_send_handler(gsl::not_null<vcpu *> vcpu);
    void EVTCHNOP_bind_ipi_handler(gsl::not_null<vcpu *> vcpu);
    void EVTCHNOP_bind_virq_handler(gsl::not_null<vcpu *> vcpu);
    void EVTCHNOP_bind_vcpu_handler(gsl::not_null<vcpu *> vcpu);

    // -------------------------------------------------------------------------
    // APIC
    // -------------------------------------------------------------------------

    using rip_cache_t = std::unordered_map<uint64_t, bfvmm::x64::unique_map<uint8_t>>;

    uint8_t *map_rip(rip_cache_t &rc, uint64_t rip, uint64_t len);

    bool xapic_handle_write(
        vcpu_t *vcpu,
        bfvmm::intel_x64::ept_violation_handler::info_t &info);

    void xapic_handle_write_icr(uint32_t icr_low);
    void xapic_handle_write_lvt_timer(uint32_t timer);

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    bool local_xenstore() const;
    void pci_init_caps();
    void pci_init_bars();
    void pci_init_nic();

    // -------------------------------------------------------------------------
    // Quirks
    // -------------------------------------------------------------------------

    void register_unplug_quirk();

private:

    uint64_t m_apic_base{};
    uint64_t m_pet_shift{};
    uint64_t m_pet_ticks{};
    uint64_t m_tsc_freq_khz{};

    std::unordered_map<uint32_t, uint64_t> m_msrs;

    rip_cache_t m_rc_xapic;

    std::array<uint32_t, 2> m_bridge_bar = {0};
    std::array<uint32_t, 6> m_nic_bar = {0};
    pci_bars_t m_nic_bar_list;

private:

    vcpu *m_vcpu;
    domain *m_domain;

    vcpu_info_t *m_vcpu_info;
    uint64_t m_hypercall_page_gpa{};
    uint32_t m_cf8{};
    uint32_t m_msi_addr{};
    uint32_t m_msi_cap{};
    uint32_t m_msix_cap{};
    uint32_t m_msix_cap_prev{};
    uint32_t m_msix_cap_next{};

    uint32_t m_nic_io;
    uint32_t m_nic_io_size;

    uintptr_t m_nic_prefetch;
    uintptr_t m_nic_prefetch_size;

    uintptr_t m_nic_non_prefetch;
    uintptr_t m_nic_non_prefetch_size;

    bfvmm::x64::unique_map<vcpu_runstate_info_t> m_runstate_info;
    bfvmm::x64::unique_map<vcpu_time_info_t> m_time_info;
    bfvmm::x64::unique_map<shared_info_t> m_shared_info;
    bfvmm::x64::unique_map<uint8_t> m_vcpu_info_ump;
    bfvmm::x64::unique_map<uint8_t> m_console;

    std::unique_ptr<boxy::intel_x64::evtchn_op> m_evtchn_op;
    //std::unique_ptr<boxy::intel_x64::gnttab_op> m_gnttab_op;

public:

    /// @cond

    xen_op_handler(xen_op_handler &&) = default;
    xen_op_handler &operator=(xen_op_handler &&) = default;

    xen_op_handler(const xen_op_handler &) = delete;
    xen_op_handler &operator=(const xen_op_handler &) = delete;

    /// @endcond
};

}

#endif
