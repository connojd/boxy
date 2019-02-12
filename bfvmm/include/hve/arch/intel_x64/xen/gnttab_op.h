//
// Bareflank Boxy
// Copyright (C) 2018 Assured Information Security, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#ifndef GNTTABOP_INTEL_X64_BOXY_H
#define GNTTABOP_INTEL_X64_BOXY_H

#include <bfmath.h>
#include <bfvmm/hve/arch/x64/unmapper.h>
#include "xen.h"

#include <xen/public/xen.h>
#include <xen/public/memory.h>
#include <xen/public/grant_table.h>


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

class EXPORT_BOXY_HVE gnttab_op
{
public:

    using shared_entry_t = grant_entry_v2_t;
    static_assert(is_power_of_2(sizeof(shared_entry_t)));

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu of the gnttab_op
    ///
    gnttab_op(vcpu_t *vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~gnttab_op() = default;

    /// Query size
    ///
    void query_size(gsl::not_null<gnttab_query_size_t *> arg);

    /// Set version
    ///
    void set_version(gsl::not_null<gnttab_set_version_t *> arg);

    /// Map grant table
    ///
    void mapspace_grant_table(gsl::not_null<xen_add_to_physmap_t *> arg);

private:

    /// Max number of frames per domain (the Xen default)
    //
    static constexpr auto max_nr_frames = 64;

    vcpu *m_vcpu{};
    uint32_t m_version{};

    std::vector<page_ptr<shared_entry_t>> m_shared_gnttab;

public:

    /// @cond

    gnttab_op(gnttab_op &&) = default;
    gnttab_op &operator=(gnttab_op &&) = default;

    gnttab_op(const gnttab_op &) = delete;
    gnttab_op &operator=(const gnttab_op &) = delete;

    /// @endcond
};

}

#endif
