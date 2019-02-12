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
