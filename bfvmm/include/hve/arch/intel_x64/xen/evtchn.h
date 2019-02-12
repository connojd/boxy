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

#ifndef EVTCHN_INTEL_X64_BOXY_H
#define EVTCHN_INTEL_X64_BOXY_H

#include "xen.h"
#include <xen/public/event_channel.h>

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

class EXPORT_BOXY_HVE evtchn
{
public:

    enum state : uint8_t {
        state_free,
        state_reserved,
        state_unbound,
        state_interdomain,
        state_pirq,
        state_virq,
        state_ipi
    };

    using state_t = enum state;

    ///
    /// @expects
    /// @ensures
    ///
    evtchn() = default;

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~evtchn() = default;

    inline auto is_pending() const
    { return m_is_pending; }

    inline auto state() const
    { return m_state; }

    inline auto priority() const
    { return m_priority; }

    inline auto prev_priority() const
    { return m_prev_priority; }

    inline auto vcpuid() const
    { return m_vcpuid; }

    inline auto prev_vcpuid() const
    { return m_prev_vcpuid; }

    inline auto port() const
    { return m_port; }

    inline auto virq() const
    { return m_ed.virq; }

    inline auto set_pending()
    { m_is_pending = true; }

    inline auto set_state(enum state state)
    { m_state = state; }

    inline auto set_priority(uint8_t priority)
    { m_priority = priority; }

    inline auto set_prev_priority(uint8_t prev_priority)
    { m_prev_priority = prev_priority; }

    inline auto set_vcpuid(vcpuid_t id)
    { m_vcpuid = id; }

    inline auto set_prev_vcpuid(vcpuid_t id)
    { m_prev_vcpuid = id; }

    inline auto set_port(evtchn_port_t port)
    { return m_port = port; }

    inline auto clear_pending()
    { m_is_pending = false; }

    inline auto set_virq(uint32_t virq)
    { m_ed.virq = virq; }

private:

    union evt_data {
        uint32_t virq;
        // TODO:
        // unbound-specific data
        // interdomain-specific data
        // pirq-specific data
    } m_ed;

    bool m_is_pending{};
    enum state m_state{state_free};

    uint8_t m_priority{EVTCHN_FIFO_PRIORITY_DEFAULT};
    uint8_t m_prev_priority{EVTCHN_FIFO_PRIORITY_DEFAULT};

    vcpuid_t m_vcpuid{};
    vcpuid_t m_prev_vcpuid{};

    evtchn_port_t m_port{};
    /// TODO mutable std::mutex m_mutex{};

public:

    /// @cond

    evtchn(evtchn &&) = default;
    evtchn &operator=(evtchn &&) = default;

    evtchn(const evtchn &) = delete;
    evtchn &operator=(const evtchn &) = delete;

    /// @endcond
};

constexpr auto is_power_of_2(size_t n)
{ return (n > 0) && ((n & (n - 1)) == 0); }

constexpr auto next_power_of_2(size_t n)
{
    while (!is_power_of_2(n)) {
        n++;
    }
    return n;
}

constexpr auto log2(const size_t n)
{
    for (auto i = 0; i < 64; i++) {
        if (((1ULL << i) & n) == n) {
            return i;
        }
    }
}

}

#endif
