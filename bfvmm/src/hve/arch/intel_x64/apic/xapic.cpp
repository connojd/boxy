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

#include <intrinsics.h>
#include <arch/intel_x64/apic/lapic.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/apic/xapic.h>

//--------------------------------------------------------------------------
// Implementation
//--------------------------------------------------------------------------

namespace boxy::intel_x64
{

namespace lapic_n = ::intel_x64::lapic;

xapic::xapic(gsl::not_null<vcpu *> vcpu) :
    m_vcpu{vcpu},
    m_xapic_ump{vcpu->map_hpa_4k<uint32_t>(vcpu->xapic_hpa())},
    m_xapic_view{m_xapic_ump.get(), 0x1000 / 4}
{ }

void
xapic::init()
{
    this->write(lapic_n::id::indx, lapic_n::id::reset_val);
    this->write(lapic_n::version::indx, lapic_n::version::reset_val);
    this->write(lapic_n::dfr::indx, lapic_n::dfr::reset_val);

    this->write(lapic_n::lvt::cmci::indx, lapic_n::lvt::reset_val);
    this->write(lapic_n::lvt::timer::indx, lapic_n::lvt::reset_val);
    this->write(lapic_n::lvt::lint0::indx, lapic_n::lvt::reset_val);
    this->write(lapic_n::lvt::lint1::indx, lapic_n::lvt::reset_val);
    this->write(lapic_n::lvt::error::indx, lapic_n::lvt::reset_val);

    this->write(lapic_n::svr::indx, lapic_n::svr::reset_val);
}

}
