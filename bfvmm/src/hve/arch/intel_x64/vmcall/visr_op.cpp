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

#include <acpi.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/visr.h>
#include <hve/arch/intel_x64/vmcall/visr_op.h>

bfvmm::x64::unique_map<uint8_t> g_mcfg_map{nullptr};
gsl::span<uint8_t> g_mcfg;

namespace boxy::intel_x64
{

vmcall_visr_op_handler::vmcall_visr_op_handler(gsl::not_null<vcpu *> vcpu) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_vmcall_handler(
        vmcall_handler_delegate(vmcall_visr_op_handler, dispatch)
    );
}

void vmcall_visr_op_handler::map_mcfg(vcpu *vcpu)
{
    auto hdr_len = sizeof(struct acpi_header_t);
    auto hdr_map = vcpu->map_gva_4k<uint8_t>(vcpu->rbx(), hdr_len);
    auto tbl_len = *reinterpret_cast<uint32_t *>(hdr_map.get() + 4);

    // Expect at least one allocation entry after the other table fields
    expects(tbl_len >= 44 + sizeof(struct mcfg_alloc_t));

    hdr_map.reset();
    g_mcfg_map = vcpu->map_gva_4k<uint8_t>(vcpu->rbx(), tbl_len);
    g_mcfg = gsl::span<uint8_t>(g_mcfg_map.get(), tbl_len);

    auto tbl = (struct acpi_header_t *)g_mcfg.data();

    printf("Signature: %c%c%c%c\n", tbl->signature[0], tbl->signature[1], tbl->signature[2], tbl->signature[3]);
    printf("Length: %u\n", tbl->length);
    printf("Revision: %u\n", tbl->revision);
    printf("Checksum: %u\n", tbl->checksum);

    auto alloc = (struct mcfg_alloc_t *)((uintptr_t)tbl + 44);
    printf("MMCFG base address: 0x%lx\n", alloc->base);
    printf("MMCFG segment number: 0x%x\n", alloc->segment);
    printf("MMCFG start bus: 0x%x\n", alloc->startbus);
    printf("MMCFG end bus: 0x%x\n", alloc->endbus);

    printf("0000:03:00.0 config space:\n");
    auto cfg = vcpu->map_gpa_4k<uint8_t>(alloc->base + (3 << 20), 4096);

    for (int i = 0; i < 256; i++) {
        printf("%02x", cfg.get()[i]);
        if (i % 16 == 15) {
            printf("\n");
        }
    }

    vcpu->set_rax(SUCCESS);
}

void vmcall_visr_op_handler::emulate(vcpu *vcpu) {}
void vmcall_visr_op_handler::enable(vcpu *vcpu) {}

bool vmcall_visr_op_handler::dispatch(vcpu *vcpu)
{
    if (bfopcode(vcpu->rax()) != __enum_visr_op) {
        return false;
    }

    switch (vcpu->rax()) {
    case __enum_visr_op__map_mcfg:
        this->map_mcfg(vcpu);
        return true;
    case __enum_visr_op__emulate:
        this->emulate(vcpu);
        return true;
    case __enum_visr_op__enable:
        this->enable(vcpu);
        return true;
    }

    throw std::runtime_error("unknown visr opcode");
}
}
