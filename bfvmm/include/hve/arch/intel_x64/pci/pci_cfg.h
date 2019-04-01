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

#ifndef PCI_INTEL_X64_BOXY_H
#define PCI_INTEL_X64_BOXY_H

#include <list>
#include <array>

#include <bfgsl.h>
#include <bfdebug.h>

#include <arch/x64/portio.h>

namespace pci {

///----------------------------------------------------------------------------
/// Types
///----------------------------------------------------------------------------

enum header_t {
    hdr_normal = 0x00,
    hdr_pci_bridge = 0x01,
    hdr_cardbus_bridge = 0x02,
    hdr_normal_multi = 0x80 | hdr_normal,
    hdr_pci_bridge_multi = 0x80 | hdr_pci_bridge,
    hdr_cardbus_bridge_multi = 0x80 | hdr_cardbus_bridge,
    hdr_nonexistant = 0xFF
};

enum class_code_t {
    cc_unclass = 0x00,
    cc_storage = 0x01,
    cc_network = 0x02,
    cc_display = 0x03,
    cc_multimedia = 0x04,
    cc_memory = 0x05,
    cc_bridge = 0x06,
    cc_simple_comms = 0x07,
    cc_input = 0x09,
    cc_processor = 0x0B,
    cc_serial_bus = 0x0C,
    cc_wireless = 0x0D
};

enum subclass_bridge_t {
    sc_bridge_host = 0x00,
    sc_bridge_isa = 0x01,
    sc_bridge_eisa = 0x02,
    sc_bridge_mca = 0x03,
    sc_bridge_pci_decode = 0x04,
    sc_bridge_pcmcia = 0x05,
    sc_bridge_nubus = 0x06,
    sc_bridge_cardbus = 0x07,
    sc_bridge_raceway = 0x08,
    sc_bridge_pci_semi_trans = 0x09,
    sc_bridge_infiniband = 0x0A,
    sc_bridge_other = 0x80
};

enum capid_t {
    capid_pcie = 0x01,
    capid_msi = 0x05,
    capid_msix = 0x11
};

uint32_t cf8_read_reg(uint32_t cf8, uint32_t reg);
void cf8_write_reg(uint32_t cf8, uint32_t reg, uint32_t val);

struct bar {
    enum { mm_t, io_t };

    explicit bar(uint32_t cf8, uint32_t reg)
    {
        const auto val = cf8_read_reg(cf8, reg);

        m_data = val;
        if (m_data == 0) {
            return;
        }

        m_type = ((val & 0x1) != 0) ? io_t : mm_t;
        m_mask = ((val & 0x1) != 0) ? 0xFFFFFFFC : 0xFFFFFFF0;
        m_addr = val & m_mask;

        // Extract the size in bytes
        cf8_write_reg(cf8, reg, 0xFFFFFFFF);
        m_size = ~(cf8_read_reg(cf8, reg) & m_mask) + 1U;
        cf8_write_reg(cf8, reg, val);

        if (m_type == mm_t) {
            m_prefetch = (val & 0x8U) != 0U;
            m_bits = 32U;
            if (((val & 0x6U) >> 1U) == 2) {
                m_bits += m_bits;
                m_addr |= static_cast<uint64_t>(cf8_read_reg(cf8, reg + 1)) << 32;
            }
        }
    }

    bool is_mm() const { return m_type == mm_t; }
    bool is_empty() const { return m_data == 0; }
    bool is_64bit() const { return m_bits == 64; }
    uint32_t size() const { return m_size; }
    uint32_t data() const { return m_data; }

private:

    bool m_prefetch{};
    uint8_t m_type{};
    uint8_t m_bits{};
    uintptr_t m_addr{};
    uint32_t m_size{};
    uint32_t m_mask{};
    uint32_t m_data{};
};

using bar_list_t = std::list<const struct bar>;

///----------------------------------------------------------------------------
/// CONFIG_ADDR helpers
///----------------------------------------------------------------------------

inline bool cf8_is_enabled(uint32_t cf8)
{ return ((cf8 & 0x80000000UL) >> 31) != 0; }

inline uint32_t cf8_to_bus(uint32_t cf8)
{ return (cf8 & 0x00FF0000UL) >> 16; }

inline uint32_t cf8_to_dev(uint32_t cf8)
{ return (cf8 & 0x0000F800UL) >> 11; }

inline uint32_t cf8_to_fun(uint32_t cf8)
{ return (cf8 & 0x00000700UL) >> 8; }

inline uint32_t cf8_to_reg(uint32_t cf8)
{ return (cf8 & 0x000000FCUL) >> 2; }

inline uint32_t cf8_to_off(uint32_t cf8)
{ return (cf8 & 0x00000003UL); }

using namespace ::x64::portio;

inline uint32_t cf8_read_reg(uint32_t cf8, uint32_t reg)
{
    const auto addr = (cf8 & 0xFFFFFF03UL) | (reg << 2);
    outd(0xCF8, addr);
    return ind(0xCFC);
}

inline void cf8_write_reg(uint32_t cf8, uint32_t reg, uint32_t val)
{
    const auto addr = (cf8 & 0xFFFFFF03UL) | (reg << 2);
    outd(0xCF8, addr);
    outd(0xCFC, val);
}

inline uint32_t bdf_to_cf8(uint32_t b, uint32_t d, uint32_t f)
{
    return (1UL << 31) | (b << 16) | (d << 11) | (f << 8);
}

///----------------------------------------------------------------------------
/// Device attributes
///----------------------------------------------------------------------------

inline bool exists(uint32_t cf8)
{ return cf8_read_reg(cf8, 0) != 0xFFFFFFFFUL; }

inline uint32_t header(uint32_t cf8)
{
    const auto val = cf8_read_reg(cf8, 3);
    return (val & 0x00FF0000UL) >> 16;
}

inline bool is_normal(uint32_t cf8)
{
    const auto hdr = header(cf8);
    return hdr ==  hdr_normal || hdr == hdr_normal_multi;
}

inline bool is_pci_bridge(uint32_t cf8)
{
    const auto hdr = header(cf8);
    return hdr ==  hdr_pci_bridge || hdr == hdr_pci_bridge_multi;
}

inline bool is_host_bridge(uint32_t cf8)
{
    const auto val = cf8_read_reg(cf8, 2);
    const auto cc = (val & 0xFF000000UL) >> 24;
    const auto sc = (val & 0x00FF0000UL) >> 16;

    return cc == cc_bridge && sc == sc_bridge_host;
}

inline uint32_t secondary_bus(uint32_t bus, uint32_t dev, uint32_t fun)
{
    const auto cf8 = bdf_to_cf8(bus, dev, fun);
    expects(is_pci_bridge(cf8));

    const auto reg = cf8_read_reg(cf8, 6);
    return (reg & 0xFF00UL) >> 8;
}

inline std::pair<uint32_t, uint32_t> find_cap(uint32_t cf8, uint32_t capid)
{
    auto reg = (cf8_read_reg(cf8, 0xD) & 0xFF) >> 2;

    while (reg != 0) {
        const auto val = cf8_read_reg(cf8, reg);
        if ((val & 0xFF) == capid) {
            return {reg, val};
        }
        reg = (val & 0xFF00) >> (8 + 2);
    }

    return {0, 0};
}

///----------------------------------------------------------------------------
/// Config space read/write
///----------------------------------------------------------------------------

inline uint32_t cfg_read(uint32_t cf8, uint32_t port, uint32_t size)
{
    expects(port >= 0xCFC && port <= 0xCFF);
    outd(0xCF8, cf8);

    switch (size) {
        case 1: return inb(port);
        case 2: return inw(port);
        case 4: return ind(port);
        default: throw std::runtime_error("Invalid PCI access size");
    }
}

inline void cfg_write(uint32_t cf8, uint32_t port, uint32_t sz, uint32_t data)
{
    expects(port >= 0xCFC && port <= 0xCFF);
    outd(0xCF8, cf8);

    switch (sz) {
        case 1:
            outb(port, gsl::narrow_cast<uint8_t>(data));
            return;
        case 2:
            outw(port, gsl::narrow_cast<uint16_t>(data));
            return;
        case 4:
            outd(port, gsl::narrow_cast<uint32_t>(data));
            return;
        default:
            throw std::runtime_error("Invalid PCI access size");
    }
}

///----------------------------------------------------------------------------
/// BAR parsing
///----------------------------------------------------------------------------

inline void parse_bars_normal(uint32_t cf8, bar_list_t &bars)
{
    const std::array<uint8_t, 6> bar_regs = {0x4, 0x5, 0x6, 0x7, 0x8, 0x9};

    for (auto i = 0; i < bar_regs.size(); i++) {
        const auto b = bar(cf8, bar_regs[i]);

        if (b.is_empty()) {
            continue;
        }

        if (b.is_mm() && b.is_64bit()) {
            ++i;
        }

        bars.push_back(b);
    }
}

inline void parse_bars_pci_bridge(uint32_t cf8, bar_list_t &bars)
{
    const std::array<uint8_t, 2> bar_regs = {0x4, 0x5};

    for (auto i = 0; i < bar_regs.size(); i++) {
        const auto b = bar(cf8, bar_regs[i]);

        if (b.is_empty()) {
            continue;
        }

        if (b.is_mm() && b.is_64bit()) {
            ++i;
        }

        bars.push_back(b);
    }
}

inline void parse_bars(uint32_t cf8, bar_list_t &bars)
{
    const auto hdr = header(cf8);

    switch (hdr) {
        case hdr_normal:
        case hdr_normal_multi:
            parse_bars_normal(cf8, bars);
            return;

        case hdr_pci_bridge:
        case hdr_pci_bridge_multi:
            parse_bars_pci_bridge(cf8, bars);
            return;

        default:
            bfalert_nhex(0, "parse_bars: Unsupported header type:", hdr);
            return;
    }
}
}

#endif
