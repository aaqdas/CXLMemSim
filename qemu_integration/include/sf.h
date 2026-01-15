#ifndef QEMU_SF_H
#define QEMU_SF_H

#include <cstdint>
#include "qemu_cxl_memsim.h"

// Snoop Filter header: stores per-line host bitmasks instead of full data.


class SnoopFilter {
public:
    uint32_t num_sets;
    uint32_t assoc;
    uint32_t line_size; // line size in bytes for block indexing
    uint32_t num_hosts;
    struct SFEntry {
        uint64_t tag;
        uint64_t mask; // 64-bit host bitmask (supports up to 64 hosts)
        CacheState mesi_state;
    };

    struct SFSet {
        SFEntry* entries; // length == assoc
        uint32_t fifo_ptr;
    };
    SFSet* sets;

    SnoopFilter(uint32_t sets_, uint32_t assoc_, uint32_t line_size_, uint32_t hosts_ = 64);
    ~SnoopFilter();

    // Read the mask for addr; returns mask in `out_mask` (first element) and state/hit
    void read(uint64_t addr, uint64_t* out_mask, CacheState* mesi_state, bool* hit);

    // Write mask for addr; if a line is exclusive, return its mask via bi_mask/bi_addr and set bi_valid.
    void write(uint64_t addr, CacheState mesi_state, uint64_t mask,
               uint64_t* bi_mask, uint64_t* bi_addr, bool* bi_valid);
};

#endif // QEMU_SF_H
