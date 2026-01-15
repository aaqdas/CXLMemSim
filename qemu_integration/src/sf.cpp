#include <cstdint>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <cassert>

// New SnoopFilter implementation uses dedicated SFEntry/SFSet structures (see include/sf.h)
#include "../include/sf.h"
#include "../include/cache.h" // for intLog2

SnoopFilter::SnoopFilter(uint32_t sets_, uint32_t assoc_, uint32_t line_size_, uint32_t hosts_)
    : num_sets(sets_), assoc(assoc_), line_size(line_size_), num_hosts(hosts_) {
    // Cap hosts to 64 and use a single 64-bit mask per entry
    if (num_hosts == 0) num_hosts = 64; // default
    assert(num_hosts <= 64 && "SnoopFilter supports up to 64 hosts");
    sets = new SFSet[num_sets];
    for (uint32_t i = 0; i < num_sets; ++i) {
        sets[i].entries = new SFEntry[assoc];
        sets[i].fifo_ptr = 0;
        for (uint32_t j = 0; j < assoc; ++j) {
            sets[i].entries[j].tag = 0ULL;
            sets[i].entries[j].mask = 0ULL;
            sets[i].entries[j].mesi_state = MESI_INVALID;
        }
    }
}

SnoopFilter::~SnoopFilter() {
    for (uint32_t i = 0; i < num_sets; ++i) {
        delete[] sets[i].entries;
    }
    delete[] sets;
}

void SnoopFilter::read(uint64_t addr, uint64_t* out_mask, CacheState* mesi_state, bool* hit) {
    uint64_t set_no = (addr >> intLog2(line_size)) % num_sets;
    uint64_t tag = (addr >> (intLog2(line_size) + intLog2(num_sets)));
    for (uint32_t w = 0; w < assoc; ++w) {
        SFEntry& e = sets[set_no].entries[w];
        if (e.mesi_state != MESI_INVALID && e.tag == tag) {
            if (out_mask) *out_mask = e.mask;
            if (mesi_state) *mesi_state = e.mesi_state;
            if (hit) *hit = true;
            return;
        }
    }
    if (out_mask) *out_mask = 0ULL;
    if (mesi_state) *mesi_state = MESI_INVALID;
    if (hit) *hit = false;
}

void SnoopFilter::write(uint64_t addr, CacheState mesi_state, uint64_t mask,
               uint64_t* bi_mask, uint64_t* bi_addr, bool* bi_valid) {
    uint64_t set_no = (addr >> intLog2(line_size)) % num_sets;
    uint64_t tag = (addr >> (intLog2(line_size) + intLog2(num_sets)));

    // initialize out params
    if (bi_mask) *bi_mask = 0ULL;
    if (bi_addr) *bi_addr = 0ULL;
    if (bi_valid) *bi_valid = false;

    // Simple behavior: update existing entry if present; otherwise insert until set is full.
    // Only when we must evict (set is full) we issue a back-invalidate for the evicted entry.

    // 1) Search for existing entry and update
    for (uint32_t w = 0; w < assoc; ++w) {
        SFEntry& e = sets[set_no].entries[w];
        if (e.mesi_state != MESI_INVALID && e.tag == tag) {
            e.mesi_state = mesi_state;
            e.mask = mask;
            return; // no BI on simple update
        }
    }

    // 2) Find an empty (invalid) entry and use it
    for (uint32_t w = 0; w < assoc; ++w) {
        SFEntry& e = sets[set_no].entries[w];
        if (e.mesi_state == MESI_INVALID) {
            e.tag = tag;
            e.mesi_state = mesi_state;
            e.mask = mask;
            return; // no BI when adding to free slot
        }
    }

    // 3) Set is full -> evict FIFO victim and issue BI for that victim
    uint32_t evict = sets[set_no].fifo_ptr;
    SFEntry& victim = sets[set_no].entries[evict];

    if (victim.mesi_state != MESI_INVALID) {
        if (bi_mask) *bi_mask = victim.mask;
        if (bi_addr) *bi_addr = (victim.tag << (intLog2(line_size) + intLog2(num_sets))) + set_no;
        if (bi_valid) *bi_valid = true;
    }

    // Replace victim
    victim.tag = tag;
    victim.mask = mask;
    victim.mesi_state = mesi_state;

    // advance FIFO pointer
    sets[set_no].fifo_ptr = (sets[set_no].fifo_ptr + 1) % assoc;
    return;
}

