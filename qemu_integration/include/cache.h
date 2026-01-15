#ifndef QEMU_CACHE_H
#define QEMU_CACHE_H


#include "qemu_cxl_memsim.h"
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif
#include <cmath>
#include <cstdbool>   // For bool   
#include <cstdint>    // For uint32_t, uint64_t, uint8_t
#include <cstddef>    // For size_t
#include <cstring>    // For memcpy

#ifdef __cplusplus
class Cache { // Write-Back Set Associative Cache
public:
    struct CacheLine {
        uint64_t tag;
        uint8_t* data;
        CacheState mesi_state; // 0: Invalid, 1: Shared, 2: Exclusive, 3: Modified
    };

    struct CacheSet {
        CacheLine* lines;
        uint32_t fifo_ptr; // Pointer for FIFO replacement policy
    };

    CacheSet* sets;
    uint32_t num_sets;
    uint32_t assoc;
    uint32_t line_size;

    Cache(uint32_t s, uint32_t a, uint32_t l);
    // : num_sets(s), assoc(a), line_size(l) {
    //     // 1. Allocate the array of sets
    //     sets = new CacheSet[num_sets]; 

    //     for (uint32_t i = 0; i < num_sets; ++i) {
    //         // 2. For each set, allocate the array of lines (the "ways")
    //         sets[i].lines = new CacheLine[assoc];

    //         for (uint32_t j = 0; j < assoc; ++j) {
    //             sets[i].lines[j].tag = 0;
    //             sets[i].lines[j].mesi_state = MESI_INVALID; // Invalid
    //             // 3. Allocate the actual byte storage for this line
    //             sets[i].lines[j].data = new uint8_t[line_size];
    //         }
    //     }
    // }
    ~Cache();
    // ~Cache() {
    //     for (uint32_t i = 0; i < num_sets; ++i) {
    //         for (uint32_t j = 0; j < assoc; ++j) {
    //             delete[] sets[i].lines[j].data;
    //         }
    //         delete[] sets[i].lines;
    //     }
    //     delete[] sets;
    // }

    // Additional methods for cache operations (read, write, evict, etc.) would go here
    virtual void read(uint64_t addr, uint64_t* data, CacheState *mesi_state, bool* hit);
    //  {
    //     uint64_t set_no = (addr >> intLog2(line_size)) % num_sets;
    //     uint64_t tag    = (addr >> (intLog2(line_size) + intLog2(num_sets)));
    //     // Search for the line in the set
    //     for (uint32_t i = 0; i < assoc; ++i) {
    //         if (sets[set_no].lines[i].mesi_state != MESI_INVALID && sets[set_no].lines[i].tag == tag) {
    //             // Cache hit
    //             memcpy(data, sets[set_no].lines[i].data, line_size);
    //             *mesi_state = (CacheState)sets[set_no].lines[i].mesi_state;
    //             *hit = true;
    //             return;
    //         }
    //     }
    //     // Cache miss
	//     *mesi_state = MESI_INVALID;
    //     *hit = false;
    //     // Handle miss (e.g., fetch from memory, evict if necessary, etc.)
    // }

    virtual void write(uint64_t addr, CacheState mesi_state, uint64_t* data, uint64_t write_size, uint64_t* wb_data, uint64_t *wb_addr, bool* wb_valid);
    // {
        // uint64_t set_no = (addr >> intLog2(line_size)) % num_sets;
        // uint64_t tag    = (addr >> (intLog2(line_size) + intLog2(num_sets)));
        // uint64_t block_idx = addr | (line_size - 1);
	    // bool miss;
        // uint64_t evict_idx;
        // // Search for the line in the set
        // for (uint32_t i = 0; i < assoc; ++i) {
        //     if ((sets[set_no].lines[i].mesi_state == MESI_EXCLUSIVE || sets[set_no].lines[i].mesi_state == MESI_MODIFIED) && sets[set_no].lines[i].tag == tag) {
        //         // Cache hit - write data
        //         memcpy(sets[set_no].lines[i].data + block_idx, data, write_size);
        //         sets[set_no].lines[i].mesi_state = MESI_MODIFIED;
        //         return;
        //     } else {
        //         if (sets[set_no].lines[i].mesi_state == MESI_INVALID) {
        //             memcpy(sets[set_no].lines[i].data + block_idx, data, write_size);
        //             sets[set_no].lines[i].mesi_state = MESI_MODIFIED;
        //             sets[set_no].lines[i].tag = tag;
        //             return;
        //         } else {
        //             continue;
        //         }
	    //     }
        // }

        // // FIFO replacement policy: evict the first line in the set
        // miss      = true;	
        // evict_idx = sets[set_no].fifo_ptr;
        // sets[set_no].fifo_ptr = (sets[set_no].fifo_ptr + 1) % assoc;

        // if (miss && (sets[set_no].lines[evict_idx].mesi_state == MESI_MODIFIED) && (sets[set_no].lines[evict_idx].tag == tag)) {
        //     memcpy(wb_data, sets[set_no].lines[evict_idx].data, line_size);
        //     *wb_addr = (sets[set_no].lines[evict_idx].tag << (intLog2(line_size) + intLog2(num_sets))) + set_no;
        //     *wb_valid = true;
        //     memcpy(sets[set_no].lines[evict_idx].data + block_idx, data, write_size);
        //     sets[set_no].lines[evict_idx].mesi_state = MESI_MODIFIED;
        //     sets[set_no].lines[evict_idx].tag = tag;
        //     return;
        // }
    // }

};
#endif

/* SnoopFilter moved to separate header/source: include/sf.h and src/sf.cpp */

#ifdef __cplusplus
}
#endif

// Add this utility function for integer intlog2
static inline uint32_t intLog2(uint32_t x) {
    return (x > 1) ? 31 - __builtin_clz(x) : 0;
}

#endif /* QEMU_CACHE_H */
