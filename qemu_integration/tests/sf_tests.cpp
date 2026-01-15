#include <iostream>
#include <cassert>
#include <vector>
#include "../include/sf.h"
#include "../include/cache.h" // for intLog2

static void printTestStatus(const std::string& name, bool passed) {
    std::cout << "Test: " << name << " ... " << (passed ? "PASSED" : "FAILED") << std::endl;
}

void test_basic_insert_and_read() {
    std::cout << "Running Test: SF Basic Insert & Read..." << std::endl;
    const uint32_t num_sets = 64;
    const uint32_t assoc = 4;
    const uint32_t line_size = 64;

    SnoopFilter sf(num_sets, assoc, line_size, 64);

    uint64_t addr = 0x1000;
    uint64_t mask = 0x1ULL << 3; // host 3
    bool bi_valid = false;
    uint64_t bi_mask = 0, bi_addr = 0;

    sf.write(addr, MESI_EXCLUSIVE, mask, &bi_mask, &bi_addr, &bi_valid);
    assert(!bi_valid && "No BI on first insert");

    uint64_t out_mask = 0;
    CacheState st;
    bool hit = false;
    sf.read(addr, &out_mask, &st, &hit);
    assert(hit && "Expected hit after insert");
    assert(out_mask == mask && "Returned mask should match");
    assert(st == MESI_EXCLUSIVE && "State should be EXCLUSIVE");

    printTestStatus("SF Basic Insert & Read", true);
}

void test_eviction_emits_bi() {
    std::cout << "Running Test: SF Eviction BI..." << std::endl;
    const uint32_t num_sets = 1; // force all addresses into same set
    const uint32_t assoc = 2;    // 2-way
    const uint32_t line_size = 64;

    SnoopFilter sf(num_sets, assoc, line_size, 64);

    uint64_t a0 = 0x0;
    uint64_t a1 = 0x1000;
    uint64_t a2 = 0x2000; // will cause eviction of a0 (FIFO)

    uint64_t m0 = 0x1ULL << 1;
    uint64_t m1 = 0x1ULL << 2;
    uint64_t m2 = 0x1ULL << 3;

    bool bi_valid = false;
    uint64_t bi_mask = 0, bi_addr = 0;

    sf.write(a0, MESI_MODIFIED, m0, &bi_mask, &bi_addr, &bi_valid);
    assert(!bi_valid);
    sf.write(a1, MESI_MODIFIED, m1, &bi_mask, &bi_addr, &bi_valid);
    assert(!bi_valid);

    // Now insert third, should evict a0 and return its mask/address
    sf.write(a2, MESI_MODIFIED, m2, &bi_mask, &bi_addr, &bi_valid);
    assert(bi_valid && "Eviction must emit BI");
    assert(bi_mask == m0 && "BI mask should equal evicted mask");

    // compute expected bi_addr: reconstruct as SnoopFilter does
    // uint64_t set_no = (a0 >> intLog2(line_size)) % num_sets;
    // uint64_t tag = (a0 >> (intLog2(line_size) + intLog2(num_sets)));
    // uint64_t expected_addr = (tag << (intLog2(line_size) + intLog2(num_sets))) + set_no;
    assert(bi_addr == a0 && "BI addr should match expected physical address");

    printTestStatus("SF Eviction BI", true);
}

void test_update_no_eviction() {
    std::cout << "Running Test: SF Update No Eviction..." << std::endl;
    const uint32_t num_sets = 4;
    const uint32_t assoc = 2;
    const uint32_t line_size = 64;
    SnoopFilter sf(num_sets, assoc, line_size, 64);

    uint64_t addr = 0x3000;
    uint64_t m1 = 0xAAULL;
    uint64_t m2 = 0x55ULL;

    bool bi_valid = false;
    uint64_t bi_mask = 0, bi_addr = 0;

    sf.write(addr, MESI_EXCLUSIVE, m1, &bi_mask, &bi_addr, &bi_valid);
    assert(!bi_valid);

    // update same tag with new mask and repeat multiple times to ensure no eviction
    sf.write(addr, MESI_EXCLUSIVE, m2, &bi_mask, &bi_addr, &bi_valid);
    assert(!bi_valid && "Update should not evict");

    for (int i = 0; i < 10; ++i) {
        bi_valid = false; bi_mask = 0; bi_addr = 0;
        sf.write(addr, MESI_EXCLUSIVE, m2, &bi_mask, &bi_addr, &bi_valid);
        assert(!bi_valid && "Repeated update should not evict");
    }

    uint64_t out_mask = 0; CacheState st; bool hit = false;
    sf.read(addr, &out_mask, &st, &hit);
    assert(hit && out_mask == m2);

    printTestStatus("SF Update No Eviction", true);
}

int main() {
    try {
        test_basic_insert_and_read();
        test_eviction_emits_bi();
        test_update_no_eviction();
        std::cout << "\nSF tests passed successfully!" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Test failed with error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}
