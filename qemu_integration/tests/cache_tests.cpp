#include <iostream>
#include <cassert>
#include <vector>
#include "../include/cache.h"
#include "../include/qemu_cxl_memsim.h"

// Helper to print test status
static void printTestStatus(const std::string& name, bool passed) {
    std::cout << "Test: " << name << " ... " << (passed ? "PASSED" : "FAILED") << std::endl;
}

void test_basic_read_write() {
    std::cout << "Running Test: Basic Read/Write..." << std::endl;
    const size_t line_size = 64;
    Cache cache(64, 4, line_size);

    uint64_t addr = 0x1000;
    uint64_t data_to_write = 0xDEADBEEFCAFEBABEULL;
    std::vector<uint64_t> write_buf(line_size / sizeof(uint64_t));
    std::vector<uint64_t> read_buf(line_size / sizeof(uint64_t));
    std::vector<uint64_t> wb_buf(line_size / sizeof(uint64_t));
    write_buf.assign(write_buf.size(), 0);
    write_buf[0] = data_to_write;
    std::fill(read_buf.begin(), read_buf.end(), 0);
    std::fill(wb_buf.begin(), wb_buf.end(), 0);
    CacheState state;
    bool hit = false;

    // 1. Initial Read (Should be a Miss)
    cache.read(addr, read_buf.data(), &state, &hit);
    assert(!hit && "Expected cache miss on initial read");
    std::cout << "  Initial read: MISS as expected." << std::endl;

    // 2. Write Data
    bool wb_valid = false;
    uint64_t wb_addr = 0;
    std::cout << "    Write buffer contents: ";
    for (size_t i = 0; i < write_buf.size(); ++i) {
        std::cout << "0x" << std::hex << write_buf[i];
        if (i != write_buf.size() - 1) std::cout << ", ";
    }
    std::cout << std::dec << std::endl;
    cache.write(addr, MESI_MODIFIED, write_buf.data(), line_size, wb_buf.data(), &wb_addr, &wb_valid);
    assert(!wb_valid && "No eviction should occur on first write");
    std::cout << "  Write: Data written, no eviction." << std::endl;

    // 3. Read Data back (Should be a Hit)
    std::fill(read_buf.begin(), read_buf.end(), 0);
    cache.read(addr, read_buf.data(), &state, &hit);
    assert(hit && "Expected cache hit after write");
    // Print out the entire cache line for verification
    std::cout << "    Cache line contents after read: ";
    for (size_t i = 0; i < read_buf.size(); ++i) {
        std::cout << "0x" << std::hex << read_buf[i];
        if (i != read_buf.size() - 1) std::cout << ", ";
    }
    std::cout << std::dec << std::endl;

    uint64_t data_read = read_buf[0];
    std::cout << "    Written data: 0x" << std::hex << data_to_write << ", Read data: 0x" << data_read << std::dec << std::endl;
    assert(data_read == data_to_write && "Read data should match written data");
    assert(state == MESI_MODIFIED && "MESI state should be MODIFIED after write");
    std::cout << "  Read after write: HIT, data and state correct." << std::endl;

    // 4. Overwrite with new data
    uint64_t new_data = 0x123456789ABCDEF0ULL;
    write_buf.assign(write_buf.size(), 0);
    write_buf[0] = new_data;
    cache.write(addr, MESI_MODIFIED, write_buf.data(), line_size, wb_buf.data(), &wb_addr, &wb_valid);
    std::fill(read_buf.begin(), read_buf.end(), 0);
    cache.read(addr, read_buf.data(), &state, &hit);
    assert(hit && read_buf[0] == new_data && "Overwrite should succeed");
    std::cout << "  Overwrite: Data updated and verified." << std::endl;

    printTestStatus("Basic Read/Write", true);
}

void test_fifo_replacement() {
    std::cout << "Running Test: FIFO Replacement..." << std::endl;
    uint32_t assoc = 2;
    const size_t fifo_line_size = 64;
    Cache cache(1, assoc, fifo_line_size);

    uint64_t val1 = 0xA, val2 = 0xB, val3 = 0xC;
    std::vector<uint64_t> wb_buf2(fifo_line_size / sizeof(uint64_t));
    uint64_t wb_addr = 0;
    std::vector<uint64_t> write_buf1(fifo_line_size / sizeof(uint64_t));
    std::vector<uint64_t> write_buf2(fifo_line_size / sizeof(uint64_t));
    std::vector<uint64_t> write_buf3(fifo_line_size / sizeof(uint64_t));
    std::vector<uint64_t> read_buf2(fifo_line_size / sizeof(uint64_t));
    write_buf1.assign(write_buf1.size(), 0); write_buf1[0] = val1;
    write_buf2.assign(write_buf2.size(), 0); write_buf2[0] = val2;
    write_buf3.assign(write_buf3.size(), 0); write_buf3[0] = val3;

    bool wb_valid2 = false;
    bool hit2 = false;
    CacheState dummy_state;

    // Fill the two ways
    cache.write(0x0, MESI_MODIFIED, write_buf1.data(), fifo_line_size, wb_buf2.data(), &wb_addr, &wb_valid2);
    assert(!wb_valid2 && "No eviction on first write");
    cache.write(0x1000, MESI_MODIFIED, write_buf2.data(), fifo_line_size, wb_buf2.data(), &wb_addr, &wb_valid2);
    assert(!wb_valid2 && "No eviction on second write");

    // Both should be in cache now
    std::fill(read_buf2.begin(), read_buf2.end(), 0);
    cache.read(0x0, read_buf2.data(), &dummy_state, &hit2); assert(hit2 && read_buf2[0] == val1);
    std::fill(read_buf2.begin(), read_buf2.end(), 0);
    cache.read(0x1000, read_buf2.data(), &dummy_state, &hit2); assert(hit2 && read_buf2[0] == val2);
    std::cout << "  Both lines present after initial writes." << std::endl;
    std::cout << "    Dummy state after read: " << dummy_state << std::endl;

    // Write a third address (should evict 0x0)
    cache.write(0x2000, MESI_MODIFIED, write_buf3.data(), fifo_line_size, wb_buf2.data(), &wb_addr, &wb_valid2);
    assert(wb_valid2 && "Eviction should occur on third write");
    assert(wb_buf2[0] == val1 && "Evicted data should match val1");
    std::cout << "  Third write: Eviction occurred, correct data evicted." << std::endl;

    // Check if 0x0 was evicted
    std::fill(read_buf2.begin(), read_buf2.end(), 0);
    cache.read(0x0, read_buf2.data(), &dummy_state, &hit2);
    assert(!hit2 && "First line should have been evicted");

    // Check if 0x1000 and 0x2000 are still there
    std::fill(read_buf2.begin(), read_buf2.end(), 0);
    cache.read(0x1000, read_buf2.data(), &dummy_state, &hit2); assert(hit2 && read_buf2[0] == val2);
    std::fill(read_buf2.begin(), read_buf2.end(), 0);
    cache.read(0x2000, read_buf2.data(), &dummy_state, &hit2); assert(hit2 && read_buf2[0] == val3);
    std::cout << "  Remaining lines verified after eviction." << std::endl;

    printTestStatus("FIFO Replacement", true);
}

// Will Not Work with current implementation, needs to be updated to handle partial writes
void test_partial_write_and_alignment() { 
    std::cout << "Running Test: Partial Write & Alignment..." << std::endl;
    const size_t small_line_size = 16;
    Cache cache2(4, 2, small_line_size); // Small line size for easy testing

    uint64_t addr2 = 0x200;
    uint64_t initial = 0xFFFFFFFFFFFFFFFFULL;
    uint16_t partial = 0x1234;
    std::vector<uint64_t> write_full(small_line_size / sizeof(uint64_t));
    std::vector<uint64_t> write_partial(small_line_size / sizeof(uint64_t));
    std::vector<uint64_t> read_back(small_line_size / sizeof(uint64_t));
    std::vector<uint64_t> wb_back(small_line_size / sizeof(uint64_t));
    write_full.assign(write_full.size(), 0);
    write_full[0] = initial;
    write_partial.assign(write_partial.size(), 0);
    write_partial[0] = partial; // lower bytes set

    CacheState st2;
    bool hit3 = false;
    bool wb_valid3 = false;
    uint64_t wb_addr2 = 0;

    // Write full line
    cache2.write(addr2, MESI_MODIFIED, write_full.data(), small_line_size, wb_back.data(), &wb_addr2, &wb_valid3);
    std::fill(read_back.begin(), read_back.end(), 0);
    cache2.read(addr2, read_back.data(), &st2, &hit3);
    assert(hit3 && read_back[0] == initial);

    // Partial write (overwrite lower 2 bytes)
    cache2.write(addr2, MESI_MODIFIED, write_partial.data(), 2, wb_back.data(), &wb_addr2, &wb_valid3);
    std::fill(read_back.begin(), read_back.end(), 0);
    cache2.read(addr2, read_back.data(), &st2, &hit3);
    assert(hit3);
    uint64_t read_val = read_back[0];
    assert((read_val & 0xFFFF) == partial && "Lower 2 bytes should be updated");
    assert((read_val >> 16) == (initial >> 16) && "Upper bytes should remain unchanged");

    std::cout << "  Partial write and alignment verified." << std::endl;
    printTestStatus("Partial Write & Alignment", true);
}

int main() {
    try {
        test_basic_read_write();
        test_fifo_replacement();
        test_partial_write_and_alignment();
        std::cout << "\nAll tests passed successfully!" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Test failed with error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}