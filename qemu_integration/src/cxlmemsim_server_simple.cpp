#include <iostream>
#include <thread>
#include <vector>
#include <cstring>
#include <cassert>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <chrono>
#include <atomic>
#include <map>
#include <mutex>
#include <algorithm>
#include <random>
#include <csignal>
#include "../include/qemu_cxl_memsim.h"
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string>
#include <cerrno>
#include <cstddef>
#include <cstdbool>

// #include "../include/cache.h"
#include "../include/sf.h"
#define DETAIL_STATS
// Memory entry structure (128 bytes total)
struct CXLMemoryEntry {
    // Data portion (64 bytes)
    uint8_t data[CACHELINE_SIZE];
    
    // Metadata portion (64 bytes)
    struct {
        uint8_t cache_state;        // MESI state
        uint8_t owner_id;           // Current owner host ID
        uint16_t sharers_bitmap;    // Bitmap of hosts sharing this line
        uint32_t access_count;      // Number of accesses
        uint64_t last_access_time;  // Timestamp of last access
        uint64_t virtual_addr;      // Virtual address mapping
        uint64_t physical_addr;     // Physical address
        uint32_t version;           // Version number for coherency
        uint8_t flags;              // Various flags (dirty, locked, etc.)
        uint8_t reserved[23];       // Reserved for future use
    } metadata;
};


class CXLMemSimServer { 
private:
    int server_fd;
    int port;
    std::map<uint64_t, CXLMemoryEntry> memory_storage;
    std::mutex memory_mutex;
    std::atomic<bool> running;

    // Shared memory backing
    int shm_fd = -1;
    void* shm_base = nullptr;
    CXLCoherencyHeader* shm_hdr = nullptr;
    CXLCachelineState* cacheline_states = nullptr;
    uint8_t* data_region = nullptr;
    size_t shm_size = 0;
    size_t num_cachelines = CXL_SHM_MAX_CACHELINES;
    std::string shm_path;
    
    // Virtual to physical address mapping
    std::map<std::pair<uint8_t, uint64_t>, uint64_t> virt_to_phys_map; // <host_id, virt_addr> -> phys_addr
    std::mutex mapping_mutex;
    
    // Track connected clients by host ID for broadcasting invalidations
    std::map<uint8_t, int> host_to_client_fd;
    std::mutex clients_mutex;
    
    // Configurable latency parameters
    double base_read_latency_ns;
    double base_write_latency_ns;
    double base_bisnp_latency_ns; // based on performance recommendations of cxl 3.2 spec (table 13.2)
    double bandwidth_gbps;
    SnoopFilter* sf;

    struct AccessStats {
        uint64_t count;
        uint64_t last_access_time;
    };
    std::map<uint64_t, AccessStats> cacheline_stats;
    std::mutex stats_mutex;

    struct EnhancedRequest : CXLMemSimRequest {
        uint8_t host_id;
        uint64_t virtual_addr;
    };

public:
     // Simple mmap of the entire file into memory; set data_region to base pointer
    bool simple_map_shm(const std::string& path) {
        shm_fd = open(path.c_str(), O_RDWR);
        if (shm_fd < 0) {
            std::cerr << "simple_map_shm: open(" << path << ") failed: " << strerror(errno) << std::endl;
            return false;
        }

        struct stat st;
        if (fstat(shm_fd, &st) < 0) {
            std::cerr << "simple_map_shm: fstat failed: " << strerror(errno) << std::endl;
            close(shm_fd);
            shm_fd = -1;
            return false;
        }

        shm_size = static_cast<size_t>(st.st_size);
        if (shm_size == 0) {
            std::cerr << "simple_map_shm: file has zero size" << std::endl;
            close(shm_fd);
            shm_fd = -1;
            return false;
        }

        shm_base = mmap(nullptr, shm_size, PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
        if (shm_base == MAP_FAILED) {
            std::cerr << "simple_map_shm: mmap failed: " << strerror(errno) << std::endl;
            close(shm_fd);
            shm_fd = -1;
            shm_base = nullptr;
            return false;
        }

        // Expose a simple pointer to the whole region
        data_region = static_cast<uint8_t*>(shm_base);
        return true;
    }

    CXLMemSimServer(int port, const std::string& shm_path_in = DEFAULT_SHARED_MEM_FILE) 
        : port(port), running(true), shm_fd(-1), shm_base(nullptr), shm_hdr(nullptr), cacheline_states(nullptr), data_region(nullptr), shm_size(0), num_cachelines(CXL_SHM_MAX_CACHELINES), shm_path(shm_path_in),
          base_read_latency_ns(200.0),  // CXL typical read latency
          base_write_latency_ns(100.0),  // CXL typical write latency
          base_bisnp_latency_ns(90.0),  // worst case cxl 3.2 bisnp latency (table 13.2)
          bandwidth_gbps(64.0) {         // CXL 2.0 x8 bandwidth
            sf = new SnoopFilter(CXL_SF_SETS, CXL_SF_ASSOC, CACHELINE_SIZE, CXL_SHM_MAX_HOSTS);
            // Use a simple mmap of the provided shared-file (minimal mapping to a pointer)
            if (simple_map_shm(shm_path) == false) {
                std::cerr << "Warning: failed to mmap shared memory file at " << shm_path << "; continuing without shared region" << std::endl;
            }
    }
    
    bool start() {
        server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) {
            std::cerr << "Failed to create socket" << std::endl;
            return false;
        }
        
        int opt = 1;
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            std::cerr << "Failed to set socket options" << std::endl;
            return false;
        }
        
        struct sockaddr_in address;
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port);
        
        if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
            std::cerr << "Failed to bind to port " << port << std::endl;
            return false;
        }
        
        if (listen(server_fd, 10) < 0) {
            std::cerr << "Failed to listen on socket" << std::endl;
            return false;
        }
        
        std::cout << "CXLMemSim server listening on port " << port << std::endl;
        std::cout << "Configuration:" << std::endl;
        std::cout << "  Read Latency: " << base_read_latency_ns << " ns" << std::endl;
        std::cout << "  Write Latency: " << base_write_latency_ns << " ns" << std::endl;
        std::cout << "  BISnp Latency: " << base_bisnp_latency_ns << " ns" << std::endl;
        std::cout << "  Bandwidth: " << bandwidth_gbps << " GB/s" << std::endl;
        std::cout << "  Snoop Filter: " << CXL_SF_SETS << " sets, " << CXL_SF_ASSOC << "-way associative" << std::endl;
        return true;
    }
    
    void handle_client(int client_fd) {
        std::cout << "Client connected" << std::endl;
        
        // Assign or retrieve host ID for this client_fd
        static std::atomic<uint8_t> next_host_id{1};
        uint8_t host_id = 0;
        
        {
            std::lock_guard<std::mutex> lock(clients_mutex);
            // Try to find an existing host_id for this client_fd
            bool found = false;
            for (const auto& kv : host_to_client_fd) {
                if (kv.second == client_fd) {
                    host_id = kv.first;
                    found = true;
                    break;
                }
            }
            if (!found) {
                host_id = next_host_id.fetch_add(1);
                host_to_client_fd[host_id] = client_fd;
            }
        }
    
        
        while (running) {
            // First try to receive enhanced request
            EnhancedRequest req;
            ssize_t received = recv(client_fd, &req, sizeof(CXLMemSimRequest), MSG_WAITALL);
            
            if (received != sizeof(CXLMemSimRequest)) {
                if (received == 0) {
                    std::cout << "Client disconnected (Host " << (int)host_id << ")" << std::endl;
                } else {
                    std::cerr << "Failed to receive request" << std::endl;
                }
                break;
            }
            
            // Set host ID and virtual address if not provided
            req.host_id = host_id;
            req.virtual_addr = req.addr; // Use physical address as virtual if not provided
            
            CXLMemSimResponse resp = {0};
            
            if (req.op_type == CXL_READ_OP) {
                resp.latency_ns = handle_read(req.addr, resp.data, req.size, req.timestamp, req.host_id, req.virtual_addr);
                resp.status = 0;
                
            } else if (req.op_type == CXL_WRITE_OP) {
                resp.latency_ns = handle_write(req.addr, req.data, req.size, req.timestamp, req.host_id, req.virtual_addr);
                resp.status = 0; 
            } else {
                resp.status = 1;
            }
            
            ssize_t sent = send(client_fd, &resp, sizeof(resp), 0);
            if (sent != sizeof(resp)) {
                std::cerr << "Failed to send response" << std::endl;
                break;
            }
            #ifdef DETAIL_STATS
                print_hotness_report();
            #endif
        }
        
        
        // Clean up host mappings on disconnect
        mapping_mutex.lock();
        auto it = virt_to_phys_map.begin();
        while (it != virt_to_phys_map.end()) {
            if (it->first.first == host_id) {
                it = virt_to_phys_map.erase(it);
            } else {
                ++it;
            }
        }
        mapping_mutex.unlock();
        
        // Unregister this client
        {
            std::lock_guard<std::mutex> lock(clients_mutex);
            host_to_client_fd.erase(host_id);
        }
        
        close(client_fd);
    }
    
    uint64_t calculate_latency(size_t size, bool is_read) {
        // Base latency
        double latency = is_read ? base_read_latency_ns : base_write_latency_ns;
        
        // Add bandwidth-based latency
        double transfer_time_ns = (size * 8.0) / (bandwidth_gbps * 1e9) * 1e9;
        latency += transfer_time_ns;
        
        // Add some variance based on queue depth (simplified)
        static thread_local std::mt19937 gen(std::random_device{}());
        std::uniform_real_distribution<> dis(0.9, 1.1);
        latency *= dis(gen);
        
        return static_cast<uint64_t>(latency);
    }

   
    
    // Enhanced request structure to handle host ID
   
    
    void broadcast_back_invalidate(uint64_t bi_addr, uint8_t requester_id, BISnpReqType bisnp_req_opcode, uint64_t bisnp_mask, bool invalidate_all) {
        for (size_t host = 1; host < CXL_SHM_MAX_HOSTS; host++) {
            if (host == requester_id && !invalidate_all) continue;
            if (((1ULL << host) & bisnp_mask) == 0) continue;

            std::lock_guard<std::mutex> lock(clients_mutex);
            auto it = host_to_client_fd.find(host);
            if (it != host_to_client_fd.end()) {
                int target_fd = it->second;
                CXLMemSimResponse resp = {0};
                resp.status = 0;
                resp.bisnp_req = bisnp_req_opcode;
                resp.addr = bi_addr;

                ssize_t sent = send(target_fd, &resp, sizeof(resp), MSG_NOSIGNAL);
                if (sent != sizeof(resp)) {
                    std::cerr << "Failed to send back-invalidation to host " << (int)host << std::endl;
                    continue;
                } else {
                    std::cout << "Sent back-invalidation to host " << (int)host 
                              << " for addr 0x" << std::hex << bi_addr 
                              << std::dec << std::endl;
                }
                // Receive a Response from the host to confirm invalidation
                CXLMemSimRequest host_resp = {0};
                ssize_t recvd = recv(target_fd, &host_resp, sizeof(host_resp), MSG_WAITALL);
                if (recvd != sizeof(host_resp)) {
                    std::cerr << "Failed to receive response from host " << (int)host << std::endl;
                    continue;
                }
                #ifdef STANDALONE_TEST
                if (host_resp.bisnp_resp == BISnpI) {
                    // Write Data Back to Shared Memory
                    // Write the full cacheline returned by the host back into the shared memory region
                    size_t offset = bi_addr & ~(CACHELINE_SIZE - 1);
                    assert (offset + CACHELINE_SIZE <= shm_size && "Shared memory write out of bounds");
                        std::lock_guard<std::mutex> lock(memory_mutex);
                        memcpy(static_cast<uint8_t*>(shm_base) + offset, host_resp.data, CACHELINE_SIZE);
                    // Sync memory pages to ensure visibility to other processes
                        if (msync(static_cast<uint8_t*>(shm_base) + offset, CACHELINE_SIZE, MS_SYNC) != 0) {
                        std::cerr << "msync failed: " << strerror(errno) << std::endl;
                    }
                }
                #endif            
            }
        }
    }

    CacheState handle_coherency_transition(uint64_t addr, CacheState old_state, uint64_t bitmask, uint8_t requester_id, bool is_write, uint8_t* inv_issued) {
        uint64_t inv_mask = 0;
        uint64_t inv_addr = 0; 
        bool inv_valid = false;
        if (is_write) {
            switch (old_state) {
                case MESI_INVALID: {
                    sf->write(addr, MESI_EXCLUSIVE, bitmask | (1 << requester_id), &inv_mask, &inv_addr, &inv_valid);
                    if (inv_valid) {
                        // Handle back-invalidation response if needed
                        broadcast_back_invalidate(inv_addr, requester_id, BISnpInv, inv_mask, true);
                        *inv_issued = 1;
                    }
                    return MESI_EXCLUSIVE;
                }
                case MESI_SHARED:{
                        broadcast_back_invalidate(addr, requester_id, BISnpInv, bitmask, true);
                        if (inv_issued) *inv_issued = 1;
                        return MESI_EXCLUSIVE;
                }
                case MESI_EXCLUSIVE: {
                    if((1 << requester_id) != bitmask) {
                        broadcast_back_invalidate(addr, requester_id, BISnpInv, bitmask, true);
                        *inv_issued = 1;
                    }
                    return MESI_EXCLUSIVE;
                }
            }
        } else {
            switch (old_state) {
                case MESI_INVALID: {
                    sf->write(addr, MESI_SHARED, bitmask | (1 << requester_id), &inv_mask, &inv_addr, &inv_valid);
                    if (inv_valid) {
                        // Handle back-invalidation response if needed
                        broadcast_back_invalidate(inv_addr, requester_id, BISnpInv, inv_mask, true);
                        *inv_issued = 1;
                    }
                    return MESI_EXCLUSIVE;
                }
                case MESI_SHARED: {
                    sf->write(addr, MESI_SHARED, bitmask | (1 << requester_id), &inv_mask, &inv_addr, &inv_valid);
                    assert(inv_valid == false && "No Invalidation Should Be Issued[S->S]"); // Should not need to invalidate for shared read
                    return MESI_SHARED;
                }
                case MESI_EXCLUSIVE: {
                    sf->write(addr, MESI_SHARED, bitmask | (1 << requester_id), &inv_mask, &inv_addr, &inv_valid);
                    assert(inv_valid == false && "No Invalidation Should Be Issued [E->S]"); // Should not need to invalidate for shared read
                    broadcast_back_invalidate(addr, requester_id, BISnpData, bitmask, false);
                    *inv_issued = 1;
                    return MESI_SHARED;
                }
                default: {
                    std::cout << "Unexpected MESI state: " << (int)old_state << std::endl;
                    break;
                }
            }
        }
        return MESI_INVALID;
    }

    uint64_t broadcast_back_invalidation(uint64_t bi_addr, uint64_t* bi_mask) {
        // Minimal helper: if a mask pointer is provided return its value, otherwise return 0.
        if (bi_mask == nullptr) return 0;
        return *bi_mask;
    }
    
    
    

    uint64_t handle_read(uint64_t addr, uint8_t* data, size_t size, uint64_t timestamp, uint8_t host_id = 0, uint64_t virt_addr = 0) {
        uint64_t   line_bitmask;
        bool hit;
        CacheState line_mesi_state;
        
        uint8_t bi_issued = 0;

        update_cacheline_stats(addr);
        
        memory_mutex.lock();
        
        sf->read(addr, &line_bitmask, &line_mesi_state, &hit);
   
        // // Update virtual to physical mapping
        // if (virt_addr != 0) {
        //     mapping_mutex.lock();
        //     virt_to_phys_map[{host_id, virt_addr}] = addr;
        //     entry.metadata.virtual_addr = virt_addr;
        //     mapping_mutex.unlock();
        // }
        CacheState old_state = static_cast<CacheState>(line_mesi_state);
        // Handle coherency state transition
        CacheState new_state = handle_coherency_transition(addr, old_state, line_bitmask, host_id, false, &bi_issued);
        
        // Copy data
       // memcpy(data, entry.data, std::min(size, (size_t)CACHELINE_SIZE));
        #ifdef STANDALONE_TEST
        // For standalone testing, read directly from the shared memory region
        size_t offset = addr & ~(CACHELINE_SIZE - 1);
        assert (offset + CACHELINE_SIZE <= shm_size && "Shared memory read out of bounds");
        memcpy(data, static_cast<uint8_t*>(shm_base) + offset, std::min(size, (size_t)CACHELINE_SIZE));
        #endif

        memory_mutex.unlock();
        
        // Add latency based on state transition
        uint64_t base_latency = calculate_latency(size, true);
        if (bi_issued) {
            base_latency += base_bisnp_latency_ns; // Additional latency for BISnp response
        }
        

        
        
        return base_latency;
    }
    
    uint64_t handle_write(uint64_t addr, const uint8_t* data, size_t size, uint64_t timestamp, uint8_t host_id = 0, uint64_t virt_addr = 0) {
        update_cacheline_stats(addr);
        uint64_t   line_bitmask;
        bool hit;
        CacheState line_mesi_state;
        uint8_t bi_issued = 0;
        
        sf->read(addr, &line_bitmask, &line_mesi_state, &hit);
        // Handle coherency state transition
        CacheState old_state = static_cast<CacheState>(line_mesi_state); 
        CacheState new_state = handle_coherency_transition(addr, old_state, line_bitmask, host_id, true, &bi_issued);

        #ifdef STANDALONE_TEST
        // For standalone testing, write directly into the shared memory region
        size_t offset = addr & ~(CACHELINE_SIZE - 1);
        assert (offset + CACHELINE_SIZE <= shm_size && "Shared memory write out of bounds");
        {
            std::lock_guard<std::mutex> lock(memory_mutex);
            memcpy(static_cast<uint8_t*>(shm_base) + offset, data, std::min(size, (size_t)CACHELINE_SIZE));
        }
        #endif  
        
        // Add latency based on state transition
        uint64_t base_latency = calculate_latency(size, false);
        if (bi_issued) {
            base_latency += base_bisnp_latency_ns; // Additional latency for BISnp response
        }
        
        return base_latency;
    }
    
    void update_cacheline_stats(uint64_t addr) {
        uint64_t cacheline_addr = addr & ~(CACHELINE_SIZE - 1);
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        
        std::lock_guard<std::mutex> lock(stats_mutex);
        auto& stats = cacheline_stats[cacheline_addr];
        stats.count++;
        stats.last_access_time = now;
    }
    
    void run() {
        while (running) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            
            int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
            if (client_fd < 0) {
                if (running) {
                    std::cerr << "Failed to accept connection" << std::endl;
                }
                continue;
            }
            
            std::thread client_thread(&CXLMemSimServer::handle_client, this, client_fd);
            client_thread.detach();
        }
    }
    
    void stop() {
        running = false;
        close(server_fd);
        // Cleanup shared memory mapping
        if (shm_base && shm_size) {
            munmap(shm_base, shm_size);
            shm_base = nullptr;
        }
        if (shm_fd >= 0) {
            close(shm_fd);
            shm_fd = -1;
        }
    }
    
    void print_hotness_report() {
        std::lock_guard<std::mutex> lock(stats_mutex);
        std::cout << "\n=== Cacheline Hotness & Coherency Report ===" << std::endl;
        
        std::vector<std::pair<uint64_t, AccessStats>> sorted_stats;
        for (const auto& entry : cacheline_stats) {
            sorted_stats.push_back(entry);
        }
        
        std::sort(sorted_stats.begin(), sorted_stats.end(),
            [](const auto& a, const auto& b) {
                return a.second.count > b.second.count;
            });
        
        std::cout << "Top 20 Hottest Cachelines:" << std::endl;
        size_t count = 0;
        
        for (const auto& entry : sorted_stats) {
            if (count++ >= 20) break;
            
            uint64_t mask;
            CacheState state;
            bool hit;
            sf->read(entry.first, &mask, &state, &hit);
            
            if (hit) {
                const char* state_str = "INVALID";
                switch (state) {
                    case MESI_SHARED: state_str = "SHARED"; break;
                    case MESI_EXCLUSIVE: state_str = "EXCLUSIVE"; break;
                    case MESI_MODIFIED: state_str = "MODIFIED"; break;
                }
                
                std::cout << "  Address: 0x" << std::hex << entry.first 
                         << " - Accesses: " << std::dec << entry.second.count 
                         << " - State: " << state_str
                         << " - Sharers Mask: 0x" << std::hex << mask << std::endl;
            } else {
                std::cout << "  Address: 0x" << std::hex << entry.first 
                         << " - Accesses: " << std::dec << entry.second.count 
                         << " - Not in Snoop Filter" << std::endl;
            }
        }
        
        std::cout << "\nCoherency Statistics from Snoop Filter:" << std::endl;
        int state_counts[4] = {0};
        for (uint32_t set_idx = 0; set_idx < sf->num_sets; ++set_idx) {
            for (uint32_t way = 0; way < sf->assoc; ++way) {
                const auto& entry = sf->sets[set_idx].entries[way];
                if (entry.mesi_state != MESI_INVALID) {
                    if (entry.mesi_state < 4) {
                        state_counts[entry.mesi_state]++;
                    }
                }
            }
        }
        
        std::cout << "  INVALID: " << state_counts[MESI_INVALID] << std::endl;
        std::cout << "  SHARED: " << state_counts[MESI_SHARED] << std::endl;
        std::cout << "  EXCLUSIVE: " << state_counts[MESI_EXCLUSIVE] << std::endl;
        std::cout << "  MODIFIED: " << state_counts[MESI_MODIFIED] << std::endl;
        
        std::cout << "\nTotal unique cachelines accessed: " << cacheline_stats.size() << std::endl;
        
        // Calculate total accesses
        uint64_t total_accesses = 0;
        for (const auto& entry : cacheline_stats) {
            total_accesses += entry.second.count;
        }
        std::cout << "Total cacheline accesses: " << total_accesses << std::endl;
        
        // Virtual to Physical mapping statistics
        mapping_mutex.lock();
        std::cout << "\nVirtual to Physical Mappings: " << virt_to_phys_map.size() << " entries" << std::endl;
        mapping_mutex.unlock();
    }
};

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <port> [shm_path]" << std::endl;
        return 1;
    }
        
    
    int port = std::atoi(argv[1]);
    std::string shm_path = (argc >= 3) ? argv[2] : DEFAULT_SHARED_MEM_FILE;
    
    CXLMemSimServer server(port, shm_path);

    // Setup signal handler for graceful shutdown
    std::signal(SIGINT, [](int) {
        std::cout << "\nShutting down server..." << std::endl;
        exit(0);
    });
    
    if (!server.start()) {
        return 1;
    }
    
    // Start periodic reporting thread
    std::thread report_thread([&server]() {
        while (true) {
            std::this_thread::sleep_for(std::chrono::seconds(30));
            server.print_hotness_report();
        }
    });
    report_thread.detach();
    
    server.run();
    
    return 0;
}