#include <iostream>
#include <thread>
#include <vector>
#include <cstring>
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
#define DETAIL_STATS
// Cache coherency states (MESI protocol)
// enum CacheState {
//     MESI_INVALID = 0,
//     MESI_SHARED = 1,
//     MESI_EXCLUSIVE = 2,
//     MESI_MODIFIED = 3
// };

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
    
    struct AccessStats {
        uint64_t count;
        uint64_t last_access_time;
    };
    std::map<uint64_t, AccessStats> cacheline_stats;
    std::mutex stats_mutex;

public:
    CXLMemSimServer(int port) 
        : port(port), running(true),
          base_read_latency_ns(200.0),  // CXL typical read latency
          base_write_latency_ns(100.0),  // CXL typical write latency
          base_bisnp_latency_ns(90.0),  // worst case cxl 3.2 bisnp latency (table 13.2)
          bandwidth_gbps(64.0) {         // CXL 2.0 x8 bandwidth
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
                
                // Get current cache state for response
                memory_mutex.lock();
                auto& entry = memory_storage[req.addr];
                resp.data[CACHELINE_SIZE - 1] = entry.metadata.cache_state; // Store cache state in last byte
                memory_mutex.unlock();
                
            } else if (req.op_type == CXL_WRITE_OP) {
                resp.latency_ns = handle_write(req.addr, req.data, req.size, req.timestamp, req.host_id, req.virtual_addr);
                resp.status = 0;
                
                // Get current cache state for response
                memory_mutex.lock();
                auto& entry = memory_storage[req.addr];
                resp.data[CACHELINE_SIZE - 1] = entry.metadata.cache_state; // Store cache state in last byte
                memory_mutex.unlock();
                
            } else {
                resp.status = 1;
            }
            // printf("[DEBUG] Dumping response fields for debugging:\n");
            // printf("  Status: %d\n", resp.status);
            // printf("  Latency: %lu ns\n", resp.latency_ns);
            // printf("  Address: 0x%lx\n", resp.addr); 
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
    struct EnhancedRequest : CXLMemSimRequest {
        uint8_t host_id;
        uint64_t virtual_addr;
    };
    
    // Broadcast back-invalidation to all sharers except the requester
    void broadcast_back_invalidation(CXLMemoryEntry& entry, uint8_t requester_id, BISnpReqType bisnp_req_opcode) {
        CXLMemSimResponse resp = {0};
        resp.status = 0;
        resp.bisnp_req = bisnp_req_opcode;
        resp.addr = entry.metadata.physical_addr;

        std::lock_guard<std::mutex> lock(clients_mutex);

        // Iterate through all potential sharers (up to 16 hosts in bitmap)
        uint16_t sharers = entry.metadata.sharers_bitmap;
        for (uint8_t host_id = 0; host_id < 16 && sharers != 0; host_id++) {
            if ((sharers & (1 << host_id)) && host_id != requester_id) {
                // Find the client socket for this host
                auto it = host_to_client_fd.find(host_id);
                if (it != host_to_client_fd.end()) {
                    int target_fd = it->second;
                    ssize_t sent = send(target_fd, &resp, sizeof(resp), MSG_NOSIGNAL);
                    if (sent != sizeof(resp)) {
                        std::cerr << "Failed to send invalidation to host " << (int)host_id << std::endl;
                        continue;
                    } else {
                        std::cout << "Sent back-invalidation to host " << (int)host_id 
                                  << " for addr 0x" << std::hex << entry.metadata.physical_addr 
                                  << std::dec << std::endl;
                    }

                    // Wait for response from the host
                        CXLMemSimRequest host_resp = {0};
                        ssize_t recvd = recv(target_fd, &host_resp, sizeof(host_resp), MSG_WAITALL);
                        if (recvd != sizeof(host_resp)) {
                            std::cerr << "Failed to receive response from host " << (int)host_id << std::endl;
                            continue;
                        }

                        // Validate BISnp response type according to request
                        bool valid = false;
                        switch (bisnp_req_opcode) {
                            case BISnpCurr:
                                // Can get BISnpE, BISnpS, BISnpI
                                valid = (host_resp.bisnp_resp == BISnpE || host_resp.bisnp_resp == BISnpS || host_resp.bisnp_resp == BISnpI);
                                break;
                            case BISnpData:
                                // Can get BISnpI or BISnpS
                                valid = (host_resp.bisnp_resp == BISnpI || host_resp.bisnp_resp == BISnpS);
                                break;
                            case BISnpInv:
                                // Can only get BISnpI
                                valid = (host_resp.bisnp_resp == BISnpI);
                                break;
                            default:
                                valid = false;
                        }
                        if (!valid) {
                            std::cerr << "Warning: Unexpected BISnp response " << (int)host_resp.bisnp_resp
                                      << " from host " << (int)host_id << " for opcode " << (int)bisnp_req_opcode << std::endl;
                        }

                        // If the host has modified data, write it back to shared memory (if it is shared or exclusive that usually means the data is not modified)
                        if (host_resp.bisnp_resp == BISnpI) {
                            std::cout << "Host " << (int)host_id << " provided modified data for addr 0x"
                                      << std::hex << entry.metadata.physical_addr << std::dec << ". Writing back." << std::endl;
                            memory_mutex.lock();
                            memcpy(entry.data, host_resp.data, CACHELINE_SIZE);
                            memory_mutex.unlock();
                        } else {
                            std::cout << "Host " << (int)host_id << " acknowledged invalidation for addr 0x"
                                      << std::hex << entry.metadata.physical_addr << std::dec << std::endl;
                        }
                }
            }
        }
    }

    CacheState handle_coherency_transition(CXLMemoryEntry& entry, uint8_t requester_id, bool is_write) {
        CacheState old_state = static_cast<CacheState>(entry.metadata.cache_state);
        CacheState new_state = old_state;
        
        if (is_write) {
            // Write request handling - need to invalidate all other sharers
            switch (old_state) {
                case MESI_INVALID:
                    new_state = MESI_MODIFIED;
                    entry.metadata.owner_id = requester_id;
                    entry.metadata.sharers_bitmap = (1 << requester_id);
                    break;
                case MESI_SHARED:
                    // Broadcast invalidation to all sharers before taking ownership
                    broadcast_back_invalidation(entry, requester_id, BISnpInv);
                    new_state = MESI_MODIFIED;
                    entry.metadata.owner_id = requester_id;
                    entry.metadata.sharers_bitmap = (1 << requester_id);
                    break;
                case MESI_EXCLUSIVE:
                    if (entry.metadata.owner_id != requester_id) {
                        // Invalidate current exclusive owner
                        broadcast_back_invalidation(entry, requester_id, BISnpInv);
                    }
                    new_state = MESI_MODIFIED;
                    entry.metadata.owner_id = requester_id;
                    entry.metadata.sharers_bitmap = (1 << requester_id);
                    break;
                case MESI_MODIFIED:
                    if (entry.metadata.owner_id != requester_id) {
                        // Need to invalidate current owner and get data
                        broadcast_back_invalidation(entry, requester_id, BISnpInv);
                        new_state = MESI_MODIFIED;
                        entry.metadata.owner_id = requester_id;
                        entry.metadata.sharers_bitmap = (1 << requester_id);
                    }
                    break;
            }
        } else {
            // Read request handling
            switch (old_state) {
                case MESI_INVALID:
                    new_state = MESI_EXCLUSIVE;
                    entry.metadata.owner_id = requester_id;
                    entry.metadata.sharers_bitmap = (1 << requester_id);
                    break;
                case MESI_EXCLUSIVE:
                    if (entry.metadata.owner_id != requester_id) {
                        // Downgrade exclusive owner to shared
                        broadcast_back_invalidation(entry, requester_id, BISnpData);
                        new_state = MESI_SHARED;
                        entry.metadata.sharers_bitmap |= (1 << requester_id);
                        entry.metadata.owner_id = 0; // No single owner in shared state
                    }
                    break;
                case MESI_SHARED:
                    entry.metadata.sharers_bitmap |= (1 << requester_id);
                    entry.metadata.owner_id = 0; // No single owner in shared state
                    break;
                case MESI_MODIFIED:
                    if (entry.metadata.owner_id != requester_id) {
                        // Get data from modified owner and transition to shared
                        broadcast_back_invalidation(entry, requester_id, BISnpData);
                        new_state = MESI_SHARED;
                        entry.metadata.sharers_bitmap |= (1 << requester_id);
                        entry.metadata.owner_id = 0; // No single owner in shared state
                    }
                    break;
            }
        }
        
        entry.metadata.cache_state = new_state;
        entry.metadata.version++;
        return new_state;
    }
    
    uint64_t handle_read(uint64_t addr, uint8_t* data, size_t size, uint64_t timestamp, uint8_t host_id = 0, uint64_t virt_addr = 0) {
        update_cacheline_stats(addr);
        
        memory_mutex.lock();
        auto& entry = memory_storage[addr];
        
        // Initialize entry if new
        if (entry.metadata.physical_addr == 0) {
            entry.metadata.physical_addr = addr;
            entry.metadata.cache_state = MESI_INVALID;
            memset(entry.data, 0, CACHELINE_SIZE);
        }
        
        // Update virtual to physical mapping
        if (virt_addr != 0) {
            mapping_mutex.lock();
            virt_to_phys_map[{host_id, virt_addr}] = addr;
            entry.metadata.virtual_addr = virt_addr;
            mapping_mutex.unlock();
        }
        CacheState old_state = static_cast<CacheState>(entry.metadata.cache_state);
        // Handle coherency state transition
        CacheState new_state = handle_coherency_transition(entry, host_id, false);
        
        // Copy data
        memcpy(data, entry.data, std::min(size, (size_t)CACHELINE_SIZE));
        
        // Update metadata
        entry.metadata.access_count++;
        entry.metadata.last_access_time = timestamp;
        
        memory_mutex.unlock();
        
        // Add latency based on state transition
        uint64_t base_latency = calculate_latency(size, true);
        if (old_state != MESI_INVALID || (old_state == MESI_SHARED && new_state == MESI_SHARED)) {
            base_latency += base_bisnp_latency_ns; // Additional latency for BISnp response
        }
        // if (new_state == MESI_SHARED && (old_state == MESI_MODIFIED)) {
        //     base_latency += base_bisnp_latency_ns; // Additional latency for writeback
        // }

        
        
        return base_latency;
    }
    
    uint64_t handle_write(uint64_t addr, const uint8_t* data, size_t size, uint64_t timestamp, uint8_t host_id = 0, uint64_t virt_addr = 0) {
        update_cacheline_stats(addr);
        
        memory_mutex.lock();
        auto& entry = memory_storage[addr];
        
        // Initialize entry if new
        if (entry.metadata.physical_addr == 0) {
            entry.metadata.physical_addr = addr;
            entry.metadata.cache_state = MESI_INVALID;
        }
        
        // Update virtual to physical mapping
        if (virt_addr != 0) {
            mapping_mutex.lock();
            virt_to_phys_map[{host_id, virt_addr}] = addr;
            entry.metadata.virtual_addr = virt_addr;
            mapping_mutex.unlock();
        }
        
        // Handle coherency state transition
        CacheState old_state = static_cast<CacheState>(entry.metadata.cache_state);
        CacheState new_state = handle_coherency_transition(entry, host_id, true);
        
        // Copy data
        memcpy(entry.data, data, std::min(size, (size_t)CACHELINE_SIZE));
        
        // Update metadata
        entry.metadata.access_count++;
        entry.metadata.last_access_time = timestamp;
        
        memory_mutex.unlock();
        
        // Add latency based on state transition
        uint64_t base_latency = calculate_latency(size, false);
        // if (old_state == MESI_SHARED || (old_state == MESI_MODIFIED && entry.metadata.owner_id != host_id)) {
        //     base_latency += 100; // Additional latency for invalidation
        // }

        if (old_state != MESI_INVALID || (old_state == MESI_SHARED && new_state == MESI_SHARED)) {
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
        
        memory_mutex.lock();
        for (const auto& entry : sorted_stats) {
            if (count++ >= 20) break;
            
            auto mem_it = memory_storage.find(entry.first);
            if (mem_it != memory_storage.end()) {
                const auto& mem_entry = mem_it->second;
                const char* state_str = "INVALID";
                switch (mem_entry.metadata.cache_state) {
                    case MESI_SHARED: state_str = "SHARED"; break;
                    case MESI_EXCLUSIVE: state_str = "EXCLUSIVE"; break;
                    case MESI_MODIFIED: state_str = "MODIFIED"; break;
                }
                
                std::cout << "  Address: 0x" << std::hex << entry.first 
                         << " - Accesses: " << std::dec << entry.second.count 
                         << " - State: " << state_str
                         << " - Owner: Host" << (int)mem_entry.metadata.owner_id
                         << " - Sharers: 0x" << std::hex << mem_entry.metadata.sharers_bitmap
                         << " - Version: " << std::dec << mem_entry.metadata.version << std::endl;
            } else {
                std::cout << "  Address: 0x" << std::hex << entry.first 
                         << " - Accesses: " << std::dec << entry.second.count << std::endl;
            }
        }
        memory_mutex.unlock();
        
        std::cout << "\nCoherency Statistics:" << std::endl;
        int state_counts[4] = {0};
        memory_mutex.lock();
        for (const auto& entry : memory_storage) {
            if (entry.second.metadata.cache_state < 4) {
                state_counts[entry.second.metadata.cache_state]++;
            }
        }
        memory_mutex.unlock();
        
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
        std::cerr << "Usage: " << argv[0] << " <port>" << std::endl;
        return 1;
    }
    
    int port = std::atoi(argv[1]);
    
    CXLMemSimServer server(port);
    
    if (!server.start()) {
        return 1;
    }
    
    // Setup signal handler for graceful shutdown
    std::signal(SIGINT, [](int) {
        std::cout << "\nShutting down server..." << std::endl;
        exit(0);
    });
    
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