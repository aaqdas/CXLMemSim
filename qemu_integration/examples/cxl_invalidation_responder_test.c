/*
 * CXL Invalidation Monitor
 * 
 * This program runs inside a QEMU VM and uses libCXLMemSim.so to:
 * 1. Connect to the CXLMemSim server
 * 2. Read/write memory locations
 * 3. Monitor for back-invalidation (BISnp) requests from the server
 *
 * Usage: ./cxl_invalidation_monitor <server_ip> <port> [address]
 * Example: ./cxl_invalidation_monitor 10.0.2.2 10000 0x1000
 *
 * Compile: gcc -o cxl_invalidation_monitor cxl_invalidation_monitor.c -L../build -lCXLMemSim -lpthread
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <stdatomic.h>
#include <stdbool.h>

#define CACHELINE_SIZE 64
#define BISnpOpCode 0x80

/* Protocol structures (matching server) */
enum BISnpReqType {
    BISnpCurr = 0,
    BISnpData = 1,
    BISnpInv  = 2
};

enum BISnpRespType {
    BISnpI = 0,
    BISnpS = 1,
    BISnpE = 2
};

typedef struct {
    uint8_t op_type;
    uint64_t addr;
    uint64_t size;
    uint64_t timestamp;
    enum BISnpRespType bisnp_resp;
    uint8_t data[CACHELINE_SIZE];
} CXLMemSimRequest;

typedef struct {
    uint8_t status;
    uint64_t latency_ns;
    uint64_t addr;
    enum BISnpReqType bisnp_req;
    uint8_t data[CACHELINE_SIZE];
} CXLMemSimResponse;

#define CXL_READ_OP  0
#define CXL_WRITE_OP 1

/* Global state */
static int g_socket_fd = -1;
static atomic_bool g_running = true;
static atomic_uint_fast64_t g_invalidations_received = 0;
static pthread_mutex_t g_socket_lock = PTHREAD_MUTEX_INITIALIZER;

/* Statistics */
static struct {
    uint64_t reads;
    uint64_t writes;
    uint64_t bisnp_curr;
    uint64_t bisnp_data;
    uint64_t bisnp_inv;
} g_stats = {0};

static uint64_t get_timestamp_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static const char* bisnp_type_to_string(enum BISnpReqType type) {
    switch (type) {
        case BISnpCurr: return "BISnpCurr (request current copy)";
        case BISnpData: return "BISnpData (request shared/exclusive)";
        case BISnpInv:  return "BISnpInv (invalidate)";
        default:        return "Unknown";
    }
}

/* Connect to CXLMemSim server */
static int connect_to_server(const char *host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    /* Set socket to non-blocking for invalidation monitoring */
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 100000;  /* 100ms timeout for reads */
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    return sock;
}

/* Handle incoming back-invalidation request */
static void handle_invalidation(CXLMemSimResponse *resp) {
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║ 🔔 BACK-INVALIDATION RECEIVED                                 ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Type:    %s\n", bisnp_type_to_string(resp->bisnp_req));
    printf("║ Address: 0x%016lx\n", resp->addr);
    printf("║ Time:    %lu\n", get_timestamp_ns());
    
    /* Print first 16 bytes of data if present */
    printf("║ Data:    ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", resp->data[i]);
    }
    printf("...\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    /* Update statistics */
    switch (resp->bisnp_req) {
        case BISnpCurr: g_stats.bisnp_curr++; break;
        case BISnpData: g_stats.bisnp_data++; break;
        case BISnpInv:  g_stats.bisnp_inv++; break;
    }
    atomic_fetch_add(&g_invalidations_received, 1);

    // Simulate updating the local MESI state
    printf("[MESI] Updating local MESI state for address 0x%016lx\n", resp->addr);

    // If BISnpData, send back a response with data
    if (resp->bisnp_req == BISnpData) {
        CXLMemSimRequest response = {0};
        response.op_type = BISnpOpCode; // Custom op for BISnpData response (not standard)
        response.addr = resp->addr;
        response.size = CACHELINE_SIZE;
        response.timestamp = get_timestamp_ns();
        response.bisnp_resp = BISnpS; // Example response type (Shared)
        // Fill with dummy data (in real code, would send actual cacheline)
        memset(response.data, 0xAB, CACHELINE_SIZE);
        pthread_mutex_lock(&g_socket_lock);
        send(g_socket_fd, &response, sizeof(response), 0);
        pthread_mutex_unlock(&g_socket_lock);
        printf("[MESI] Sent back response with data for address 0x%016lx\n", resp->addr);
    }
}

/* Send a read request and wait for response */
static int cxl_read(uint64_t addr, uint8_t *data, size_t size) {
    CXLMemSimRequest req = {0};
    CXLMemSimResponse resp = {0};

    req.op_type = CXL_READ_OP;
    req.addr = addr;
    req.size = size;
    req.timestamp = get_timestamp_ns();

    pthread_mutex_lock(&g_socket_lock);

    if (send(g_socket_fd, &req, sizeof(req), 0) != sizeof(req)) {
        perror("send read request");
        pthread_mutex_unlock(&g_socket_lock);
        return -1;
    }

    if (recv(g_socket_fd, &resp, sizeof(resp), MSG_WAITALL) != sizeof(resp)) {
        perror("recv read response");
        pthread_mutex_unlock(&g_socket_lock);
        return -1;
    }

    pthread_mutex_unlock(&g_socket_lock);

    /* Check if this response contains a back-invalidation */
    if (resp.bisnp_req != 0) {
        handle_invalidation(&resp);
    }

    if (resp.status == 0) {
        memcpy(data, resp.data, size < CACHELINE_SIZE ? size : CACHELINE_SIZE);
        g_stats.reads++;
        return 0;
    }

    return -1;
}

/* Send a write request and wait for response */
static int cxl_write(uint64_t addr, const uint8_t *data, size_t size) {
    CXLMemSimRequest req = {0};
    CXLMemSimResponse resp = {0};

    req.op_type = CXL_WRITE_OP;
    req.addr = addr;
    req.size = size;
    req.timestamp = get_timestamp_ns();
    memcpy(req.data, data, size < CACHELINE_SIZE ? size : CACHELINE_SIZE);

    pthread_mutex_lock(&g_socket_lock);

    if (send(g_socket_fd, &req, sizeof(req), 0) != sizeof(req)) {
        perror("send write request");
        pthread_mutex_unlock(&g_socket_lock);
        return -1;
    }

    if (recv(g_socket_fd, &resp, sizeof(resp), MSG_WAITALL) != sizeof(resp)) {
        perror("recv write response");
        pthread_mutex_unlock(&g_socket_lock);
        return -1;
    }

    pthread_mutex_unlock(&g_socket_lock);

    /* Check if this response contains a back-invalidation */
    if (resp.bisnp_req != 0) {
        handle_invalidation(&resp);
    }

    if (resp.status == 0) {
        g_stats.writes++;
        return 0;
    }

    return -1;
}

/* Background thread to monitor for asynchronous invalidations */
static void *invalidation_monitor_thread(void *arg) {
    (void)arg;
    CXLMemSimResponse resp;

    printf("[Monitor] Invalidation monitor thread started\n");

    while (g_running) {
        /* Try to receive any pending invalidation messages */
        pthread_mutex_lock(&g_socket_lock);
        
        /* Use MSG_DONTWAIT to check without blocking */
        ssize_t received = recv(g_socket_fd, &resp, sizeof(resp), MSG_DONTWAIT);
        
        pthread_mutex_unlock(&g_socket_lock);

        if (received == sizeof(resp)) {
            /* Got a message - check if it's an invalidation */
            if (resp.bisnp_req != 0) {
                handle_invalidation(&resp);
            }
        } else if (received < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
            /* Real error */
            if (g_running) {
                perror("[Monitor] recv error");
            }
            break;
        }

        /* Small sleep to avoid busy-waiting */
        usleep(10000);  /* 10ms */
    }

    printf("[Monitor] Invalidation monitor thread exiting\n");
    return NULL;
}

static void signal_handler(int sig) {
    (void)sig;
    printf("\nShutting down...\n");
    g_running = false;
    fflush(stdout);
    exit(0);
}

static void print_stats(void) {
    printf("\n═══════════════════════════════════════════════════════════════\n");
    printf("                    SESSION STATISTICS                          \n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("  Total Reads:              %lu\n", g_stats.reads);
    printf("  Total Writes:             %lu\n", g_stats.writes);
    printf("  BISnpCurr Received:       %lu\n", g_stats.bisnp_curr);
    printf("  BISnpData Received:       %lu\n", g_stats.bisnp_data);
    printf("  BISnpInv Received:        %lu\n", g_stats.bisnp_inv);
    printf("  Total Invalidations:      %lu\n", 
           g_stats.bisnp_curr + g_stats.bisnp_data + g_stats.bisnp_inv);
    printf("═══════════════════════════════════════════════════════════════\n");
}

static void interactive_menu(uint64_t base_addr) {
    char input[256];
    uint64_t addr = base_addr;

    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║           CXL MEMORY ACCESS - INTERACTIVE MODE               ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Commands:                                                    ║\n");
    printf("║   r [addr]    - Read from address (default: 0x%lx)\n", base_addr);
    printf("║   w [addr] <val> - Write value to address                    ║\n");
    printf("║   m           - Monitor mode (just watch invalidations)      ║\n");
    printf("║   s           - Show statistics                              ║\n");
    printf("║   q           - Quit                                         ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    while (g_running) {
        printf("cxl> ");
        fflush(stdout);

        if (fgets(input, sizeof(input), stdin) == NULL) {
            break;
        }

        /* Remove newline */
        input[strcspn(input, "\n")] = 0;

        if (strlen(input) == 0) {
            continue;
        }

        char cmd = input[0];
        
        switch (cmd) {
            case 'r': case 'R': {
                /* Read command */
                uint64_t read_addr = addr;
                if (strlen(input) > 2) {
                    read_addr = strtoull(input + 2, NULL, 0);
                    addr = read_addr;
                }
                
                uint8_t data[CACHELINE_SIZE] = {0};
                printf("Reading from 0x%lx...\n", read_addr);
                
                CXLMemSimRequest req = {0};
                CXLMemSimResponse resp = {0};
                req.op_type = CXL_READ_OP;
                req.addr = read_addr;
                req.size = CACHELINE_SIZE;
                req.timestamp = get_timestamp_ns();
                pthread_mutex_lock(&g_socket_lock);
                int send_ok = (send(g_socket_fd, &req, sizeof(req), 0) == sizeof(req));
                int recv_ok = (recv(g_socket_fd, &resp, sizeof(resp), MSG_WAITALL) == sizeof(resp));
                pthread_mutex_unlock(&g_socket_lock);
                if (!send_ok || !recv_ok) {
                    printf("Read failed!\n");
                    break;
                }
                if (resp.bisnp_req != 0) handle_invalidation(&resp);
                if (resp.status == 0) {
                    memcpy(data, resp.data, CACHELINE_SIZE);
                    g_stats.reads++;
                    printf("Data: ");
                    for (int i = 0; i < 16; i++) printf("%02x ", data[i]);
                    printf("...\n");
                    printf("As uint64: 0x%lx\n", *(uint64_t*)data);
                    printf("Access latency: %lu ns (%.2f us)\n", resp.latency_ns, resp.latency_ns/1000.0);
                } else {
                    printf("Read failed!\n");
                }
                break;
            }
            
            case 'w': case 'W': {
                /* Write command */
                uint64_t write_addr = addr;
                uint64_t value = 0;
                char *ptr = input + 2;
                write_addr = strtoull(ptr, &ptr, 0);
                if (*ptr) value = strtoull(ptr, NULL, 0);
                addr = write_addr;
                uint8_t data[CACHELINE_SIZE] = {0};
                *(uint64_t*)data = value;
                printf("Writing 0x%lx to 0x%lx...\n", value, write_addr);
                CXLMemSimRequest req = {0};
                CXLMemSimResponse resp = {0};
                req.op_type = CXL_WRITE_OP;
                req.addr = write_addr;
                req.size = CACHELINE_SIZE;
                req.timestamp = get_timestamp_ns();
                memcpy(req.data, data, CACHELINE_SIZE);
                pthread_mutex_lock(&g_socket_lock);
                int send_ok = (send(g_socket_fd, &req, sizeof(req), 0) == sizeof(req));
                int recv_ok = (recv(g_socket_fd, &resp, sizeof(resp), MSG_WAITALL) == sizeof(resp));
                pthread_mutex_unlock(&g_socket_lock);
                if (!send_ok || !recv_ok) {
                    printf("Write failed!\n");
                    break;
                }
                if (resp.bisnp_req != 0) handle_invalidation(&resp);
                if (resp.status == 0) {
                    g_stats.writes++;
                    printf("Write successful\n");
                    printf("Access latency: %lu ns (%.2f us)\n", resp.latency_ns, resp.latency_ns/1000.0);
                } else {
                    printf("Write failed!\n");
                }
                break;
            }
            
            case 'm': case 'M': {
                /* Monitor mode - just wait and watch */
                printf("Monitor mode - watching for invalidations (Ctrl+C to return)...\n");
                while (g_running) {
                    sleep(1);
                    printf("  [%lu invalidations received so far]\r", 
                           atomic_load(&g_invalidations_received));
                    fflush(stdout);
                }
                printf("\n");
                break;
            }
            
            case 's': case 'S': {
                print_stats();
                break;
            }
            
            case 'q': case 'Q': {
                g_running = false;
                break;
            }
            
            default:
                printf("Unknown command: %c\n", cmd);
                break;
        }
    }
}

int main(int argc, char *argv[]) {
    const char *server_host = "192.168.100.1";  /* Default: host from QEMU guest */
    int port = 9999;
    uint64_t base_addr = 0x1000;

    printf("═══════════════════════════════════════════════════════════════\n");
    printf("          CXL MEMORY INVALIDATION MONITOR                      \n");
    printf("═══════════════════════════════════════════════════════════════\n\n");

    if (argc < 2) {
        printf("Usage: %s <server_ip> <port> [base_address]\n", argv[0]);
        printf("Example: %s 10.0.2.2 10000 0x1000\n\n", argv[0]);
        printf("Using defaults: %s:%d, base_addr=0x%lx\n", server_host, port, base_addr);
    } else {
        server_host = argv[1];
        if (argc > 2) port = atoi(argv[2]);
        if (argc > 3) base_addr = strtoull(argv[3], NULL, 0);
    }

    /* Setup signal handler */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Connect to server */
    printf("Connecting to CXLMemSim server at %s:%d...\n", server_host, port);
    g_socket_fd = connect_to_server(server_host, port);
    if (g_socket_fd < 0) {
        fprintf(stderr, "Failed to connect to server\n");
        return 1;
    }
    printf("✓ Connected successfully\n\n");

    /* Start invalidation monitor thread */
    pthread_t monitor_thread;
    if (pthread_create(&monitor_thread, NULL, invalidation_monitor_thread, NULL) != 0) {
        perror("pthread_create");
        close(g_socket_fd);
        return 1;
    }

    /* Run interactive menu */
    interactive_menu(base_addr);

    /* Cleanup */
    g_running = false;
    pthread_join(monitor_thread, NULL);
    
    print_stats();
    
    close(g_socket_fd);
    printf("Goodbye!\n");

    return 0;
}
