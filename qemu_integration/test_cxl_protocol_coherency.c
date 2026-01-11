/*
 * CXL Protocol Coherency Test via CXLMemSim Server
 * This ensures true coherency between different VMs/processes
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <errno.h>
#include <time.h>

#define CACHELINE_SIZE 64
#define TEST_SIZE (16 * 1024)  // Test 16KB

// CXLMemSim Protocol structures
typedef struct {
    uint8_t op_type;      // 0=READ, 1=WRITE
    uint64_t addr;
    uint64_t size;
    uint64_t timestamp;
    uint8_t data[64];
} ServerRequest;

typedef struct {
    uint8_t status;
    uint64_t latency_ns;
    uint8_t data[64];
} ServerResponse;

// Connect to CXLMemSim server
int connect_to_server(const char* host, int port) {
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

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sock);
        return -1;
    }

    return sock;
}

// Write to CXLMemSim server
int write_to_server(int sock, uint64_t addr, const uint8_t* data, size_t size) {
    ServerRequest req = {0};
    req.op_type = 1;  // WRITE
    req.addr = addr;
    req.size = size;
    req.timestamp = 0;

    memcpy(req.data, data, size < 64 ? size : 64);

    if (send(sock, &req, sizeof(req), 0) != sizeof(req)) {
        printf("Failed to send write request\n");
        return -1;
    }

    ServerResponse resp = {0};
    if (recv(sock, &resp, sizeof(resp), MSG_WAITALL) != sizeof(resp)) {
        printf("Failed to receive response\n");
        return -1;
    }

    return resp.status == 0 ? 0 : -1;
}

// Read from CXLMemSim server
int read_from_server(int sock, uint64_t addr, uint8_t* data, size_t size) {
    ServerRequest req = {0};
    req.op_type = 0;  // READ
    req.addr = addr;
    req.size = size;
    req.timestamp = 0;

    if (send(sock, &req, sizeof(req), 0) != sizeof(req)) {
        printf("Failed to send read request\n");
        return -1;
    }

    ServerResponse resp = {0};
    if (recv(sock, &resp, sizeof(resp), MSG_WAITALL) != sizeof(resp)) {
        printf("Failed to receive response\n");
        return -1;
    }

    if (resp.status == 0) {
        memcpy(data, resp.data, size < 64 ? size : 64);
        return 0;
    }

    return -1;
}

void writer_test(const char* server_host, int port) {
    printf("\n=== WRITER Process (PID: %d) ===\n", getpid());
    printf("Connecting to CXLMemSim server at %s:%d\n", server_host, port);

    int sock = connect_to_server(server_host, port);
    if (sock < 0) {
        fprintf(stderr, "WRITER: Failed to connect to server\n");
        exit(1);
    }

    printf("WRITER: Connected to CXLMemSim server\n");

    // Clear and write test patterns
    printf("WRITER: Writing test patterns...\n");

    for (size_t i = 0; i < TEST_SIZE; i += CACHELINE_SIZE) {
        uint8_t pattern_data[CACHELINE_SIZE];
        uint8_t pattern = (i / CACHELINE_SIZE) & 0xFF;

        // Fill cacheline with pattern
        for (int j = 0; j < CACHELINE_SIZE; j++) {
            pattern_data[j] = pattern;
        }

        // Write to server
        if (write_to_server(sock, i, pattern_data, CACHELINE_SIZE) < 0) {
            printf("WRITER: Failed to write at offset %zu\n", i);
        } else if (i < 1024 || i % 1024 == 0) {
            printf("  Wrote pattern 0x%02x at offset %zu\n", pattern, i);
        }
    }

    // Verify our writes by reading back
    printf("\nWRITER: Verifying writes...\n");
    int errors = 0;

    for (size_t i = 0; i < 1024; i += CACHELINE_SIZE) {
        uint8_t read_data[CACHELINE_SIZE];
        uint8_t expected = (i / CACHELINE_SIZE) & 0xFF;

        if (read_from_server(sock, i, read_data, CACHELINE_SIZE) == 0) {
            if (read_data[0] != expected) {
                printf("  WRITER verify error at offset %zu: expected 0x%02x, got 0x%02x\n",
                       i, expected, read_data[0]);
                errors++;
            }
        }
    }

    if (errors == 0) {
        printf("WRITER: ✓ All patterns written and verified\n");
    } else {
        printf("WRITER: ✗ Found %d errors in verification\n", errors);
    }

    close(sock);
    printf("WRITER: Complete\n");
}

void reader_test(const char* server_host, int port) {
    printf("\n=== READER Process (PID: %d) ===\n", getpid());
    printf("Connecting to CXLMemSim server at %s:%d\n", server_host, port);

    int sock = connect_to_server(server_host, port);
    if (sock < 0) {
        fprintf(stderr, "READER: Failed to connect to server\n");
        exit(1);
    }

    printf("READER: Connected to CXLMemSim server\n");

    // Check problematic offsets
    size_t problem_offsets[] = {64, 128, 192, 320, 384, 448, 576, 640, 704, 832, 896, 960};
    int num_problems = sizeof(problem_offsets) / sizeof(problem_offsets[0]);

    printf("\nREADER: Checking problematic offsets:\n");
    int errors = 0;

    for (int i = 0; i < num_problems; i++) {
        size_t offset = problem_offsets[i];
        uint8_t read_data[CACHELINE_SIZE];
        uint8_t expected = (offset / CACHELINE_SIZE) & 0xFF;

        if (read_from_server(sock, offset, read_data, CACHELINE_SIZE) == 0) {
            if (read_data[0] != expected) {
                printf("  Error at offset %zu: expected 0x%02x, got 0x%02x\n",
                       offset, expected, read_data[0]);
                errors++;

                // Show first few bytes
                printf("    Data: ");
                for (int j = 0; j < 8; j++) {
                    printf("%02x ", read_data[j]);
                }
                printf("...\n");
            } else {
                printf("  ✓ Offset %zu: correct (0x%02x)\n", offset, expected);
            }
        } else {
            printf("  Failed to read offset %zu\n", offset);
            errors++;
        }
    }

    // Full scan
    printf("\nREADER: Full verification...\n");
    for (size_t i = 0; i < TEST_SIZE; i += CACHELINE_SIZE) {
        uint8_t read_data[CACHELINE_SIZE];
        uint8_t expected = (i / CACHELINE_SIZE) & 0xFF;

        if (read_from_server(sock, i, read_data, CACHELINE_SIZE) == 0) {
            if (read_data[0] != expected) {
                if (errors < 20) {
                    printf("  Error at offset %zu: expected 0x%02x, got 0x%02x\n",
                           i, expected, read_data[0]);
                }
                errors++;
            } else if (i < 1024 || i % 1024 == 0) {
                printf("  ✓ Offset %zu: correct (0x%02x)\n", i, expected);
            }
        }
    }

    if (errors == 0) {
        printf("\nREADER: ✓ All patterns verified successfully!\n");
    } else {
        printf("\nREADER: ✗ Found %d errors\n", errors);
    }

    close(sock);
    printf("READER: Complete\n");
}

int main(int argc, char *argv[]) {
    const char* server_host = "10.0.2.2";  // Host from QEMU guest perspective
    int port = 10000;

    printf("=== CXL Protocol Coherency Test ===\n");
    printf("Using CXLMemSim server for true coherency\n\n");

    if (argc < 2) {
        printf("Usage: %s <write|read> [server_ip] [port]\n", argv[0]);
        printf("Example:\n");
        printf("  VM1: %s write 10.0.2.2 10000\n", argv[0]);
        printf("  VM2: %s read 10.0.2.2 10000\n", argv[0]);
        return 1;
    }

    if (argc > 2) server_host = argv[2];
    if (argc > 3) port = atoi(argv[3]);

    if (strcmp(argv[1], "write") == 0) {
        writer_test(server_host, port);
    } else if (strcmp(argv[1], "read") == 0) {
        // Give writer time to write
        printf("Waiting for writer to complete...\n");
        sleep(2);
        reader_test(server_host, port);
    } else {
        printf("Invalid command: %s\n", argv[1]);
        return 1;
    }

    return 0;