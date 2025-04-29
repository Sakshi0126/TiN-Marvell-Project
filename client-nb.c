#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/quic.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

#define HOST "10.68.0.105"
#define PORT 4433

static const unsigned char alpn[] = {0x02, 0x68, 0x33};  // "\x02h3"
static volatile int running = 1;

void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down gracefully...\n", sig);
    running = 0;
}

// Define struct for thread arguments
struct thread_args {
    SSL_CTX *ctx;
    size_t record_size;
    int thread_id;  // Added thread ID for better logging
};

static SSL_CTX *create_ctx() {
    SSL_CTX *ctx = SSL_CTX_new(OSSL_QUIC_client_method());
    if (!ctx) {
        fprintf(stderr, "Error: Unable to create SSL context\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    // Disable certificate verification for self-signed cert
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;
}

static void *client_thread(void *arg) {
    struct thread_args *args = (struct thread_args *)arg;
    SSL_CTX *ctx = args->ctx;
    size_t record_size = args->record_size;
    int thread_id = args->thread_id;
    SSL *ssl = NULL;
    int sockfd = -1;
    struct sockaddr_in addr = {0};
    char *buffer = NULL;
    size_t read_bytes, written;
    size_t total_bytes = 0;
    struct timespec start, last_report, now;
    double elapsed, report_interval = 30.0;  // Report after few seconds
    int connection_closed_by_server = 0;
    int connect_complete = 0;

    // Allocate buffer
    buffer = malloc(record_size);
    if (!buffer) {
        fprintf(stderr, "Error: Memory allocation failed for buffer\n");
        goto err;
    }

    // Create UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Error: Socket creation failed - %s\n", strerror(errno));
        goto err;
    }

    // Set server address
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, HOST, &addr.sin_addr) <= 0) {
        fprintf(stderr, "Error: Invalid address - %s\n", HOST);
        goto err;
    }

    // Connect socket to server
    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Error: Connection to server failed - %s\n", strerror(errno));
        goto err;
    }

    // Create SSL connection
    ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "Error: SSL object creation failed\n");
        ERR_print_errors_fp(stderr);
        goto err;
    }

    // Set ALPN
    if (SSL_set_alpn_protos(ssl, alpn, sizeof(alpn)) != 0) {
        fprintf(stderr, "Error: Failed to set ALPN protocols\n");
        ERR_print_errors_fp(stderr);
        goto err;
    }

    if (!SSL_set_fd(ssl, sockfd)) {
        fprintf(stderr, "Error: Failed to associate socket with SSL\n");
        ERR_print_errors_fp(stderr);
        goto err;
    }

    // Set to non-blocking mode
    if (!SSL_set_blocking_mode(ssl, 0)) {
        fprintf(stderr, "Error: Failed to set non-blocking mode\n");
        ERR_print_errors_fp(stderr);
        goto err;
    }

    // Set connect state
    SSL_set_connect_state(ssl);

    // Handshake in non-blocking mode
    printf("Thread %d: Connecting to server at %s:%d...\n", thread_id, HOST, PORT);
    
    // Non-blocking connect loop
    while (!connect_complete && running) {
        int result = SSL_connect(ssl);
        if (result == 1) {
            connect_complete = 1;
            break;
        }
        
        int err = SSL_get_error(ssl, result);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            usleep(1000); // Small sleep to avoid busy-wait
            continue;
        }
        
        fprintf(stderr, "Thread %d: Connection handshake failed: %s\n", 
                thread_id, ERR_error_string(err, NULL));
        goto err;
    }
    
    if (!connect_complete) {
        fprintf(stderr, "Thread %d: SSL_connect did not complete\n", thread_id);
        goto err;
    }

    // Verify ALPN
    const unsigned char *alpn_negotiated;
    unsigned int alpn_len;
    SSL_get0_alpn_selected(ssl, &alpn_negotiated, &alpn_len);
    if (alpn_len > 0) {
        printf("Thread %d: Negotiated ALPN: %.*s\n", thread_id, alpn_len, alpn_negotiated);
    } else {
        printf("Thread %d: No ALPN negotiated\n", thread_id);
    }

    printf("Thread %d: Connected successfully to server\n", thread_id);

    // Send record_size to server in non-blocking mode
    int write_complete = 0;
    while (!write_complete && running) {
        int result = SSL_write_ex(ssl, &record_size, sizeof(record_size), &written);
        if (result) {
            if (written == sizeof(record_size)) {
                write_complete = 1;
                break;
            } else {
                fprintf(stderr, "Thread %d: Warning: Partial write of record size: %zu bytes\n", 
                        thread_id, written);
                goto err;
            }
        }
        
        int err = SSL_get_error(ssl, result);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            usleep(1000); // Small sleep to avoid busy-wait
            continue;
        }
        
        fprintf(stderr, "Thread %d: Error: Failed to send record size to server: %s\n", 
                thread_id, ERR_error_string(err, NULL));
        goto err;
    }
    
    if (!write_complete) {
        fprintf(stderr, "Thread %d: Failed to send record size to server\n", thread_id);
        goto err;
    }
    
    printf("Thread %d: Requested record size: %zu bytes\n", thread_id, record_size);

    // Initialize timing
    clock_gettime(CLOCK_MONOTONIC, &start);
    last_report = start;

    // Continuously read data in non-blocking mode
    while (running && SSL_get_shutdown(ssl) == 0) {
        int result = SSL_read_ex(ssl, buffer, record_size, &read_bytes);
        if (result) {
            total_bytes += read_bytes;
        } else {
            int err = SSL_get_error(ssl, result);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                usleep(1000);  // Brief sleep to avoid busy loop
                continue;
            }
            
            if (SSL_get_shutdown(ssl)) {
                printf("Thread %d: Server closed the connection\n", thread_id);
                connection_closed_by_server = 1;
            } else {
                fprintf(stderr, "Thread %d: Error receiving data from server: %s\n", 
                        thread_id, ERR_error_string(err, NULL));
            }
            break;
        }

        // Check for throughput report
        clock_gettime(CLOCK_MONOTONIC, &now);
        elapsed = (now.tv_sec - last_report.tv_sec) + (now.tv_nsec - last_report.tv_nsec) / 1e9;
        if (elapsed >= report_interval) {
            double total_elapsed = (now.tv_sec - start.tv_sec) + (now.tv_nsec - start.tv_nsec) / 1e9;
            double throughput_gbps = (total_bytes * 8.0) / (total_elapsed * 1e9);  // Bytes to Gbps
            double throughput_mbps = throughput_gbps * 1000.0;  // Convert to Mbps for more readable values
            
            printf("Thread %d: Current throughput = %.2f Mbps (%.1f seconds elapsed, %.2f MB received)\n",
                   thread_id, throughput_mbps, total_elapsed, total_bytes / (1024.0 * 1024.0));
            last_report = now;
        }
    }

    // Print final throughput
    
    clock_gettime(CLOCK_MONOTONIC, &now);
    elapsed = (now.tv_sec - start.tv_sec) + (now.tv_nsec - start.tv_nsec) / 1e9;
    if (elapsed > 0) {
        double throughput_gbps = (total_bytes * 8.0) / (elapsed * 1e9);
        double throughput_mbps = throughput_gbps * 1000.0;  // Convert to Mbps for more readable values
        
        printf("\n========== Thread %d: Final Results ==========\n", thread_id);
        printf("Total data received: %.2f MB\n", total_bytes / (1024.0 * 1024.0));
        printf("Total time: %.1f seconds\n", elapsed);
        printf("Average throughput: %.3f Gbps (%.2f Mbps)\n", 
               throughput_gbps, throughput_mbps);
        printf("==========================================\n");
    }

    // Shutdown in non-blocking mode
    if (!connection_closed_by_server) {
        printf("Thread %d: Shutting down connection...\n", thread_id);
        int shutdown_complete = 0;
        int attempts = 0;
        const int max_attempts = 50; // More attempts for non-blocking mode
        
        while (!shutdown_complete && attempts < max_attempts) {
            int shutdown_ret = SSL_shutdown(ssl);
            if (shutdown_ret == 1) {
                printf("Thread %d: Connection closed gracefully\n", thread_id);
                shutdown_complete = 1;
                break;
            }
            
            if (shutdown_ret < 0) {
                int err = SSL_get_error(ssl, shutdown_ret);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    usleep(10000); // Wait 10ms before retry in non-blocking mode
                    attempts++;
                    continue;
                }
                
                fprintf(stderr, "Thread %d: Connection closure failed: %s\n", 
                        thread_id, ERR_error_string(err, NULL));
                break;
            }
            
            // shutdown_ret == 0, which means "shutdown is not finished"
            usleep(10000);  // Wait 10ms before retry
            attempts++;
        }
        
        if (!shutdown_complete) {
            fprintf(stderr, "Thread %d: SSL_shutdown did not complete after %d attempts\n", 
                    thread_id, max_attempts);
        }
    }

err:
    free(buffer);
    if (ssl) SSL_free(ssl);
    if (sockfd >= 0) close(sockfd);
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <num_connections> <record_size>\n", argv[0]);
        fprintf(stderr, "Example: %s 5 8192\n", argv[0]);
        return 1;
    }

    int num_connections = atoi(argv[1]);
    if (num_connections <= 0 || num_connections > 100) {
        fprintf(stderr, "Error: Invalid number of connections (must be 1-100)\n");
        return 1;
    }

    size_t record_size = atol(argv[2]);
    if (record_size <= 0 || record_size > 1024 * 1024) {  // Limit to 1MB
        fprintf(stderr, "Error: Invalid record size (must be 1-1048576 bytes)\n");
        return 1;
    }

    // Set up signal handler
    signal(SIGINT, signal_handler);

    // Initialize OpenSSL
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

    SSL_CTX *ctx = create_ctx();
    if (!ctx) return 1;

    pthread_t *threads = malloc(sizeof(pthread_t) * num_connections);
    if (!threads) {
        fprintf(stderr, "Error: Memory allocation failed for thread array\n");
        SSL_CTX_free(ctx);
        return 1;
    }

    struct thread_args *args = malloc(sizeof(struct thread_args) * num_connections);
    if (!args) {
        fprintf(stderr, "Error: Memory allocation failed for thread arguments\n");
        free(threads);
        SSL_CTX_free(ctx);
        return 1;
    }

    printf("Starting QUIC client with %d connection(s), record size: %zu bytes\n", 
           num_connections, record_size);
    printf("Press Ctrl+C to stop the test\n\n");

    for (int i = 0; i < num_connections; i++) {
        args[i].ctx = ctx;
        args[i].record_size = record_size;
        args[i].thread_id = i+1;
        
        if (pthread_create(&threads[i], NULL, client_thread, &args[i]) != 0) {
            fprintf(stderr, "Error: Failed to create thread %d\n", i+1);
            num_connections = i;
            break;
        }
    }

    for (int i = 0; i < num_connections; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("\nAll connections closed, test complete\n");

    free(args);
    free(threads);
    SSL_CTX_free(ctx);
    return 0;
}
