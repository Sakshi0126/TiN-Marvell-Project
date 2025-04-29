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

static const unsigned char alpn_h3[] = {0x02, 0x68, 0x33}; 
static volatile int running = 1;
static volatile int active_connections = 0;
static pthread_mutex_t connections_mutex = PTHREAD_MUTEX_INITIALIZER;

void signal_handler(int sig) {
    printf("\nReceived signal %d, shutting down gracefully...\n", sig);
    running = 0;
}

static int select_alpn(SSL *ssl, const unsigned char **out, unsigned char *out_len,
                       const unsigned char *in, unsigned int in_len, void *arg) {
    if (SSL_select_next_proto((unsigned char **)out, out_len, alpn_h3,
                              sizeof(alpn_h3), in, in_len) != OPENSSL_NPN_NEGOTIATED) {
        fprintf(stderr, "Warning: ALPN negotiation failed\n");
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    return SSL_TLSEXT_ERR_OK;
}

static SSL_CTX *create_ctx(const char *cert_path, const char *key_path) {
    SSL_CTX *ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (!ctx) {
        fprintf(stderr, "Error: SSL context creation failed\n");
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    if (SSL_CTX_use_certificate_chain_file(ctx, cert_path) <= 0) {
        fprintf(stderr, "Error: Failed to load certificate from %s\n", cert_path);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error: Failed to load private key from %s\n", key_path);
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Error: Private key does not match the certificate\n");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return NULL;
    }

    SSL_CTX_set_alpn_select_cb(ctx, select_alpn, NULL);
    return ctx;
}

static int create_socket(uint16_t port) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        fprintf(stderr, "Error: Socket creation failed - %s\n", strerror(errno));
        return -1;
    }

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = INADDR_ANY;

    int opt = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        fprintf(stderr, "Error: Failed to set socket options - %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "Error: Failed to bind to port %d - %s\n", port, strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

static int run_quic_conn(SSL *conn, int conn_id) {
    size_t record_size = 0;
    size_t read_bytes, written;
    char *buffer = NULL;
    struct sockaddr_in peer_addr;
    socklen_t addr_len = sizeof(peer_addr);
    char peer_ip[INET_ADDRSTRLEN];
    size_t total_bytes_sent = 0;
    int client_closed_connection = 0;

    // Get peer information
    printf("Connection: 0x%lx (LWP %d)]\n", (unsigned long)pthread_self(), (int)getpid());
    
    if (getpeername(SSL_get_fd(conn), (struct sockaddr *)&peer_addr, &addr_len) == 0) {
        inet_ntop(AF_INET, &peer_addr.sin_addr, peer_ip, INET_ADDRSTRLEN);
        printf("Connection %d: Client connected from %s:%d\n", 
               conn_id, peer_ip, ntohs(peer_addr.sin_port));
    } else {
        printf("Connection %d: New client connected 0x%lx (LWP %d) \n", conn_id, (unsigned long)pthread_self(), (int)getpid());
    }

    // Increment active connections counter
    pthread_mutex_lock(&connections_mutex);
    active_connections++;
    printf("Status: %d active connection(s)\n", active_connections);
    pthread_mutex_unlock(&connections_mutex);

    // Read record_size from client in non-blocking mode
    while (running && SSL_get_shutdown(conn) == 0) {
        int result = SSL_read_ex(conn, &record_size, sizeof(record_size), &read_bytes);
        if (result) {
            break; // Successfully read the data
        }
        
        int err = SSL_get_error(conn, result);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            usleep(1000); // Small sleep to avoid busy-wait
            continue;
        }
        
        if (SSL_get_shutdown(conn)) {
            printf("Connection %d: Client closed the connection during initial handshake\n", conn_id);
            goto cleanup;
        }
        
        fprintf(stderr, "Connection %d: Error receiving record size from client: %s\n", 
                conn_id, ERR_error_string(err, NULL));
        goto cleanup;
    }
    
    if (read_bytes != sizeof(record_size) || record_size <= 0 || record_size > 1024 * 1024) {
        fprintf(stderr, "Connection %d: Client requested invalid record size: %zu\n", conn_id, record_size);
        goto cleanup;
    }
    
    printf("Connection %d: Client requested record size: %zu bytes\n", conn_id, record_size);

    // Allocate buffer
    buffer = malloc(record_size);
    if (!buffer) {
        fprintf(stderr, "Connection %d: Memory allocation failed for data buffer\n", conn_id);
        goto cleanup;
    }
    
    // Fill buffer with pattern
    for (size_t i = 0; i < record_size; i++) {
        buffer[i] = 'A' + (i % 26);  // Fill with A-Z pattern
    }

    printf("Connection %d: Starting data transfer...\n", conn_id);

    // Continuously send data in non-blocking mode
    while (running && SSL_get_shutdown(conn) == 0) {
        int result = SSL_write_ex(conn, buffer, record_size, &written);
        if (!result) {
            int err = SSL_get_error(conn, result);
            if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
                usleep(1000); // Small sleep to avoid busy-wait
                continue;
            }
            
            if (SSL_get_shutdown(conn)) {
                printf("Connection %d: Client closed the connection\n", conn_id);
                client_closed_connection = 1;
            } else {
                fprintf(stderr, "Connection %d: Error sending data to client: %s\n", 
                        conn_id, ERR_error_string(err, NULL));
            }
            break;
        }
        
        total_bytes_sent += written;
        
        // Small sleep to avoid overwhelming slow clients
        usleep(100);
    }

    printf("Connection %d: Data transfer completed\n", conn_id);

    // Shutdown connection if client didn't close it
    if (!client_closed_connection) {
        printf("Connection %d: Closing connection...\n", conn_id);
        int shutdown_ret;
        for (int i = 0; i < 5; i++) {
            shutdown_ret = SSL_shutdown(conn);
            if (shutdown_ret == 1) {
                printf("Connection %d: Connection closed gracefully\n", conn_id);
                break;
            }
            if (shutdown_ret == 0) {
                usleep(100000);  // Wait 100ms before retry
            } else {
                fprintf(stderr, "Connection %d: Connection closure failed\n", conn_id);
                break;
            }
        }
    }

cleanup:
    // Decrement active connections counter
    pthread_mutex_lock(&connections_mutex);
    active_connections--;
    printf("Status: %d active connection(s) remaining\n", active_connections);
    pthread_mutex_unlock(&connections_mutex);
    
    printf("Connection %d: Session completed\n", conn_id);
    free(buffer);
    return 0;
}

typedef struct {
    SSL *conn;
    int conn_id;
} thread_arg_t;

void *connection_thread(void *arg) {
    thread_arg_t *targ = (thread_arg_t *)arg;
    run_quic_conn(targ->conn, targ->conn_id);
    SSL_free(targ->conn);
    free(targ);
    return NULL;
}

static int run_quic_server(SSL_CTX *ctx, int fd, uint16_t port) {
    SSL *listener = SSL_new_listener(ctx, 0);
    if (!listener) {
        fprintf(stderr, "Error: Failed to create QUIC listener\n");
        ERR_print_errors_fp(stderr);
        return 0;
    }

    if (!SSL_set_fd(listener, fd)) {
        fprintf(stderr, "Error: Failed to associate socket with SSL listener\n");
        ERR_print_errors_fp(stderr);
        SSL_free(listener);
        return 0;
    }

    if (!SSL_listen(listener)) {
        fprintf(stderr, "Error: SSL_listen failed\n");
        ERR_print_errors_fp(stderr);
        SSL_free(listener);
        return 0;
    }

    // Set to non-blocking mode for graceful shutdown support
    if (!SSL_set_blocking_mode(listener, 0)) {
        fprintf(stderr, "Error: Failed to set non-blocking mode\n");
        ERR_print_errors_fp(stderr);
        SSL_free(listener);
        return 0;
    }

    printf("QUIC Server listening on port %d\n", port);
    printf("Press Ctrl+C to stop the server\n\n");

    int conn_id = 0;

while (running) {
        SSL *conn = SSL_accept_connection(listener, 0);
        if (!conn) {
            unsigned long err = ERR_get_error();
            if (err == 0) {
                // No error means we just need to wait - this is normal for non-blocking mode
                usleep(10000);  // Sleep for 10ms to avoid busy-wait
                continue;
            }
            
            fprintf(stderr, "Error accepting connection: %s\n", 
                    ERR_error_string(err, NULL));
            continue;
        }

        // Set connection to non-blocking mode
        if (!SSL_set_blocking_mode(conn, 0)) {
            fprintf(stderr, "Warning: Failed to set non-blocking mode for connection\n");
            ERR_print_errors_fp(stderr);
            SSL_free(conn);
            continue;
        }

        thread_arg_t *targ = malloc(sizeof(thread_arg_t));
        if (!targ) {
            fprintf(stderr, "Error: Memory allocation failed for connection handler\n");
            SSL_free(conn);
            continue;
        }
        
        targ->conn = conn;
        targ->conn_id = ++conn_id;

        pthread_t thread;
        if (pthread_create(&thread, NULL, connection_thread, targ) != 0) {
            fprintf(stderr, "Error: Failed to create thread for connection %d\n", conn_id);
            SSL_free(conn);
            free(targ);
            continue;
        }
        
        pthread_detach(thread);
    }

    printf("Shutting down server...\n");
    
    // Wait for active connections to finish
    int wait_count = 0;
    while (active_connections > 0 && wait_count < 30) {
        printf("Waiting for %d active connection(s) to close...\n", active_connections);
        sleep(1);
        wait_count++;
    }
    
    if (active_connections > 0) {
        printf("Some connections did not close cleanly. Forcing shutdown.\n");
    } else {
        printf("All connections closed successfully.\n");
    }

    SSL_free(listener);
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <port> <cert.pem> <key.pem>\n", argv[0]);
        fprintf(stderr, "Example: %s 4433 server.crt server.key\n", argv[0]);
        return 1;
    }

    unsigned long port = strtoul(argv[1], NULL, 0);
    if (port == 0 || port > UINT16_MAX) {
        fprintf(stderr, "Error: Invalid port number: %lu\n", port);
        return 1;
    }

    // Set up signal handler
    signal(SIGINT, signal_handler);

    // Initialize OpenSSL
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);

    SSL_CTX *ctx = create_ctx(argv[2], argv[3]);
    if (!ctx) return 1;

    int fd = create_socket((uint16_t)port);
    if (fd < 0) {
        SSL_CTX_free(ctx);
        return 1;
    }

    if (!run_quic_server(ctx, fd, (uint16_t)port)) {
        SSL_CTX_free(ctx);
        close(fd);
        return 1;
    }

    SSL_CTX_free(ctx);
    close(fd);
    printf("QUIC Server shut down successfully\n");
    return 0;
}
