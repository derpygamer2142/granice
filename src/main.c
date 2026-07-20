// networking headers
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

// program headers
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

// openssl stuff
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// compression library wrappers
// these will be implementations of some libraries
// that just take a string and return it as a compressed one
#include "include/compression_wrappers.h"

char* ACCEPTED_ENCODINGS[] = { "gzip" };
const unsigned int NUM_ACCEPTED_ENCODINGS = 1;

// misc other stuff
#include "include/hashtable.h"
#include "client.h"
#include "http_wrapper.h"

// completely arbitrary
#define CACHE_KEY_LENGTH 128
// in seconds
#define CACHE_LIFETIME   90
// in bytes
#define CACHE_REQUEST_ALLOC 4096

// hash table to cache responses
HashTable* responseCache;

struct cached_response {
    time_t last_update;
    char* response;
    size_t length;
    size_t alloc_size;
    size_t header_length;
};

SSL_CTX* ctx;

char* generate_hash_key(struct parsed_request* request) {
    char* accepted_encodings = get_header_value(request->headers, "Accept-Encoding");
    char* key = malloc(CACHE_KEY_LENGTH); // one must imagine sisyphus happy. so much malloc. so much memory.

    // find an encoding that both the client and this server accept
    char* encoding = 0;

    if (accepted_encodings) {
        for (int i = 0; i < NUM_ACCEPTED_ENCODINGS; i++) {
            if (strstr(accepted_encodings, ACCEPTED_ENCODINGS[i])) {
                encoding = ACCEPTED_ENCODINGS[i];
                break;
            }
        }        
    }

    // todo: this could probably be a bit better
    if (encoding) snprintf(key, CACHE_KEY_LENGTH-1, "%s %s", request->path, encoding);
    else snprintf(key, CACHE_KEY_LENGTH-1, "%s", request->path);
    key[CACHE_KEY_LENGTH-1] = '\0'; // a little odd but this should ensure the key is null-terminated

    return key;
}

/*
 * returns 0 if response not sent
 * returns 1 if response sent
*/
int serve_directory(char* directory, struct client_info* client, char* path, struct parsed_request* request) {
    // printf("serve_resource %s %s\n", get_client_address(client), path);
    char* full_path = sanitize_file_path(directory, path, client);
    if (!full_path) return 1;

    FILE* fp = fopen(full_path, "rb");

    if (!fp) {
        // printf("Not found: %s, %s\n", path, full_path);
        free(full_path);
        // don't need to close the file pointer because it wasn't created?
        return 0;
    }

    char* key = generate_hash_key(request);

    // if there is a cached response younger than CACHE_LIFETIME, send that
    // otherwise go through the normal stuff

    struct cached_response* cached = hash_get(responseCache, key, strlen(key));
    if (!cached) {
        // initialize a cache entry to be updated by the child thread
        // this is done in the main thread to avoid problems with resizing memory on child threads
        // note: i don't think resizing the memory on the main thread will cause problems
        // because the memory should be preserved until all child threads are killed
        // but i'm not completely sure

        struct cached_response* entry = calloc_shm(1, sizeof(struct cached_response));

        entry->last_update = 0;
        entry->length = 0;
        entry->alloc_size = CACHE_REQUEST_ALLOC;
        entry->header_length = 0;
        // This is kind of cursed. We start off by allocating some memory
        // and keeping the length at 0. In the child process(where we read contents)
        // if the content length exceeds the allocated memory we write
        // the content length and the main thread will reallocate the memory.
        entry->response = (char*) malloc_shm(CACHE_REQUEST_ALLOC);

        hash_store(responseCache, key, strlen(key), (void*) entry);

        cached = entry; // make it easier for the child thread to edit the entry
    }
    else {
        if (cached->length > cached->alloc_size) {
            munmap(cached->response, cached->alloc_size);
            cached->response = (char*) malloc_shm(cached->length);
            cached->alloc_size = cached->length;
        }
    }
    free(key);

    if (!fork()) {
        time_t timer;
        time(&timer);
        char* out = 0;

        if (timer - cached->last_update >= CACHE_LIFETIME) {
            // cache is expired, update

            fseek(fp, 0L, SEEK_END);
            size_t content_length = ftell(fp);
            rewind(fp);
            const char* content_type = get_content_type(full_path);
            char* filedata = malloc(content_length + 1);

            fread(filedata, content_length, 1, fp);
            char* accepted_encoding = get_header_value(request->headers, "Accept-Encoding");
            char* encoding = 0;

            if (accepted_encoding) {
                if (strstr(accepted_encoding, "gzip")) {
                    char* compressed = zlibGzip(filedata, content_length, &content_length);
                    free(filedata);
                    filedata = compressed;
                    encoding = "gzip";
                }
            }
                


            #define BSIZE 2048
            char headers[BSIZE] = "HTTP/1.1 200 OK\r\n"
                                "Connection: close\r\n";
            // this seems like a weird way to do this
            if (encoding) sprintf(headers+strlen(headers), "Content-Encoding: %s\r\n", encoding); // write the encoding header if it was encoded
            sprintf(headers+strlen(headers), "Content-Length: %lu\r\nContent-Type: %s\r\n\r\n", content_length, content_type);

            cached->header_length = strlen(headers);

            char* buffer = malloc(strlen(headers)+content_length+1);
            strcpy(buffer, headers);
            
            int length = strlen(buffer);
            for (int i = 0; i < content_length; i++) {
                buffer[length+i] = (unsigned char)filedata[i];
            }
            buffer[length+content_length] = '\0';
            // super weird code

            if (cached->alloc_size >= length+content_length+1) {
                memcpy(cached->response, buffer, length+content_length+1);
                time(&cached->last_update);
                free(buffer);
            }
            else {
                out = buffer;
            }

            cached->length = length+content_length+1;
        }

        int send_head = !strcasecmp(request->method, "HEAD");
        int len = (int) (send_head ? cached->header_length : cached->length);

        // printf("Response: %s\n", cached->response);
        if (client->tls) {
            SSL_write(client->ssl, out ? out : cached->response, len);
        }
        else {
            send(client->socket, out ? out : cached->response, len, 0);
        }
        if (out) free(out);

        // free(buffer);
        // freeing is done later because the response is cached
        fclose(fp);
        drop_client(client);
        free_headers(request->headers);
        free(request->path);
        free(request->method);
        free(request);
        free(full_path);
        // printf("Child done with request\n");
        exit(0);
    }
    else {
        // sockets might be preserved if the parent process doesn't close it
        // this causes problems in older browsers
        // modern browsers will automatically close it i think
        free(full_path);
        drop_client(client);
        return 1;
    }
}

int create_socket(const char* host, const char* port) {
    //printf("Configuring local address\n");
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    
    struct addrinfo *bind_address;
    getaddrinfo(host, port, &hints, &bind_address);

    //printf("Creating socket\n");
    int socket_listen;
    socket_listen = socket(bind_address->ai_family,
        bind_address->ai_socktype, bind_address->ai_protocol);
    
    if (socket_listen < 0) {
        fprintf(stderr, "socket() failed. %s (%d)\n", strerror(errno), errno);
        exit(1);
    }

    int yes = 1;
    if (setsockopt(socket_listen, SOL_SOCKET, SO_REUSEADDR, (void*)&yes, sizeof(yes)) < 0) {
        fprintf(stderr, "setsockopt() failed. %s (%d)\n", strerror(errno), errno);
        exit(1);
    }

    // this makes it so ipv4 gets mapped to ipv6
    // doesn't work on wsl so i can't test it
    /*int option = 0;
    if (setsockopt(socket_listen, IPPROTO_IPV6, IPV6_V6ONLY, (void*)&option, sizeof(option))) {
        fprintf(stderr, "setsockopt() failed. %s (%d)\n", strerror(errno), errno);
        exit(1);
    }*/

    //printf("Binding socket\n");
    if (bind(socket_listen, bind_address->ai_addr, bind_address->ai_addrlen)) {
        fprintf(stderr, "bind() failed. %s (%d)\n", strerror(errno), errno);
        exit(1);
    }
    freeaddrinfo(bind_address);

    //printf("Now listening\n");
    if (listen(socket_listen, 64)) {
        fprintf(stderr, "listen() failed. %s (%d)\n", strerror(errno), errno);
        exit(1);
    }

    return socket_listen;
}

void handle_request(struct client_info* client, char* request, char* serve) { // request is null terminated
    struct parsed_request* parsed = parse_request(client, request);
    if (!parsed) return;

    if (strncmp("/", parsed->path, 1)) { // not a path
        send_400(client);
    }
    else {
        if (!strcasecmp(parsed->method, "GET") || !strcasecmp(parsed->method, "HEAD")) {
            if (strchr(parsed->path, ' ')) {
                send_400(client);
                return;
            }

            if (!serve_directory(serve, client, parsed->path, parsed)) {
                send_404(client);
            }
        }
        else if (!strcasecmp(parsed->method, "OPTIONS")) {
            if (!strcmp(parsed->path, "*")) {
                char wildcard_options[2048];
                sprintf(wildcard_options,
                    "HTTP/1.1 200 OK\r\n"
                    "Allow: OPTIONS, GET, HEAD\r\n"
                    "Cache_Control: max-age=%i\r\n"
                    "Content-Length: 0\r\n\r\n",
                    CACHE_LIFETIME
                );

                send_uncached(client, wildcard_options, strlen(wildcard_options));
            }
            else {
                char* filepath = sanitize_file_path(serve, parsed->path, client);
                if (access(filepath, F_OK) == 0) { // Check if the file path exists
                    char response[2048];
                    sprintf(response,
                        "HTTP/1.1 200 OK\r\n"
                        "Allow: OPTIONS, GET, HEAD\r\n"
                        "Cache_Control: max-age=%i\r\n"
                        "Content-Length: 0\r\n\r\n",
                        CACHE_LIFETIME
                    );
                    send_uncached(client, response, strlen(response));
                }
                else {
                    char response[2048];
                    sprintf(response,
                        "HTTP/1.1 404 Not Found\r\n"
                        "Allow: OPTIONS, GET, HEAD\r\n"
                        "Cache_Control: max-age=%i\r\n"
                        "Content-Length: 0\r\n\r\n",
                        CACHE_LIFETIME
                    );
                    send_uncached(client, response, strlen(response));
                }

                free(filepath);
            }
        }
        else {
            // we are only looking at GET, HEAD, and OPTIONS requests right now
            send_501(client);
        }
    }

    free(parsed->path);
    free(parsed->method);
    free_headers(parsed->headers);
    free(parsed);
    // printf("Served request\n");
}

int main(int argc, char* argv[]) {
    signal(SIGPIPE, SIG_IGN);

    char cert_path[128];
    char key_path[128];

    if (argc > 2) {
        printf("Serving %s with SSL files from directory %s\n", argv[2], argv[1]);
        sprintf(cert_path, "%s/cert.pem", argv[1]);
        sprintf(key_path, "%s/key.pem", argv[1]);
    }
    else {
        fprintf(stderr, "Failed to start.\nUsage: server.bin /certificate/directory/ /serve/directory/\n");
        exit(1);
    }

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        fprintf(stderr, "SSL_CTX_new() failed\n");
        return 1;
    }
    SSL_CTX_set_options(ctx, SSL_OP_IGNORE_UNEXPECTED_EOF); // Fixes a thing where unexpected SSL disconnects cause problems
    if (!SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM)
    || !SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM)) {
        fprintf(stderr, "SSL_CTX_use_certificate_file() failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }


    int https_server = create_socket("0.0.0.0", "443");
    int http_server  = create_socket("0.0.0.0", "80");

    responseCache = hash_table_init(0);

    while (1) {
        fd_set reads;
        reads = wait_on_clients(https_server, http_server);

        if (FD_ISSET(https_server, &reads)) {
            // handle connections on the https port
            struct client_info* client = get_client(-1);

            client->socket = accept(https_server,
                (struct sockaddr*) &(client->address),
                &client->address_length
            );

            if (client->socket < 0) {
                fprintf(stderr, "accept() failed. %s (%d)\n", strerror(errno), errno);
                close(https_server);
                return 1;
            }

            client->ssl = SSL_new(ctx);
            if (!client->ssl) {
                fprintf(stderr, "SSL_new() failed\n");
                return 1;
            }
            SSL_set_fd(client->ssl, client->socket);
            if (SSL_accept(client->ssl) <= 0) {
                fprintf(stderr, "SSL_accept() failed\n");
                ERR_print_errors_fp(stderr);


                drop_client(client);
            }
            else {
                //printf("New https connection from %s, using SSL %s\n", get_client_address(client), SSL_get_cipher(client->ssl));
                client->tls = 1;
            }


        }
        if (FD_ISSET(http_server, &reads)) {
            // handle connections on the http port
            struct client_info* client = get_client(-1);
            client->tls = 0;

            client->socket = accept(http_server,
                (struct sockaddr*) &(client->address),
                &client->address_length
            );

            if (client->socket < 0) {
                fprintf(stderr, "accept() failed. %s (%d)\n", strerror(errno), errno);
                close(http_server);
                return 1;
            }

            //printf("New http connection from %s\n", get_client_address(client));

        }

        struct client_info* client = clients;
        time_t current;
        time(&current);

        while (client) {

            struct client_info* next = client->next;
            if (FD_ISSET(client->socket, &reads)) {

                if (MAX_REQUEST_SIZE == client->received) {
                    send_400(client); // todo: maybe 500?
                    continue;
                }

                int r;
                if (client->tls) r = SSL_read(client->ssl, client->request + client->received, MAX_REQUEST_SIZE-client->received);
                else r = recv(client->socket, client->request + client->received, MAX_REQUEST_SIZE-client->received, 0);

                if (r < 1) {
                    printf("Unexpected disconnect from %s\n", get_client_address(client));
                    drop_client(client);
                }
                else {
                    client->received += r;
                    client->request[client->received] = 0;
                    char* q = strstr(client->request, "\r\n\r\n"); // todo: close socket if client doesn't end request, handle post body?
                    if (client) client->last_packet = current;
                    if (q) {
                        handle_request(client, client->request, argv[2]);
                    }
                }
            }
            else {
                if (current - client->last_packet > CLIENT_TIMEOUT) {
                    printf("Client timeout %s\n", get_client_address(client));
                    drop_client(client);
                }
            }

            client = next;
        }
    }

    //printf("\nClosing socket\n");
    close(https_server);
    close(http_server);
    SSL_CTX_free(ctx);
    //printf("Finished");
    return 0;
}