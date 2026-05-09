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

// max time since last packet, in seconds
#define CLIENT_TIMEOUT 8

#define MAX_REQUEST_SIZE 2048

struct client_info {
    socklen_t address_length;
    struct sockaddr_storage address;
    int socket;
    char request[MAX_REQUEST_SIZE + 1];
    int received;
    struct client_info *next;
    SSL* ssl;
    int tls;
    time_t last_packet;
};

struct header_list {
    char** headers;
    int length;
};

struct parsed_request {
    char* path;
    char* method;
    char* body;
    struct header_list* headers;
};

static struct client_info* clients = 0;
SSL_CTX* ctx;

struct client_info* get_client(int socket) {
    struct client_info* ci = clients;
    while (ci) {
        if (ci->socket == socket) break;
        ci = ci->next;
    }

    if (ci) return ci;

    struct client_info* n = (struct client_info*) calloc(1, sizeof(struct client_info));

    if (!n) {
        fprintf(stderr, "Out of memory.\n");
        exit(1);
    }

    n->address_length = sizeof(n->address);
    n->next = clients;
    time(&n->last_packet);

    clients = n;
    return n;
}

void drop_client(struct client_info* client) {
    //if (handshake_successful) SSL_shutdown(client->ssl);
    close(client->socket);
    SSL_free(client->ssl);
    

    struct client_info** p = &clients;

    while (*p) {
        if (*p == client) {
            *p = client->next;
            free(client);
            return;
        }
        p = &(*p)->next;
    }

    fprintf(stderr, "drop_client not found\n");
    exit(1);
}

const char* get_client_address(struct client_info* ci) {
    static char address_buffer[100];
    getnameinfo((struct sockaddr*)&ci->address, ci->address_length,
                address_buffer, sizeof(address_buffer),
                0, 0,
                NI_NUMERICHOST
    );

    return address_buffer;
}

struct timeval timeout_struct;

fd_set wait_on_clients(int https, int http) {
    fd_set reads;
    FD_ZERO(&reads);
    FD_SET(http,  &reads);
    FD_SET(https, &reads);
    int max_socket = http;
    if (https > max_socket) max_socket = https;

    struct client_info* ci = clients;
    while (ci) {
        FD_SET(ci->socket, &reads);
        if (ci->socket > max_socket) max_socket = ci->socket;
        ci = ci->next;
    }

    if (select(max_socket+1, &reads, 0, 0, &timeout_struct) < 0) {
        fprintf(stderr, "select() failed. %s (%d)\n", strerror(errno), errno);
        exit(1);
    }

    return reads;
}

void send_400(struct client_info* client) {
    // printf("sent 400\n");
    const char* text = "HTTP/1.1 400 Bad Request\r\n"
                       "Connection: close\r\n"
                       "Content-Length: 11\r\n\r\nBad Request";
    if (client->tls) SSL_write(client->ssl, text, strlen(text)); // todo: queue this?
    else send(client->socket, text, strlen(text), 0);
    drop_client(client);
}

void send_404(struct client_info* client) {
    // printf("sent 404\n");
    const char* text = "HTTP/1.1 404 Not Found\r\n"
                       "Connection: close\r\n"
                       "Content-Length: 9\r\n\r\nNot Found";
    if (client->tls) SSL_write(client->ssl, text, strlen(text)); // todo: queue this?
    else send(client->socket, text, strlen(text), 0);
    drop_client(client);
}

void send_501(struct client_info* client) {
    // printf("sent 501\n");
    const char* text = "HTTP/1.1 501 Not Implemented\r\n"
                       "Connection: close\r\n"
                       "Content-Length: 15\r\n\r\nNot Implemented";
    if (client->tls) SSL_write(client->ssl, text, strlen(text)); // todo: queue this?
    else send(client->socket, text, strlen(text), 0);
    drop_client(client);
}

void send_uncached(struct client_info* client, char* response, int length) {
    if (client->tls) SSL_write(client->ssl, response, length); // todo: queue this?
    else send(client->socket, response, length, 0);
    drop_client(client);
}

const char* get_content_type(const char* path) {
    const char* last_dot = strchr(path, '.');
    if (last_dot) {
        if (strcmp(last_dot, ".css") == 0) return "text/css";
        if (strcmp(last_dot, ".csv") == 0) return "text/csv";
        if (strcmp(last_dot, ".gif") == 0) return "image/gif";
        if (strcmp(last_dot, ".htm") == 0) return "text/html";
        if (strcmp(last_dot, ".html") == 0) return "text/html";
        if (strcmp(last_dot, ".ico") == 0) return "image/x-icon";
        if (strcmp(last_dot, ".jpeg") == 0) return "image/jpeg";
        if (strcmp(last_dot, ".jpg") == 0) return "image/jpeg";
        if (strcmp(last_dot, ".js") == 0) return "application/javascript";
        if (strcmp(last_dot, ".json") == 0) return "application/json";
        if (strcmp(last_dot, ".png") == 0) return "image/png";
        if (strcmp(last_dot, ".pdf") == 0) return "application/pdf";
        if (strcmp(last_dot, ".svg") == 0) return "image/svg+xml";
        if (strcmp(last_dot, ".txt") == 0) return "text/plain";
        if (strcmp(last_dot, ".md") == 0) return "text/markdown";
    }

    return "application/octet-stream";
}

struct header_list* get_headers(char* request) {
    #define MAX_HEADERS 67
    // this highkirkuinely might leak a whole lot of memory if it doesn't get freed properly
    char** headers = calloc(MAX_HEADERS, sizeof(char*)); // completely arbitrary
    int i = 0;
    while (i < MAX_HEADERS) {
        char* next = strstr(request, "\r\n");
        if (next == request || i == MAX_HEADERS-1) { 
            struct header_list* retobj = calloc(1, sizeof(struct header_list));
            retobj->headers = headers;
            retobj->length = i;
            return retobj; // next newline is right after the current pointer, that's the start of the body
        }

        char* temp = malloc(1 + next-request);
        temp[next-request] = '\0'; // terminate string

        strncpy(temp, request, next-request);
        headers[i] = temp;
        //printf("Extracted header: %s\n", temp);
        request = next+2;
        i++;
    }
}

void free_headers(struct header_list* headers) {
    if (!headers) return;
    for (int i = 0; i < headers->length; i++) {
        free(headers->headers[i]);
    }
    free(headers->headers);
    free(headers);
}

char* get_header_value(struct header_list* headers, char* header) {
    // search for the value of header in the headers object
    if (!headers) return 0;

    int headerlen = strlen(header);
    for (int i = 0; i < headers->length; i++) {
        int actual = strlen(headers->headers[i]);
        if (!strncasecmp(headers->headers[i], header, headerlen)) {
            if (actual >= headerlen+2) return headers->headers[i]+headerlen+2;
            return 0;
        }
    }

    return 0;
}

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

char* sanitize_file_path(char* directory, char* path, struct client_info* client) {
    int shouldfree = 0;

    if (strcmp(path, "/") == 0) path = "/index.html";
    int pathlen = strlen(path);
    if (path[pathlen-1] == '/') {
        path[pathlen-1] = '\0';
    }
    if (strrchr(path, '.') <= strrchr(path, '/')) {
        char* temppath = malloc(strlen(path) + strlen(".html") + 1);
        strcpy(temppath, path);
        strcat(temppath, ".html");
        //printf("Correcting path %s to %s\n", path, temppath);
        path = temppath;
        //printf("Path: %s\n", path);
        shouldfree = 1;
    }
    if (strlen(path) > 100) { // too long, ignore
        if (shouldfree) free(path);
        send_400(client);
        return 0;
    }
    if (strstr(path, "..")) { // cringe path traversal attempt
        if (shouldfree) free(path);
        send_400(client);
        return 0;
    }

    char* full_path = malloc(128);
    sprintf(full_path, "%s%s", directory, path);
    if (shouldfree) free(path); // we don't need to know the path anymore

    return full_path;
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

struct parsed_request* parse_request(struct client_info* client, char* http_request) {
    struct parsed_request* parsed = (struct parsed_request*) calloc(1, sizeof(struct parsed_request));
    if (!parsed) {
        fprintf(stderr, "Out of memory.\n");
        exit(1);
    }

    char* original = http_request;
    int space = strcspn(http_request, " \r\n"); // get the number of characters to the next space or newline
    // we check for newline as well to make sure we don't overflow to the next line
    if (space == strlen(http_request)) { // if there isn't any, malformed request
        send_400(client);
        free(parsed);
        return 0;
    }
    int nline = strcspn(http_request, "\r\n");
    if (nline == space) { // if we made it to the end of the line without seeing a space then it's malformed
        send_400(client);
        free(parsed);
        return 0;
    }
    char* method = malloc(space + 1);
    method[space] = '\0'; // terminate method string
    strncpy(method, http_request, space);

    http_request += space+1;
    space = strcspn(http_request, " \r\n"); // get the number of characters to the next space
    nline = strstr(http_request, "\r\n")-http_request;
    if (space == strlen(http_request)) { // if there isn't one, it's missing the path
        send_400(client);
        free(method);
        free(parsed);
        return 0;
    }
    if (nline == space) { // same as before, still on the same line
        send_400(client);
        free(method);
        free(parsed);
        return 0;
    }
    char* path = malloc(space + 1);
    strncpy(path, http_request, space);
    path[space] = '\0'; // terminate path string

    http_request += space;
    char* next = strstr(http_request, "\r\n"); // get the next line in the request, we don't care about the second part(it's the http version)
    // can't use nline for this becaus it could be \r or \n
    if (next) http_request = next+2;
    if (http_request[0] == '\r' || http_request[0] == '\n' || http_request[0] == ' ' || http_request[0] == '\0') {
        // there aren't any headers, this line is immediately followed by an empty line or something
        parsed->headers = 0;
    }
    else {
        parsed->headers = get_headers(http_request);
        
        /*char* user_agent = get_header_value(parsed->headers, "User-Agent");
        if (user_agent) printf("User agent: %s\n", user_agent); // debug
        else printf("Couldn't find user agent!\n");*/
    }
    


    parsed->body = strstr(http_request,"\r\n\r\n")+4; // todo: maybe don't check for body depending on the method?
    parsed->method = method;
    parsed->path = path;

    //printf("Body: %s\n", parsed->body);
    return parsed;
}

void handle_request(struct client_info* client, char* request, char* serve) { // request is null terminated
    // printf("Request %s\n", request);
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
    if (!SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM)
    || !SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM)) {
        fprintf(stderr, "SSL_CTX_use_certificate_file() failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }


    int https_server = create_socket("0.0.0.0", "443");
    int http_server  = create_socket("0.0.0.0", "80");

    responseCache = hash_table_init(0);

    timeout_struct.tv_sec = CLIENT_TIMEOUT;

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