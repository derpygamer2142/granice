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
};

struct parsed_request {
    char* path;
    char* method;
    char* body;
    // todo: headers
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
    clients = n;
    return n;
}

void drop_client(struct client_info* client, int dry) {
    //if (handshake_successful) SSL_shutdown(client->ssl);
    if (!dry) {
        close(client->socket);
        SSL_free(client->ssl);
    }

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

    if (select(max_socket+1, &reads, 0, 0, 0) < 0) {
        fprintf(stderr, "select() failed. %s (%d)\n", strerror(errno), errno);
        exit(1);
    }

    return reads;
}

void send_400(struct client_info* client) {
    printf("sent 400\n");
    const char* text = "HTTP/1.1 400 Bad Request\r\n"
                       "Connection: close\r\n"
                       "Content-Length: 11\r\n\r\nBad Request";
    if (client->tls) SSL_write(client->ssl, text, strlen(text)); // todo: queue this?
    else send(client->socket, text, strlen(text), 0);
    drop_client(client, 0);
}

void send_404(struct client_info* client) {
    printf("sent 404\n");
    const char* text = "HTTP/1.1 404 Not Found\r\n"
                       "Connection: close\r\n"
                       "Content-Length: 9\r\n\r\nNot Found";
    if (client->tls) SSL_write(client->ssl, text, strlen(text)); // todo: queue this?
    else send(client->socket, text, strlen(text), 0);
    drop_client(client, 0);
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
    }

    return "application/octet-stream";
}

/*
 * returns 0 if response not sent
 * returns 1 if response sent
*/
int serve_directory(char* directory, struct client_info* client, char* path) {
    // todo: queue this?
    // cache files
    printf("serve_resource %s %s\n", get_client_address(client), path);
    int shouldfree = 0;

    if (strcmp(path, "/") == 0) path = "/index.html";
    if (strrchr(path, '.') <= strrchr(path, '/')) {
        char* temppath = malloc(strlen(path) + strlen(".html") + 1);
        strcpy(temppath, path);
        strcat(temppath, ".html");
        printf("Correcting path %s to %s\n", path, temppath);
        path = temppath;
        printf("Path: %s\n", path);
        shouldfree = 1;
    }
    if (strlen(path) > 100) { // too long, ignore
        if (shouldfree) free(path);
        send_400(client);
        return 1;
    }
    if (strstr(path, "..")) { // cringe path traversal attempt
        if (shouldfree) free(path);
        send_400(client);
        return 1;
    }

    char full_path[128];
    sprintf(full_path, "%s%s", directory, path);
    if (shouldfree) free(path); // we don't need to know the path anymore

    FILE* fp = fopen(full_path, "rb");

    if (!fp) {
        printf("Not found\n");
        // don't need to close the file point because it wasn't created?
        return 0;
    }

    if (!fork()) {
        fseek(fp, 0L, SEEK_END);
        size_t content_length = ftell(fp);
        rewind(fp);
        const char* content_type = get_content_type(full_path);

        #define BSIZE 2048
        char headers[BSIZE] = "HTTP/1.1 200 OK\r\n"
                            "Connection: close\r\n";
        // this seems like a weird way to do this
        
        sprintf(headers+strlen(headers), "Content-Length: %lu\r\nContent-Type: %s\r\n\r\n", content_length, content_type);

        char* buffer = malloc(strlen(headers)+content_length+1);
        strcpy(buffer, headers);

        // bad?
        fread(buffer+strlen(buffer), content_length, 1, fp);
        strcat(buffer, "\0");
        //printf("Response: %s\n", buffer);
        if (client->tls) {
            SSL_write(client->ssl, buffer, strlen(buffer));
        }
        else {
            send(client->socket, buffer, strlen(buffer), 0);
        }

        free(buffer);
        fclose(fp);
        drop_client(client, 0);
        exit(0); // todo: this might be preserving client socket connections longer than needed. need to check on that.
    }
    else {
        // socket will be closed by the child process
        // only remove from list, don't actually close it
        drop_client(client, 1);
        return 1;
    }
}

int create_socket(const char* host, const char* port) {
    printf("Configuring local address\n");
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    
    struct addrinfo *bind_address;
    getaddrinfo(host, port, &hints, &bind_address);

    printf("Creating socket\n");
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

    printf("Binding socket\n");
    if (bind(socket_listen, bind_address->ai_addr, bind_address->ai_addrlen)) {
        fprintf(stderr, "bind() failed. %s (%d)\n", strerror(errno), errno);
        exit(1);
    }
    freeaddrinfo(bind_address);

    printf("Now listening\n");
    if (listen(socket_listen, 10)) {
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
    printf("Request: %s\n", http_request);
    int space = strcspn(http_request, " ");
    if (space == strlen(http_request)) {
        return 0;
        send_400(client);
    }
    char* method = malloc(space + 1);
    method[space] = '\0'; // terminate method string
    strncpy(method, http_request, space);
    printf("Method: %s\n", method);

    http_request += space+1;
    space = strcspn(http_request, " \n");
    char* path = malloc(space + 1);
    strncpy(path, http_request, space);
    path[space] = '\0'; // terminate path string
    printf("Path: %s\n", path);

    parsed->body = strstr(http_request,"\r\n\r\n")+4;
    parsed->method = method;
    parsed->path = path;

    printf("Body: %s\n", parsed->body);
    return parsed;
}

void handle_request(struct client_info* client, char* request) { // request is null terminated
    struct parsed_request* parsed = parse_request(client, request);
    if (!parsed) return;

    if (strncmp("/", parsed->path, 1)) {
        send_400(client);
    }
    else {
        if (!serve_directory("public", client, parsed->path)) {
            send_404(client);
        }
    }
}

int main() {

    signal(SIGPIPE, SIG_IGN);

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        fprintf(stderr, "SSL_CTX_new() failed\n");
        return 1;
    }
    if (!SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM)
    || !SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM)) {
        fprintf(stderr, "SSL_CTX_use_certificate_file() failed\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }


    int https_server = create_socket(0, "443");
    int http_server  = create_socket(0, "80");

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


                drop_client(client, 0);
            }
            else {
                printf("New https connection from %s, using SSL %s\n", get_client_address(client), SSL_get_cipher(client->ssl));
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

            printf("New http connection from %s\n", get_client_address(client));

        }

        struct client_info* client = clients;

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
                    drop_client(client, 0);
                }
                else {
                    client->received += r;
                    client->request[client->received] = 0;
                    char* q = strstr(client->request, "\r\n\r\n"); // todo: close socket if client doesn't end request
                    if (q) {
                        handle_request(client, client->request);
                    }

                }
            }

            client = next;
        }
    }

    printf("\nClosing socket\n");
    close(https_server);
    close(http_server);
    SSL_CTX_free(ctx);
    printf("Finished");
    return 0;
}