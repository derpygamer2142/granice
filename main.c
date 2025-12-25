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

// openssl stuff
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_REQUEST_SIZE 65535

struct client_info {
    socklen_t address_length;
    struct sockaddr_storage address;
    int socket;
    char request[MAX_REQUEST_SIZE + 1];
    int received;
    struct client_info *next;
};

static struct client_info* clients = 0;

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

void drop_client(struct client_info* client) {
    close(client->socket);

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

fd_set wait_on_clients(int server) {
    fd_set reads;
    FD_ZERO(&reads);
    FD_SET(server, &reads);
    int max_socket = server;

    struct client_info* ci = clients;
    while (ci) {
        FD_SET(ci->socket, &reads);
        if (ci->socket > max_socket) max_socket = ci->socket;
        ci = ci->next;
    }

    if (select(max_socket+1, &reads, 0, 0, 0) < 0) {
        fprintf(stderr, "select() failed. (%d)\n", errno);
        exit(1);
    }

    return reads;
}

void send_400(struct client_info* client) {
    printf("sent 400\n");
    const char* text = "HTTP/1.1 400 Bad Request\r\n"
                       "Connection: close\r\n"
                       "Content-Length: 11\r\n\r\nBad Request";
    send(client->socket, text, strlen(text), 0); // todo: queue this?
    drop_client(client);
}

void send_404(struct client_info* client) {
    printf("sent 404\n");
    const char* text = "HTTP/1.1 404 Not Found\r\n"
                       "Connection: close\r\n"
                       "Content-Length: 9\r\n\r\nNot Found";
    send(client->socket, text, strlen(text), 0); // todo: queue this?
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
    }

    return "application/octet-stream";
}

void serve_resource(struct client_info* client, const char* path) {
    // todo: queue this?
    // cache files
    printf("serve_resource %s %s\n", get_client_address(client), path);

    if (strcmp(path, "/") == 0) path = "/index.html";
    if (strlen(path) > 100) return send_400(client);
    if (strstr(path, "..")) return send_404(client);

    char full_path[128];
    sprintf(full_path, "public%s", path);

    FILE* fp = fopen(full_path, "rb");

    if (!fp) return send_404(client);
    fseek(fp, 0L, SEEK_END);
    size_t content_length = ftell(fp);
    rewind(fp);
    const char* content_type = get_content_type(full_path);

    #define BSIZE 1024
    char buffer[BSIZE];
    
    // this is not a good way to do this
    sprintf(buffer, "HTTP/1.1 200 OK\r\n");
    send(client->socket, buffer, strlen(buffer), 0);

    sprintf(buffer, "Connection: close\r\n");
    send(client->socket, buffer, strlen(buffer), 0);
    
    sprintf(buffer, "Content-Length: %lu\r\n", content_length);
    send(client->socket, buffer, strlen(buffer), 0);

    sprintf(buffer, "Content-Type: %s\r\n", content_type);
    send(client->socket, buffer, strlen(buffer), 0);

    sprintf(buffer, "\r\n");
    send(client->socket, buffer, strlen(buffer), 0);

    // bad
    int r = fread(buffer, 1, BSIZE, fp);
    while (r) {
        send(client->socket, buffer, r, 0);
        r = fread(buffer, 1, BSIZE, fp);
    }

    fclose(fp);
    drop_client(client);
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
        fprintf(stderr, "socket() failed. (%d)\n", errno);
        exit(1);
    }

    // this makes it so ipv4 gets mapped to ipv6
    // doesn't work on wsl so i can't test it
    /*int option = 0;
    if (setsockopt(socket_listen, IPPROTO_IPV6, IPV6_V6ONLY, (void*)&option, sizeof(option))) {
        fprintf(stderr, "setsockopt() failed. (%d)\n", errno);
        exit(1);
    }*/

    printf("Binding socket\n");
    if (bind(socket_listen, bind_address->ai_addr, bind_address->ai_addrlen)) {
        fprintf(stderr, "bind( failed. (%d)\n", errno);
        exit(1);
    }
    freeaddrinfo(bind_address);

    printf("Now listening\n");
    if (listen(socket_listen, 10)) {
        fprintf(stderr, "listen() failed. (%d)\n", errno);
        exit(1);
    }

    return socket_listen;
}

int main() {
    int server = create_socket(0, "8080");

    while (1) {
        fd_set reads;
        reads = wait_on_clients(server);

        if (FD_ISSET(server, &reads)) {
            struct client_info* client = get_client(-1);

            client->socket = accept(server,
                (struct sockaddr*) &(client->address),
                &client->address_length
            );

            if (client->socket < 0) {
                fprintf(stderr, "accept() failed. (%d)\n", errno);
                return 1;
            }

            printf("New connection from %s\n", get_client_address(client));
        }

        struct client_info* client = clients;

        while (client) {

            struct client_info* next = client->next;
            if (FD_ISSET(client->socket, &reads)) {

                if (MAX_REQUEST_SIZE == client->received) {
                    send_400(client); // todo: maybe 500?
                    continue;
                }
                int r = recv(client->socket, client->request + client->received, MAX_REQUEST_SIZE-client->received, 0);


                if (r < 1) {
                    printf("Unexpected disconnect from %s\n", get_client_address(client));
                    drop_client(client);
                }
                else {
                    client->received += r;
                    client->request[client->received] = 0;
                    char* q = strstr(client->request, "\r\n\r\n");
                    if (q) {
                        if (strncmp("GET /", client->request, 5)) {
                            send_400(client);
                        }
                        else {
                            char* path = client->request + 4;
                            char* end_path = strstr(path, " ");
                            if (!end_path) {
                                send_400(client);
                            }
                            else {
                                *end_path = 0;
                                serve_resource(client, path);
                            }
                        }
                    }

                }
            }

            client = next;
        }
    }

    printf("\nClosing socket\n");
    close(server);
    printf("Finished");
    return 0;
}