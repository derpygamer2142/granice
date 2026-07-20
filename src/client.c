#include "client.h"

struct client_info* clients = 0;
struct timeval CLIENT_WAIT_TIMEOUT;

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
    close(client->socket);
    SSL_shutdown(client->ssl);
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

    CLIENT_WAIT_TIMEOUT.tv_sec = CLIENT_TIMEOUT;
    if (select(max_socket+1, &reads, 0, 0, &CLIENT_WAIT_TIMEOUT) < 0) {
        fprintf(stderr, "select() failed. %s (%d)\n", strerror(errno), errno);
        exit(1);
    }

    return reads;
}