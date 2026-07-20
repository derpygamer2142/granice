#ifndef CLIENT_H
#define CLIENT_H

#include <sys/socket.h>
#include <openssl/ssl.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>

#include <sys/select.h>


// max time since last packet, in seconds
#define CLIENT_TIMEOUT 8

#pragma once
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

extern struct client_info* clients;

struct client_info* get_client(int socket);

void drop_client(struct client_info* client);

const char* get_client_address(struct client_info* ci);

fd_set wait_on_clients(int https, int http);

#endif