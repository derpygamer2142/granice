#ifndef HTTP_WRAPPER
#define HTTP_WRAPPER
#include "client.h"
#include <stdlib.h>

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

void send_400(struct client_info* client);

void send_404(struct client_info* client);

void send_501(struct client_info* client);

void send_uncached(struct client_info* client, char* response, int length);

const char* get_content_type(const char* path);

struct header_list* get_headers(char* request);

void free_headers(struct header_list* headers);

char* get_header_value(struct header_list* headers, char* header);

// Todo: store error codes to get rid of side effects
char* sanitize_file_path(char* directory, char* path, struct client_info* client);

struct parsed_request* parse_request(struct client_info* client, char* http_request);

#endif