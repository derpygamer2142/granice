#include "http_wrapper.h"

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