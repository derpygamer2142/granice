#ifndef COMPRESSION_WRAPPERS
#define COMPRESSION_WRAPPERS

#include <stdio.h>
#include <stdlib.h>
#include <zlib.h>
#include <assert.h>
#include <string.h>

#define CHUNK 16384

char* zlibGzip(char* input, unsigned int size, size_t* outSize) {
    // based on https://zlib.net/zpipe.c
    z_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree  = Z_NULL;
    stream.opaque = Z_NULL;
    int ret = deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);

    if (ret != Z_OK) {
        fprintf(stderr, "Deflate init error\n");
    }

    size_t max = compressBound(size);
    unsigned char* out = (unsigned char*)malloc(max);

    stream.next_in = (unsigned char*)input;
    stream.avail_in = size;
    stream.next_out = out;
    stream.avail_out = max;

    ret = deflate(&stream, Z_FINISH);
    //assert(ret == Z_STREAM_END); // maybe don't do this

    *outSize = stream.total_out;
    deflateEnd(&stream);

    //printf("Went from %u to %u bytes\n", size, (unsigned int)stream.total_out);

    return (char*)out;
}

#endif