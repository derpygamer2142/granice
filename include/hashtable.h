#ifndef HASH_TABLE

#define HASH_TABLE
#include "include/superfasthash.h"
#include <stdlib.h>
#include <string.h>

#include <stdio.h>

// I don't know what the difference is between a hash map and a hash table
// am I using this term right

// Semi arbitrary load size, if this is exceeded then the table will be expanded.
#define LOAD_SIZE 0.75

// An entry in the hash table, which stores the key for lookup and a pointer to the value.
typedef struct {
    uint32_t key;
    void* value;
    unsigned int index; // index in the entry list
} HashEntry;

// A generic hash table data structure.
typedef struct {
    HashEntry** data;
    unsigned int size;
    unsigned int used;
    HashEntry** entries; // for linear lookup
} HashTable;

// Initialize a hash table with an initial size of start_size. If start_size is 0, it will default to an arbitrary one.
HashTable* hash_table_init(unsigned int start_size) {
    if (start_size == 0) start_size = 67; // 67 is a prime number and therefore it should be efficient
    HashTable* table = (HashTable*) calloc(1, sizeof(HashTable));
    table->size = start_size;
    table->used = 0;
    HashEntry** dataArray = (HashEntry**)calloc(start_size, sizeof(HashEntry*));
    table->data = dataArray;

    table->entries = (HashEntry**) calloc(start_size, sizeof(HashEntry*));

    return table;
}

// Free memory used by a given hash table, and optionally free() all values stored in hash table entries.
void destroy_hash_table(HashTable* table, int free_entries) {
    for (int i = 0; i < table->used; i++) {
        if (table->entries[i]) {
            if (free_entries) free(table->entries[i]->value); // free() all non-null values in the hash table.
            free(table->entries[i]);
        }
    }
    

    free(table->data); // free the table data
    free(table->entries); // free entry list
    free(table); // free the table itself
}

// Store a value at a given pre-hashed key in a hash table. Returns the number of used entries. Does not resize, returns 0 for error. Internal.
unsigned int _hash_store_prehashed(HashTable* table, uint32_t hashResult, void* value) {
    uint32_t index = hashResult % table->size;
    HashEntry** data = table->data;

    if (data[index]) {
        // check for collision
        if (data[index]->key == hashResult) {
            // no collision, can be overwritten
            table->data[index]->value = value;
        }
        else {
            // collision
            // look for the next open spot
            while (data[index]) {
                if (data[index]->key == hashResult) {
                    // found the correct entry, can be overwritten
                    data[index]->value = value;
                    break;
                }

                index++;
                if (index >= table->size) {
                    // overflow, need to resize allocated memory
                    return 0; // failed
                }
            }

            if (!data[index]) {

                data[index] = (HashEntry*) calloc(1, sizeof(HashEntry)); // new entry

                data[index]->key = hashResult;
                data[index]->value = value;
                data[index]->index = table->used;

                table->entries[table->used] = data[index];

                table->used++;

            }
        }
    }
    else {
        data[index] = (HashEntry*) calloc(1, sizeof(HashEntry)); // new entry
        data[index]->key = hashResult;
        data[index]->value = value;
        data[index]->index = table->used;
        
        table->entries[table->used] = data[index];
        
        table->used++;
    }

    return table->used;
}

// Resize an existing hash table. Doubles plus one the size because why not. Does not preserves entry references.
int resize_hash_table(HashTable* table) {

    int originalSize = table->size;
    HashEntry** newData = (HashEntry**) calloc(originalSize*2 + 1, sizeof(HashEntry*)); // double the size plus one
    free(table->data);
    table->data = newData; // this shouldn't leak memory?
    table->size = originalSize*2 + 1; // update size
    unsigned int tempUsed = table->used;
    table->used = 0;

    // very small optimization, but use malloc instead of calloc
    // because we don't care about the memory being zeroed
    // since the initialized memory is being copied anyways
    HashEntry** newEntries = (HashEntry**) malloc(table->size * sizeof(HashEntry*));
    HashEntry** oldEntries = table->entries;
    table->entries = newEntries;


    // copy entries to new data
    for (int i = 0; i < tempUsed; i++) {
        if (oldEntries[i])
            if (!_hash_store_prehashed(table, oldEntries[i]->key, oldEntries[i]->value)) {
                // avoid the annoying edge case that we hit another overflow while resizing
                i = -1;
                originalSize = table->size;
                HashEntry** newData = (HashEntry**) calloc(originalSize*2 + 1, sizeof(HashEntry*)); // double the size plus one

                free(table->data);
                table->data = newData; // this shouldn't leak memory?
                table->size = originalSize*2 + 1; // update size

                // very small optimization, but use malloc instead of calloc
                // because we don't care about the memory being zeroed
                // since the initialized memory is being copied anyways
                HashEntry** newEntries = (HashEntry**) malloc(table->size * sizeof(HashEntry*));

                for (int i = 0; i < table->used; i++) {
                    free(table->entries[i]);
                }
                free(table->entries); // this is pointing to an unused piece of memory, so we can free it

                table->entries = newEntries;
                table->used = 0;
            }
    }

    for (int i = 0; i < tempUsed; i++) {
        free(oldEntries[i]);
    }

    free(oldEntries);

    return table->size;
}

// Store a value at a given key in a hash table, where key is len bytes long. Returns the number of used entries.
unsigned int hash_store(HashTable* table, char* key, int len, void* value) {
    uint32_t hashResult = SuperFastHash(key, len);
    unsigned int ret = _hash_store_prehashed(table, hashResult, value);
    while (!ret) {
        resize_hash_table(table);
        ret = _hash_store_prehashed(table, hashResult, value);
    }
    if ((1.0*table->used / table->size) > LOAD_SIZE) {
        // table usage exceeds the load size, resize
        resize_hash_table(table);
    }
    return ret;
}

// Get the value stored at a given key of length len in a hash table.
void* hash_get(HashTable* table, char* key, int len) {
    uint32_t hashResult = SuperFastHash(key, len);
    uint32_t index = hashResult % table->size;
    HashEntry** data = table->data;

    while (index < table->size) {
        if (data[index]) {
                if (data[index]->key != hashResult) index++;
                else {
                    break;
                }
            }
        else return 0;
    }

    if (index >= table->size) {
        return 0; // not present
    }

    return data[index]->value;
}

// Removes the value of a given key and optionally free the value. Returns the value.
// Does not change the number of used entries because that would be difficult.
void* hash_remove(HashTable* table, char* key, int len, int freeValue) {
    uint32_t hashResult = SuperFastHash(key, len);
    uint32_t index = hashResult % table->size;
    HashEntry** data = table->data;

    while (index < table->size) {
        if (data[index]) {
            if (data[index]->key == hashResult) break;
        }
        else index = table->size;
        index++;
    }

    if (index >= table->size) {
        return 0; // not present
    }

    table->entries[data[index]->index] = 0;

    void* oldValue = data[index]->value;
    if (freeValue) free(data[index]->value);
    free(data[index]);
    
    data[index] = 0;

    return oldValue;
}

#endif