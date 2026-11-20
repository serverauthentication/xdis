#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t *data;
    uint64_t size;
    void    *fh;
    void    *mh;
    int      writable;
    int      owned;
} map_file;

bool map_open(map_file *m, const char *path);
bool map_open_buf(map_file *m, uint8_t *buf, uint64_t size, int take_owner);
void map_close(map_file *m);
