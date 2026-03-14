#ifndef CMD5_H
#define CMD5_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>

typedef struct {
  uint32_t state[4];
  uint32_t count[2];
  unsigned char buffer[64];
} cass_md5_ctx;

void cass_md5_initialize(cass_md5_ctx *);
void cass_md5_update(cass_md5_ctx *, unsigned char *, size_t);
void cass_md5_finalize(cass_md5_ctx *, unsigned char *);

#endif
