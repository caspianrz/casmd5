#include "cmd5.h"

#include <stdio.h>

static void md5string(unsigned char *input, unsigned char *digest) {
  uint32_t length = strlen((const char *)input);
  cass_md5_ctx context;

  cass_md5_initialize(&context);
  cass_md5_update(&context, input, length);
  cass_md5_finalize(&context, digest);
}

static void md5print(unsigned char digest[16]) {
  unsigned int i;
  for (i = 0; i < 16; i++)
    printf("%02x", (unsigned char)digest[i]);
}

static void cmd5digest_main(int argc, char *argv[]) {
  unsigned char out[16];
  md5string((unsigned char *)argv[1], out);
  md5print(out);
}

int main(int argc, char *argv[]) {
  cmd5digest_main(argc, argv);
  return 0;
}
