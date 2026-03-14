#include "cmd5.h"

static inline const uint32_t rotate_left(const uint32_t x, const uint8_t n) {
  return (x << n) | (x >> (32 - n));
}

static inline const uint32_t F(const uint32_t x, const uint32_t y,
                               const uint32_t z) {
  return (x & y) | ((~x) & z);
}

static inline const uint32_t G(const uint32_t x, const uint32_t y,
                               const uint32_t z) {
  return (x & z) | (y & (~z));
}

static inline const uint32_t H(const uint32_t x, const uint32_t y,
                               const uint32_t z) {
  return x ^ y ^ z;
}

static inline const uint32_t I(const uint32_t x, const uint32_t y,
                               const uint32_t z) {
  return y ^ (x | (~z));
}

/**
 * All FF, GG, HH, II functions are just same instruction applied with F,G,H,I.
 * so we just pass F,G,H,I as parameter and use the same function for all
 * rounds.
 */
static inline const uint32_t
R(const uint32_t (*func)(const uint32_t, const uint32_t, const uint32_t),
  const uint32_t a, const uint32_t b, const uint32_t c, const uint32_t d,
  const uint32_t x, const uint8_t s, const uint32_t ac) {
  return rotate_left(a + func(b, c, d) + x + ac, s) + b;
}

static unsigned char PADDING[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

static void _decode(uint32_t *output, unsigned char *input, uint32_t len) {
  unsigned int i, j;
  for (i = 0, j = 0; j < len; i++, j += 4)
    output[i] = ((uint32_t)input[j]) | (((uint32_t)input[j + 1]) << 8) |
                (((uint32_t)input[j + 2]) << 16) |
                (((uint32_t)input[j + 3]) << 24);
}

void cass_md5_transform(cass_md5_ctx *ctx, unsigned char block[64]) {
  uint32_t aa = ctx->state[0], bb = ctx->state[1], cc = ctx->state[2],
           dd = ctx->state[3];
  uint32_t x[16];

  _decode(x, block, 64);

  // Round 1
  aa = R(F, aa, bb, cc, dd, x[0], 7, 0xd76aa478);
  dd = R(F, dd, aa, bb, cc, x[1], 12, 0xe8c7b756);
  cc = R(F, cc, dd, aa, bb, x[2], 17, 0x242070db);
  bb = R(F, bb, cc, dd, aa, x[3], 22, 0xc1bdceee);
  aa = R(F, aa, bb, cc, dd, x[4], 7, 0xf57c0faf);
  dd = R(F, dd, aa, bb, cc, x[5], 12, 0x4787c62a);
  cc = R(F, cc, dd, aa, bb, x[6], 17, 0xa8304613);
  bb = R(F, bb, cc, dd, aa, x[7], 22, 0xfd469501);
  aa = R(F, aa, bb, cc, dd, x[8], 7, 0x698098d8);
  dd = R(F, dd, aa, bb, cc, x[9], 12, 0x8b44f7af);
  cc = R(F, cc, dd, aa, bb, x[10], 17, 0xffff5bb1);
  bb = R(F, bb, cc, dd, aa, x[11], 22, 0x895cd7be);
  aa = R(F, aa, bb, cc, dd, x[12], 7, 0x6b901122);
  dd = R(F, dd, aa, bb, cc, x[13], 12, 0xfd987193);
  cc = R(F, cc, dd, aa, bb, x[14], 17, 0xa679438e);
  bb = R(F, bb, cc, dd, aa, x[15], 22, 0x49b40821);

  // Round 2
  aa = R(G, aa, bb, cc, dd, x[1], 5, 0xf61e2562);
  dd = R(G, dd, aa, bb, cc, x[6], 9, 0xc040b340);
  cc = R(G, cc, dd, aa, bb, x[11], 14, 0x265e5a51);
  bb = R(G, bb, cc, dd, aa, x[0], 20, 0xe9b6c7aa);
  aa = R(G, aa, bb, cc, dd, x[5], 5, 0xd62f105d);
  dd = R(G, dd, aa, bb, cc, x[10], 9, 0x2441453);
  cc = R(G, cc, dd, aa, bb, x[15], 14, 0xd8a1e681);
  bb = R(G, bb, cc, dd, aa, x[4], 20, 0xe7d3fbc8);
  aa = R(G, aa, bb, cc, dd, x[9], 5, 0x21e1cde6);
  dd = R(G, dd, aa, bb, cc, x[14], 9, 0xc33707d6);
  cc = R(G, cc, dd, aa, bb, x[3], 14, 0xf4d50d87);
  bb = R(G, bb, cc, dd, aa, x[8], 20, 0x455a14ed);
  aa = R(G, aa, bb, cc, dd, x[13], 5, 0xa9e3e905);
  dd = R(G, dd, aa, bb, cc, x[2], 9, 0xfcefa3f8);
  cc = R(G, cc, dd, aa, bb, x[7], 14, 0x676f02d9);
  bb = R(G, bb, cc, dd, aa, x[12], 20, 0x8d2a4c8a);

  // Round 3
  aa = R(H, aa, bb, cc, dd, x[5], 4, 0xfffa3942);
  dd = R(H, dd, aa, bb, cc, x[8], 11, 0x8771f681);
  cc = R(H, cc, dd, aa, bb, x[11], 16, 0x6d9d6122);
  bb = R(H, bb, cc, dd, aa, x[14], 23, 0xfde5380c);
  aa = R(H, aa, bb, cc, dd, x[1], 4, 0xa4beea44);
  dd = R(H, dd, aa, bb, cc, x[4], 11, 0x4bdecfa9);
  cc = R(H, cc, dd, aa, bb, x[7], 16, 0xf6bb4b60);
  bb = R(H, bb, cc, dd, aa, x[10], 23, 0xbebfbc70);
  aa = R(H, aa, bb, cc, dd, x[13], 4, 0x289b7ec6);
  dd = R(H, dd, aa, bb, cc, x[0], 11, 0xeaa127fa);
  cc = R(H, cc, dd, aa, bb, x[3], 16, 0xd4ef3085);
  bb = R(H, bb, cc, dd, aa, x[6], 23, 0x4881d05);
  aa = R(H, aa, bb, cc, dd, x[9], 4, 0xd9d4d039);
  dd = R(H, dd, aa, bb, cc, x[12], 11, 0xe6db99e5);
  cc = R(H, cc, dd, aa, bb, x[15], 16, 0x1fa27cf8);
  bb = R(H, bb, cc, dd, aa, x[2], 23, 0xc4ac5665);

  // Round 4
  aa = R(I, aa, bb, cc, dd, x[0], 6, 0xf4292244);
  dd = R(I, dd, aa, bb, cc, x[7], 10, 0x432aff97);
  cc = R(I, cc, dd, aa, bb, x[14], 15, 0xab9423a7);
  bb = R(I, bb, cc, dd, aa, x[5], 21, 0xfc93a039);
  aa = R(I, aa, bb, cc, dd, x[12], 6, 0x655b59c3);
  dd = R(I, dd, aa, bb, cc, x[3], 10, 0x8f0ccc92);
  cc = R(I, cc, dd, aa, bb, x[10], 15, 0xffeff47d);
  bb = R(I, bb, cc, dd, aa, x[1], 21, 0x85845dd1);
  aa = R(I, aa, bb, cc, dd, x[8], 6, 0x6fa87e4f);
  dd = R(I, dd, aa, bb, cc, x[15], 10, 0xfe2ce6e0);
  cc = R(I, cc, dd, aa, bb, x[6], 15, 0xa3014314);
  bb = R(I, bb, cc, dd, aa, x[13], 21, 0x4e0811a1);
  aa = R(I, aa, bb, cc, dd, x[4], 6, 0xf7537e82);
  dd = R(I, dd, aa, bb, cc, x[11], 10, 0xbd3af235);
  cc = R(I, cc, dd, aa, bb, x[2], 15, 0x2ad7d2bb);
  bb = R(I, bb, cc, dd, aa, x[9], 21, 0xeb86d391);

  ctx->state[0] += aa;
  ctx->state[1] += bb;
  ctx->state[2] += cc;
  ctx->state[3] += dd;

  memset(x, 0, sizeof(x));
}

void cass_md5_initialize(cass_md5_ctx *ctx) {
  memset(ctx->buffer, 0, 64);
  ctx->count[0] = ctx->count[1] = 0;
  ctx->state[0] = 0x67452301;
  ctx->state[1] = 0xEFCDAB89;
  ctx->state[2] = 0x98BADCFE;
  ctx->state[3] = 0x10325476;
}

void cass_md5_update(cass_md5_ctx *ctx, unsigned char *input, size_t length) {
  uint32_t index = (ctx->count[0] >> 3) & 0x3F;
  uint32_t part_len = 0;

  /* Update number of bits */
  if ((ctx->count[0] += (length << 3)) < (length << 3)) {
    ctx->count[1]++;
  }
  ctx->count[1] += (length >> 29);

  part_len = 64 - index;

  uint32_t i = 0;
  if (length >= part_len) {
    memcpy(&ctx->buffer[index], input, part_len);
    cass_md5_transform(ctx, ctx->buffer);
    for (i = part_len; i + 63 < length; i += 64)
      cass_md5_transform(ctx, &input[i]);
    index = 0;
  } else {
    i = 0;
  }

  /* Buffer remaining input */
  memcpy(&ctx->buffer[index], &input[i], length - i);
}

static void _encode(unsigned char *output, uint32_t *input, uint32_t len) {
  unsigned int i, j;
  for (i = 0, j = 0; j < len; i++, j += 4) {
    output[j] = (unsigned char)(input[i] & 0xff);
    output[j + 1] = (unsigned char)((input[i] >> 8) & 0xff);
    output[j + 2] = (unsigned char)((input[i] >> 16) & 0xff);
    output[j + 3] = (unsigned char)((input[i] >> 24) & 0xff);
  }
}

void cass_md5_finalize(cass_md5_ctx *ctx, unsigned char digest[16]) {
  unsigned char bits[8];
  uint32_t index, pad_len;

  _encode(bits, ctx->count, 8);

  index = (ctx->count[0] >> 3) & 0x3f;
  pad_len = (index < 56) ? (56 - index) : (120 - index);

  cass_md5_update(ctx, PADDING, pad_len);

  cass_md5_update(ctx, bits, 8);

  _encode(digest, ctx->state, 16);

  memset(ctx, 0, sizeof (*ctx));
}
