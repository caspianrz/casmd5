#include "cmd5.h"

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static unsigned char PADDING[64] = {
    0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

#define FF(a, b, c, d, x, s, ac)                                               \
  {                                                                            \
    (a) += F((b), (c), (d)) + (x) + (uint32_t)(ac);                            \
    (a) = ROTATE_LEFT((a), (s));                                               \
    (a) += (b);                                                                \
  }
#define GG(a, b, c, d, x, s, ac)                                               \
  {                                                                            \
    (a) += G((b), (c), (d)) + (x) + (uint32_t)(ac);                            \
    (a) = ROTATE_LEFT((a), (s));                                               \
    (a) += (b);                                                                \
  }
#define HH(a, b, c, d, x, s, ac)                                               \
  {                                                                            \
    (a) += H((b), (c), (d)) + (x) + (uint32_t)(ac);                            \
    (a) = ROTATE_LEFT((a), (s));                                               \
    (a) += (b);                                                                \
  }
#define II(a, b, c, d, x, s, ac)                                               \
  {                                                                            \
    (a) += I((b), (c), (d)) + (x) + (uint32_t)(ac);                            \
    (a) = ROTATE_LEFT((a), (s));                                               \
    (a) += (b);                                                                \
  }

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
  FF(aa, bb, cc, dd, x[0], 7, 0xd76aa478);
  FF(dd, aa, bb, cc, x[1], 12, 0xe8c7b756);
  FF(cc, dd, aa, bb, x[2], 17, 0x242070db);
  FF(bb, cc, dd, aa, x[3], 22, 0xc1bdceee);
  FF(aa, bb, cc, dd, x[4], 7, 0xf57c0faf);
  FF(dd, aa, bb, cc, x[5], 12, 0x4787c62a);
  FF(cc, dd, aa, bb, x[6], 17, 0xa8304613);
  FF(bb, cc, dd, aa, x[7], 22, 0xfd469501);
  FF(aa, bb, cc, dd, x[8], 7, 0x698098d8);
  FF(dd, aa, bb, cc, x[9], 12, 0x8b44f7af);
  FF(cc, dd, aa, bb, x[10], 17, 0xffff5bb1);
  FF(bb, cc, dd, aa, x[11], 22, 0x895cd7be);
  FF(aa, bb, cc, dd, x[12], 7, 0x6b901122);
  FF(dd, aa, bb, cc, x[13], 12, 0xfd987193);
  FF(cc, dd, aa, bb, x[14], 17, 0xa679438e);
  FF(bb, cc, dd, aa, x[15], 22, 0x49b40821);

  // Round 2
  GG(aa, bb, cc, dd, x[1], 5, 0xf61e2562);
  GG(dd, aa, bb, cc, x[6], 9, 0xc040b340);
  GG(cc, dd, aa, bb, x[11], 14, 0x265e5a51);
  GG(bb, cc, dd, aa, x[0], 20, 0xe9b6c7aa);
  GG(aa, bb, cc, dd, x[5], 5, 0xd62f105d);
  GG(dd, aa, bb, cc, x[10], 9, 0x2441453);
  GG(cc, dd, aa, bb, x[15], 14, 0xd8a1e681);
  GG(bb, cc, dd, aa, x[4], 20, 0xe7d3fbc8);
  GG(aa, bb, cc, dd, x[9], 5, 0x21e1cde6);
  GG(dd, aa, bb, cc, x[14], 9, 0xc33707d6);
  GG(cc, dd, aa, bb, x[3], 14, 0xf4d50d87);
  GG(bb, cc, dd, aa, x[8], 20, 0x455a14ed);
  GG(aa, bb, cc, dd, x[13], 5, 0xa9e3e905);
  GG(dd, aa, bb, cc, x[2], 9, 0xfcefa3f8);
  GG(cc, dd, aa, bb, x[7], 14, 0x676f02d9);
  GG(bb, cc, dd, aa, x[12], 20, 0x8d2a4c8a);

  // Round 3
  HH(aa, bb, cc, dd, x[5], 4, 0xfffa3942);
  HH(dd, aa, bb, cc, x[8], 11, 0x8771f681);
  HH(cc, dd, aa, bb, x[11], 16, 0x6d9d6122);
  HH(bb, cc, dd, aa, x[14], 23, 0xfde5380c);
  HH(aa, bb, cc, dd, x[1], 4, 0xa4beea44);
  HH(dd, aa, bb, cc, x[4], 11, 0x4bdecfa9);
  HH(cc, dd, aa, bb, x[7], 16, 0xf6bb4b60);
  HH(bb, cc, dd, aa, x[10], 23, 0xbebfbc70);
  HH(aa, bb, cc, dd, x[13], 4, 0x289b7ec6);
  HH(dd, aa, bb, cc, x[0], 11, 0xeaa127fa);
  HH(cc, dd, aa, bb, x[3], 16, 0xd4ef3085);
  HH(bb, cc, dd, aa, x[6], 23, 0x4881d05);
  HH(aa, bb, cc, dd, x[9], 4, 0xd9d4d039);
  HH(dd, aa, bb, cc, x[12], 11, 0xe6db99e5);
  HH(cc, dd, aa, bb, x[15], 16, 0x1fa27cf8);
  HH(bb, cc, dd, aa, x[2], 23, 0xc4ac5665);

  // Round 4
  II(aa, bb, cc, dd, x[0], 6, 0xf4292244);
  II(dd, aa, bb, cc, x[7], 10, 0x432aff97);
  II(cc, dd, aa, bb, x[14], 15, 0xab9423a7);
  II(bb, cc, dd, aa, x[5], 21, 0xfc93a039);
  II(aa, bb, cc, dd, x[12], 6, 0x655b59c3);
  II(dd, aa, bb, cc, x[3], 10, 0x8f0ccc92);
  II(cc, dd, aa, bb, x[10], 15, 0xffeff47d);
  II(bb, cc, dd, aa, x[1], 21, 0x85845dd1);
  II(aa, bb, cc, dd, x[8], 6, 0x6fa87e4f);
  II(dd, aa, bb, cc, x[15], 10, 0xfe2ce6e0);
  II(cc, dd, aa, bb, x[6], 15, 0xa3014314);
  II(bb, cc, dd, aa, x[13], 21, 0x4e0811a1);
  II(aa, bb, cc, dd, x[4], 6, 0xf7537e82);
  II(dd, aa, bb, cc, x[11], 10, 0xbd3af235);
  II(cc, dd, aa, bb, x[2], 15, 0x2ad7d2bb);
  II(bb, cc, dd, aa, x[9], 21, 0xeb86d391);

  ctx->state[0] += aa;
  ctx->state[1] += bb;
  ctx->state[2] += cc;
  ctx->state[3] += dd;

  // TODO: for security reasons we should zeroize the x buffer.
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

  // TODO: zero out
}

#undef ROTATE_LEFT

#undef F
#undef G
#undef H
#undef I

#undef FF
#undef GG
#undef HH
#undef II
