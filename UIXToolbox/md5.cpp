#include "stdafx.h"
#include <stdio.h>
#include <string.h>
#include "md5.h"

static void md5_process(MD5_CTX* ctx, const md5_byte_t data[64]);

void MD5Init(MD5_CTX* ctx)
{
    ctx->count[0] = ctx->count[1] = 0;
    ctx->abcd[0] = 0x67452301;
    ctx->abcd[1] = 0xefcdab89;
    ctx->abcd[2] = 0x98badcfe;
    ctx->abcd[3] = 0x10325476;
}

void MD5Update(MD5_CTX* ctx, const md5_byte_t* data, unsigned int len)
{
    md5_word_t t = ctx->count[0];
    if ((ctx->count[0] = t + ((md5_word_t)len << 3)) < t)
        ctx->count[1]++;
    ctx->count[1] += len >> 29;

    t = (t >> 3) & 0x3f;

    if (t)
    {
        md5_byte_t* p = (md5_byte_t*)ctx->buf + t;
        t = 64 - t;
        if (len < t)
        {
            memcpy(p, data, len);
            return;
        }
        memcpy(p, data, t);
        md5_process(ctx, ctx->buf);
        data += t;
        len -= t;
    }

    while (len >= 64)
    {
        md5_process(ctx, data);
        data += 64;
        len -= 64;
    }

    memcpy(ctx->buf, data, len);
}

void MD5Final(md5_byte_t digest[16], MD5_CTX* ctx)
{
    static const md5_byte_t pad[64] = { 0x80 };
    md5_byte_t data[8];
    int i;

    for (i = 0; i < 8; ++i)
        data[i] = (md5_byte_t)(ctx->count[i >> 2] >> ((i & 3) << 3));

    MD5Update(ctx, pad, (unsigned int)((55 - (ctx->count[0] >> 3)) & 63) + 1);
    MD5Update(ctx, data, 8);

    for (i = 0; i < 16; ++i)
        digest[i] = (md5_byte_t)(ctx->abcd[i >> 2] >> ((i & 3) << 3));

    memset(ctx, 0, sizeof(*ctx));
}

#define F(x, y, z) ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z) ((y) ^ ((z) & ((x) ^ (y))))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | ~(z)))

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define STEP(f, a, b, c, d, x, t, s) \
    (a) += f((b), (c), (d)) + (x) + (t); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b);

static void md5_process(MD5_CTX* ctx, const md5_byte_t data[64])
{
    md5_word_t a = ctx->abcd[0], b = ctx->abcd[1], c = ctx->abcd[2], d = ctx->abcd[3];
    md5_word_t x[16];
    int i;

    for (i = 0; i < 16; ++i)
    {
        x[i] = (md5_word_t)data[i * 4] |
               ((md5_word_t)data[i * 4 + 1] << 8) |
               ((md5_word_t)data[i * 4 + 2] << 16) |
               ((md5_word_t)data[i * 4 + 3] << 24);
    }

    STEP(F, a, b, c, d, x[ 0], 0xd76aa478,  7)
    STEP(F, d, a, b, c, x[ 1], 0xe8c7b756, 12)
    STEP(F, c, d, a, b, x[ 2], 0x242070db, 17)
    STEP(F, b, c, d, a, x[ 3], 0xc1bdceee, 22)
    STEP(F, a, b, c, d, x[ 4], 0xf57c0faf,  7)
    STEP(F, d, a, b, c, x[ 5], 0x4787c62a, 12)
    STEP(F, c, d, a, b, x[ 6], 0xa8304613, 17)
    STEP(F, b, c, d, a, x[ 7], 0xfd469501, 22)
    STEP(F, a, b, c, d, x[ 8], 0x698098d8,  7)
    STEP(F, d, a, b, c, x[ 9], 0x8b44f7af, 12)
    STEP(F, c, d, a, b, x[10], 0xffff5bb1, 17)
    STEP(F, b, c, d, a, x[11], 0x895cd7be, 22)
    STEP(F, a, b, c, d, x[12], 0x6b901122,  7)
    STEP(F, d, a, b, c, x[13], 0xfd987193, 12)
    STEP(F, c, d, a, b, x[14], 0xa679438e, 17)
    STEP(F, b, c, d, a, x[15], 0x49b40821, 22)

    STEP(G, a, b, c, d, x[ 1], 0xf61e2562,  5)
    STEP(G, d, a, b, c, x[ 6], 0xc040b340,  9)
    STEP(G, c, d, a, b, x[11], 0x265e5a51, 14)
    STEP(G, b, c, d, a, x[ 0], 0xe9b6c7aa, 20)
    STEP(G, a, b, c, d, x[ 5], 0xd62f105d,  5)
    STEP(G, d, a, b, c, x[10], 0x02441453,  9)
    STEP(G, c, d, a, b, x[15], 0xd8a1e681, 14)
    STEP(G, b, c, d, a, x[ 4], 0xe7d3fbc8, 20)
    STEP(G, a, b, c, d, x[ 9], 0x21e1cde6,  5)
    STEP(G, d, a, b, c, x[14], 0xc33707d6,  9)
    STEP(G, c, d, a, b, x[ 3], 0xf4d50d87, 14)
    STEP(G, b, c, d, a, x[ 8], 0x455a14ed, 20)
    STEP(G, a, b, c, d, x[13], 0xa9e3e905,  5)
    STEP(G, d, a, b, c, x[ 2], 0xfcefa3f8,  9)
    STEP(G, c, d, a, b, x[ 7], 0x676f02d9, 14)
    STEP(G, b, c, d, a, x[12], 0x8d2a4c8a, 20)

    STEP(H, a, b, c, d, x[ 5], 0xfffa3942,  4)
    STEP(H, d, a, b, c, x[ 8], 0x8771f681, 11)
    STEP(H, c, d, a, b, x[11], 0x6d9d6122, 16)
    STEP(H, b, c, d, a, x[14], 0xfde5380c, 23)
    STEP(H, a, b, c, d, x[ 1], 0xa4beea44,  4)
    STEP(H, d, a, b, c, x[ 4], 0x4bdecfa9, 11)
    STEP(H, c, d, a, b, x[ 7], 0xf6bb4b60, 16)
    STEP(H, b, c, d, a, x[10], 0xbebfbc70, 23)
    STEP(H, a, b, c, d, x[13], 0x289b7ec6,  4)
    STEP(H, d, a, b, c, x[ 0], 0xeaa127fa, 11)
    STEP(H, c, d, a, b, x[ 3], 0xd4ef3085, 16)
    STEP(H, b, c, d, a, x[ 6], 0x04881d05, 23)
    STEP(H, a, b, c, d, x[ 9], 0xd9d4d039,  4)
    STEP(H, d, a, b, c, x[12], 0xe6db99e5, 11)
    STEP(H, c, d, a, b, x[15], 0x1fa27cf8, 16)
    STEP(H, b, c, d, a, x[ 2], 0xc4ac5665, 23)

    STEP(I, a, b, c, d, x[ 0], 0xf4292244,  6)
    STEP(I, d, a, b, c, x[ 7], 0x432aff97, 10)
    STEP(I, c, d, a, b, x[14], 0xab9423a7, 15)
    STEP(I, b, c, d, a, x[ 5], 0xfc93a039, 21)
    STEP(I, a, b, c, d, x[12], 0x655b59c3,  6)
    STEP(I, d, a, b, c, x[ 3], 0x8f0ccc92, 10)
    STEP(I, c, d, a, b, x[10], 0xffeff47d, 15)
    STEP(I, b, c, d, a, x[ 1], 0x85845dd1, 21)
    STEP(I, a, b, c, d, x[ 8], 0x6fa87e4f,  6)
    STEP(I, d, a, b, c, x[15], 0xfe2ce6e0, 10)
    STEP(I, c, d, a, b, x[ 6], 0xa3014314, 15)
    STEP(I, b, c, d, a, x[13], 0x4e0811a1, 21)
    STEP(I, a, b, c, d, x[ 4], 0xf7537e82,  6)
    STEP(I, d, a, b, c, x[11], 0xbd3af235, 10)
    STEP(I, c, d, a, b, x[ 2], 0x2ad7d2bb, 15)
    STEP(I, b, c, d, a, x[ 9], 0xeb86d391, 21)

    ctx->abcd[0] += a;
    ctx->abcd[1] += b;
    ctx->abcd[2] += c;
    ctx->abcd[3] += d;
}

bool GetFileMd5(const char* path, char outHex[33])
{
    FILE* file = fopen(path, "rb");
    if (file == NULL) {
        return false;
    }

    MD5_CTX ctx;
    MD5Init(&ctx);

    unsigned char buffer[4096];
    size_t bytesRead = 0;

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        MD5Update(&ctx, buffer, (unsigned int)bytesRead);
    }

    fclose(file);

    unsigned char digest[16];
    MD5Final(digest, &ctx);

    for (int i = 0; i < 16; i++) {
        sprintf(outHex + (i * 2), "%02x", digest[i]);
    }
    outHex[32] = '\0';

    return true;
}