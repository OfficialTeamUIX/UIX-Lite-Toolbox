#ifndef MD5_H
#define MD5_H

typedef unsigned char md5_byte_t;
typedef unsigned int md5_word_t;

typedef struct
{
    md5_word_t count[2];
    md5_word_t abcd[4];
    md5_byte_t buf[64];
} MD5_CTX;

void MD5Init(MD5_CTX* ctx);
void MD5Update(MD5_CTX* ctx, const md5_byte_t* data, unsigned int len);
void MD5Final(md5_byte_t digest[16], MD5_CTX* ctx);

bool GetFileMd5(const char* path, char outHex[33]);

#endif