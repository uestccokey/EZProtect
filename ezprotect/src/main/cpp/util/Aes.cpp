//
// Created by like on 2022/1/26.
//

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "AesCipher.h"
#include "Base64.h"
#include "Aes.h"
#include "Logger.h"

const static char HEX[] = {0x10, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf};

void fill(const char *from, unsigned char *to, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        to[i] = from[i];
    }
}

/// encrypt by AES/ECB/PKCS5Padding
char *aes_encrypt(const char *text, const unsigned char *key) {
    using ::cipher::AES_ECB_Cipher;

    char tail_space[16] = {HEX[0]};
    ssize_t text_size = strlen(text);
    size_t directly_size = text_size;

    // PKCS5Padding补码
    if (text_size % 16) {
        directly_size = (text_size / 16) * 16;
        size_t tail_size = text_size - directly_size;
        memcpy(tail_space, text + directly_size, tail_size);
        memset(tail_space + tail_size, HEX[16 - tail_size], 16 - tail_size);
    } else {
        memset(tail_space, HEX[0], 16);
    }

    size_t target_size = directly_size + 16;
    unsigned char *target = (unsigned char *) malloc(target_size);

    AES_ECB_Cipher context(key);
    unsigned char buffer[17] = {0x0};
    size_t round = directly_size / 16;
    for (size_t i = 0; i < round; ++i) {
        fill(text + i * 16, buffer, 16);
        context.AES128_ECB_encrypt(buffer, target + i * 16);
    }
    fill(tail_space, buffer, 16);
    context.AES128_ECB_encrypt(buffer, target + round * 16);

    // `target` strict-alias enabled.
    char *result;
    size_t result_size = 0;
    int n = base64_encode((char *) target, target_size, &result, &result_size);
    free(target);
    if (n != 0) {
        LOGD("Base64 encode result: %d", n);
        return NULL;
    }

    return result;
}

/// decrypt by AES/ECB/PKCS5Padding
char *aes_decrypt(const char *raw, const unsigned char *key) {
    using ::cipher::AES_ECB_Cipher;

    size_t text_size = 0;
    char *text;
    int n = base64_decode(raw, strlen(raw), &text, &text_size);
    if (n != 0) {
        LOGD("Base64 decode result: %d", n);
        return NULL;
    }

    unsigned char *source = (unsigned char *) malloc(text_size);

    AES_ECB_Cipher context(key);
    unsigned char buffer[17] = {0x0};
    size_t round = text_size / 16;
    for (size_t i = 0; i < round; ++i) {
        fill(text + i * 16, buffer, 16);
        context.AES128_ECB_decrypt(buffer, source + i * 16);
    }

    // unpadding with pkcs5, remove unused characters
    unsigned char last_char = source[text_size - 1];
    size_t size = text_size - last_char;
    source[size] = '\0';

    free(text);

    // `source` strict-alias enabled.
    return (char *) source;
}

//int test(int argc, char **argv) {
//    if (argc == 1) {
//        printf("%s data\n", argv[0]);
//        return 1;
//    }
//
//    unsigned char key[] = "ikw35kf9IK9eE93J";
//    char *secret = aes_encrypt(argv[1], key);
//    printf("encrypt: %s\n", secret);
//    char *source = aes_decrypt(secret, key);
//    printf("decrypt: %s\n", source);
//
//    free(secret);
//    free(source);
//
//    return 0;
//}
