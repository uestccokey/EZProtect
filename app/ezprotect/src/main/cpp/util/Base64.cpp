//
// Created by like on 2022/1/26.
//

#include "Base64.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>

static const char base[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";

static char find_pos(char ch) {
    // the last position (the only) in base[]
    char *ptr = (char *) strrchr(base, ch);
    return (ptr - base);
}

static void encode_translate_group(const char *text, char *output) {
    uint32_t bits = 0;
    for (size_t j = 0; j < 3; ++j) {
        bits = (bits << 8) | (text[j] & 0xFF);
    }

    size_t cur = 0;
    for (size_t j = 0; j < 4; ++j) {
        char shift = (3 - j) * 6;
        char changed = (bits >> shift) & 0x3F;
        output[cur++] = base[(size_t) changed];
    }
}

int base64_encode(const char *text, size_t text_size, char **output,
                  size_t *output_size) {
    // 1. caculate size and alloc memory.
    size_t group = (text_size + 2) / 3;
    size_t total_size = group * 4 + 1;
    char *buffer = (char *) malloc(total_size);
    size_t cur = 0;

    if (buffer == NULL) {
        return -ENOMEM;
    }

    // 2. translate by group.
    for (size_t i = 0; i < text_size; i += 3, cur += 4) {
        if (i + 3 > text_size) {
            size_t have = text_size - i;
            size_t owe = 3 - have;

            char equals[4] = {0x0};
            memset(equals, 0, 4);
            memcpy(equals, text + i, have);
            encode_translate_group(equals, buffer + cur);
            memset(buffer + cur + 4 - owe, '=', owe);
        } else {
            encode_translate_group(text + i, buffer + cur);
        }
    }
    buffer[cur] = '\0';

    *output = buffer;
    *output_size = cur;

    return 0;
}

static size_t tail_equals_count(const char *text, size_t text_size) {
    size_t equals_count = 0;
    for (size_t i = 1; i < 3; ++i) {
        if (text[text_size - i] == '=') {
            equals_count += 1;
        }
    }
    return equals_count;
}

static size_t padding_size(const char *text, size_t text_size) {
    size_t actual_size = 0;
    size_t equal_count = 0;
    for (size_t i = 1; i < 4; ++i) {
        if (text[text_size - i] == '=') {
            equal_count += 1;
        }
    }
    switch (equal_count) {
        case 0:
            actual_size += 4;  // 3 + 1 [1 for NULL]
            break;
        case 1:
            actual_size += 4;  // Ceil((6*3)/8)+1
            break;
        case 2:
            actual_size += 3;  // Ceil((6*2)/8)+1
            break;
        case 3:
            actual_size += 2;  // Ceil((6*1)/8)+1
            break;
    }
    return actual_size;
}

static void decode_translate_group(const char *text, char *output) {
    uint32_t bits = 0;
    size_t cur = 0;
    for (size_t j = 0; j < 4; ++j) {
        bits = (bits << 6) | find_pos(text[j]);
    }
    for (size_t j = 0; j < 3; ++j) {
        char shift = (2 - j) * 8;
        char changed = (bits >> shift) & 0xFF;
        output[cur++] = changed;
    }
}

int base64_decode(const char *text, size_t text_size, char **output,
                  size_t *output_size) {
    if (text_size % 4) {
        // wrong format for base64.
        return -EINVAL;
    }

    size_t actual_size = text_size / 4 * 3 + 1;
    size_t cur = 0;
    size_t cnt = tail_equals_count(text, text_size);
    char *buffer = (char *) malloc(actual_size);
    for (size_t i = 0; i < text_size; i += 4, cur += 3) {
        decode_translate_group(text + i, buffer + cur);
    }
    cur -= cnt;
    buffer[cur] = '\0';

    *output = buffer;
    *output_size = cur;

    return 0;
}

