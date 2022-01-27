//
// Created by like on 2022/1/26.
//

#ifndef _BASE64_H_
#define _BASE64_H_

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int base64_decode(const char *text, size_t text_size, char **output, size_t *output_size);

int base64_encode(const char *text, size_t text_size, char **output, size_t *output_size);

#ifdef __cplusplus
}
#endif

#endif

