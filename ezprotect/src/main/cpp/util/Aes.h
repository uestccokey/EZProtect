//
// Created by like on 2022/1/26.
//

#ifndef AES_H
#define AES_H

#ifdef __cplusplus
extern "C" {
#endif

char *aes_encrypt(const char *text, const unsigned char *key);

char *aes_decrypt(const char *raw, const unsigned char *key);

#ifdef __cplusplus
}
#endif

#endif
