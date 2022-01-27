//
// Created by like on 2022/1/26.
//

#ifndef _AES_CIPHER_H_
#define _AES_CIPHER_H_

#include <stdint.h>
#include <stddef.h>

namespace cipher {

    class AES_ECB_Cipher {
    public:
        explicit AES_ECB_Cipher(const unsigned char *key, bool use_cbc = false) : mKey(key), mState(NULL), use_cbc(use_cbc) {};

        void AES128_ECB_encrypt(const unsigned char *input, unsigned char *out);

        void AES128_ECB_decrypt(const unsigned char *input, unsigned char *out);

//        int encode(const unsigned char *src, uint32_t src_len, unsigned char *dest, uint32_t &dest_len);
//
//        int decode(const unsigned char *src, uint32_t src_len, unsigned char *dest, uint32_t &dest_len);

    private:
        typedef uint8_t state_t[4][4];
        uint8_t mRoundKey[240];
        const unsigned char *mKey;
        state_t *mState;
        bool use_cbc;
        static const uint8_t scSbox[256];
        static const uint8_t scRsbox[256];
        static const uint8_t scRcon[255];
        static const uint32_t KEYLEN;
        static const uint32_t NR;
        static const uint32_t NB;
        static const uint32_t NK;

        static inline uint8_t getSBoxValue(uint8_t num);

        static inline uint8_t getSBoxInvert(uint8_t num);

        static inline uint8_t xtime(uint8_t num);

        static inline uint8_t Multiply(uint8_t x, uint8_t y);

        void AddRoundKey(uint8_t round);

        void InvAddRoundKey(uint8_t round);

        void KeyExpansion();

        void MixColumns();

        void SubBytes();

        void ShiftRows();

        void Cipher();

        void InvMixColumns();

        void InvSubBytes();

        void InvShiftRows();

        void InvCipher();
    };

}

#endif
