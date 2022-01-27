//
// Created by like on 2022/1/26.
//

#include <cstring>
#include "AesCipher.h"
#include "Logger.h"

namespace cipher {

    const uint8_t AES_ECB_Cipher::scSbox[256] = {
            //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

    const uint8_t AES_ECB_Cipher::scRsbox[256] = {
            //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};

    const uint8_t AES_ECB_Cipher::scRcon[255] = {
            0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
            0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
            0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
            0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
            0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
            0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
            0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
            0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
            0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
            0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
            0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
            0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
            0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
            0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
            0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb};

    const uint32_t AES_ECB_Cipher::NR = 10;
    const uint32_t AES_ECB_Cipher::NB = 4;
    const uint32_t AES_ECB_Cipher::NK = 4;
    const uint32_t AES_ECB_Cipher::KEYLEN = 16;

    uint8_t AES_ECB_Cipher::getSBoxValue(uint8_t num) {
        return scSbox[num];
    }

    uint8_t AES_ECB_Cipher::getSBoxInvert(uint8_t num) {
        return scRsbox[num];
    }

    uint8_t AES_ECB_Cipher::xtime(uint8_t x) {
        return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
    }

    uint8_t AES_ECB_Cipher::Multiply(uint8_t x, uint8_t y) {
        return (((y & 1) * x) ^
                ((y >> 1 & 1) * xtime(x)) ^
                ((y >> 2 & 1) * xtime(xtime(x))) ^
                ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
                ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));
    }

    void AES_ECB_Cipher::AddRoundKey(uint8_t round) {
        uint8_t i, j;
        for (i = 0; i < 4; ++i) {
            for (j = 0; j < 4; ++j) {
                (*mState)[j][i] ^= mRoundKey[round * NB * 4 + i * NB + j];
            }
        }
    }

    void AES_ECB_Cipher::InvAddRoundKey(uint8_t round) {
        uint8_t i, j;
        for (i = 0; i < 4; ++i) {
            for (j = 0; j < 4; ++j) {
                (*mState)[i][j] ^= mRoundKey[round * NB * 4 + i * NB + j];
            }
        }
    }

    void AES_ECB_Cipher::KeyExpansion() {
        int i, j;
        unsigned char temp[4], k;

        bzero(mRoundKey, sizeof(mRoundKey));

        // The first round key is the key itself.
        for (i = 0; i < NK; i++) {
            mRoundKey[i * 4] = mKey[i * 4];
            mRoundKey[i * 4 + 1] = mKey[i * 4 + 1];
            mRoundKey[i * 4 + 2] = mKey[i * 4 + 2];
            mRoundKey[i * 4 + 3] = mKey[i * 4 + 3];
        }

        // All other round keys are found from the previous round keys.
        while (i < (NB * (NR + 1))) {
            for (j = 0; j < 4; j++) {
                temp[j] = mRoundKey[(i - 1) * 4 + j];
            }
            if (i % NK == 0) {
                // This function rotates the 4 bytes in a word to the left once.
                // [a0,a1,a2,a3] becomes [a1,a2,a3,a0]

                // Function RotWord()
                {
                    k = temp[0];
                    temp[0] = temp[1];
                    temp[1] = temp[2];
                    temp[2] = temp[3];
                    temp[3] = k;
                }

                // SubWord() is a function that takes a four-byte input word and
                // applies the S-box to each of the four bytes to produce an output word.

                // Function Subword()
                {
                    temp[0] = getSBoxValue(temp[0]);
                    temp[1] = getSBoxValue(temp[1]);
                    temp[2] = getSBoxValue(temp[2]);
                    temp[3] = getSBoxValue(temp[3]);
                }

                temp[0] = temp[0] ^ scRcon[i / NK];
            } else if (NK > 6 && i % NK == 4) {
                // Function Subword()
                {
                    temp[0] = getSBoxValue(temp[0]);
                    temp[1] = getSBoxValue(temp[1]);
                    temp[2] = getSBoxValue(temp[2]);
                    temp[3] = getSBoxValue(temp[3]);
                }
            }
            mRoundKey[i * 4 + 0] = mRoundKey[(i - NK) * 4 + 0] ^ temp[0];
            mRoundKey[i * 4 + 1] = mRoundKey[(i - NK) * 4 + 1] ^ temp[1];
            mRoundKey[i * 4 + 2] = mRoundKey[(i - NK) * 4 + 2] ^ temp[2];
            mRoundKey[i * 4 + 3] = mRoundKey[(i - NK) * 4 + 3] ^ temp[3];
            i++;
        }
    }

//    static const int MAX_DECODE_BUF_LEN = 256;
//
//    int AES_ECB_Cipher::encode(const unsigned char *src, uint32_t src_len, unsigned char *dest, uint32_t &len) {
//        // check input null pointer
//        if (NULL == src) {
//            print("AES_ECB_Cipher::encode src is NULL ");
//            return -1;
//        }
//        // make sure dest buff is larger than src buff
//        if (len < src_len) {
//            print("AES_ECB_Cipher::encode src is NULL ");
//            return -1;
//        }
//
//        unsigned char encode_buf[MAX_DECODE_BUF_LEN];
//        bzero(encode_buf, sizeof(encode_buf));
//        memcpy(encode_buf, src, src_len);
//        uint32_t encode_buf_size = src_len;
//
//        // input been padded well with pkcs5padding
//        uint8_t pading_size = AES_ECB_Cipher::KEYLEN - encode_buf_size % AES_ECB_Cipher::KEYLEN;
//        // PKCS5Padding rules: ��(16-len)��(16-len)
//        for (uint8_t pading = 0; pading < pading_size; pading++) {
//            encode_buf[encode_buf_size + pading] = pading_size;
//        }
//        encode_buf_size += pading_size;
//
//        uint32_t round = encode_buf_size / AES_ECB_Cipher::KEYLEN;
//        const unsigned char *iv = mKey;
//        for (uint32_t i = 0; i < round; ++i) {
//            AES128_ECB_encrypt(encode_buf + i * AES_ECB_Cipher::KEYLEN, dest + i * AES_ECB_Cipher::KEYLEN);
//            if (use_cbc) {
//                for (int j = 0; j < AES_ECB_Cipher::KEYLEN; ++j) {
//                    (dest + i * AES_ECB_Cipher::KEYLEN)[j] ^= iv[j];
//                }
//                iv = encode_buf + i * AES_ECB_Cipher::KEYLEN;
//            }
//        }
//
//        len = encode_buf_size;
//        if (len < 0 || len <= src_len) {
//            print("AES_ECB_Cipher::encode, fail to encrypt src");
//            return -1;
//        }
//        dest[len] = 0;
//        return 0;
//    }
//
//    int AES_ECB_Cipher::decode(const unsigned char *src, uint32_t src_len, unsigned char *dest, uint32_t &len) {
//        // check input null pointer
//        if (NULL == src) {
//            print("AES_ECB_Cipher::decode src is NULL ");
//            return -1;
//        }
//        // make sure dest buff is larger than src buff
//        if (len < src_len) {
//            print("AES_ECB_Cipher::decode src is NULL ");
//            return -1;
//        }
//        // assume input has been padded well with pkcs5padding
//        if (src_len % AES_ECB_Cipher::KEYLEN != 0) {
//            print("AES_ECB_Cipher::decode, src len has to be divided by 16");
//            return -1;
//        }
//        uint32_t round = src_len / AES_ECB_Cipher::KEYLEN;
//        const unsigned char *iv = mKey;
//        for (uint32_t i = 0; i < round; ++i) {
//            AES128_ECB_decrypt(src + i * AES_ECB_Cipher::KEYLEN, dest + i * AES_ECB_Cipher::KEYLEN);
//            if (use_cbc) {
//                for (int j = 0; j < AES_ECB_Cipher::KEYLEN; ++j) {
//                    (dest + i * AES_ECB_Cipher::KEYLEN)[j] ^= iv[j];
//                }
//                iv = src + i * AES_ECB_Cipher::KEYLEN;
//            }
//        }
//
//        // unpad with pkcs5, remove unused charactors
//        uint8_t lastASIIC = (uint8_t) dest[src_len - 1];
//        len = src_len - lastASIIC;
//        if (len < 0 || len >= src_len) {
//            print("AES_ECB_Cipher::decode, fail to decrypt src");
//            return -1;
//        }
//        dest[len] = 0;
//        return 0;
//    }

    void AES_ECB_Cipher::MixColumns() {
        int i;
        unsigned char Tmp, Tm, t;
        for (i = 0; i < 4; i++) {
            t = (*mState)[0][i];
            Tmp = (*mState)[0][i] ^ (*mState)[1][i] ^ (*mState)[2][i] ^ (*mState)[3][i];
            Tm = (*mState)[0][i] ^ (*mState)[1][i];
            Tm = xtime(Tm);
            (*mState)[0][i] ^= Tm ^ Tmp;
            Tm = (*mState)[1][i] ^ (*mState)[2][i];
            Tm = xtime(Tm);
            (*mState)[1][i] ^= Tm ^ Tmp;
            Tm = (*mState)[2][i] ^ (*mState)[3][i];
            Tm = xtime(Tm);
            (*mState)[2][i] ^= Tm ^ Tmp;
            Tm = (*mState)[3][i] ^ t;
            Tm = xtime(Tm);
            (*mState)[3][i] ^= Tm ^ Tmp;
        }
    }

    void AES_ECB_Cipher::SubBytes() {
        uint8_t i, j;
        for (i = 0; i < 4; i++) {
            for (j = 0; j < 4; j++) {
                (*mState)[i][j] = getSBoxValue((*mState)[i][j]);
            }
        }
    }

    void AES_ECB_Cipher::ShiftRows() {
        unsigned char temp;

        // Rotate first row 1 columns to left
        temp = (*mState)[1][0];
        (*mState)[1][0] = (*mState)[1][1];
        (*mState)[1][1] = (*mState)[1][2];
        (*mState)[1][2] = (*mState)[1][3];
        (*mState)[1][3] = temp;

        // Rotate second row 2 columns to left
        temp = (*mState)[2][0];
        (*mState)[2][0] = (*mState)[2][2];
        (*mState)[2][2] = temp;
        temp = (*mState)[2][1];
        (*mState)[2][1] = (*mState)[2][3];
        (*mState)[2][3] = temp;

        // Rotate third row 3 columns to left
        temp = (*mState)[3][0];
        (*mState)[3][0] = (*mState)[3][3];
        (*mState)[3][3] = (*mState)[3][2];
        (*mState)[3][2] = (*mState)[3][1];
        (*mState)[3][1] = temp;
    }

    void AES_ECB_Cipher::Cipher() {
        uint8_t round = 0;

        // Add the First round key to the state before starting the rounds.
        AddRoundKey(0);

        // There will be Nr rounds.
        // The first Nr-1 rounds are identical.
        // These Nr-1 rounds are executed in the loop below.
        for (round = 1; round < NR; round++) {
            SubBytes();
            ShiftRows();
            MixColumns();
            AddRoundKey(round);
        }

        // The last round is given below.
        // The MixColumns function is not here in the last round.
        SubBytes();
        ShiftRows();
        AddRoundKey(NR);
    }

    void AES_ECB_Cipher::AES128_ECB_encrypt(const unsigned char *input, unsigned char *output) {
        memcpy(output, input, AES_ECB_Cipher::KEYLEN);
        mState = (state_t *) output;

        state_t state;
        mState = &state;

        uint8_t i, j;
        for (i = 0; i < 4; i++) {
            for (j = 0; j < 4; j++) {
                (*mState)[j][i] = input[i * 4 + j];
            }
        }

        KeyExpansion();
        Cipher();

        for (i = 0; i < 4; i++) {
            for (j = 0; j < 4; j++) {
                output[i * 4 + j] = (*mState)[j][i];
            }
        }
    }

    void AES_ECB_Cipher::InvMixColumns() {
        uint8_t a, b, c, d;

        for (uint32_t i = 0; i < 4; ++i) {
            a = (*mState)[i][0];
            b = (*mState)[i][1];
            c = (*mState)[i][2];
            d = (*mState)[i][3];

            (*mState)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
            (*mState)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
            (*mState)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
            (*mState)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
        }
    }

    void AES_ECB_Cipher::InvSubBytes() {
        uint8_t i, j;
        for (i = 0; i < 4; ++i) {
            for (j = 0; j < 4; ++j) {
                (*mState)[j][i] = getSBoxInvert((*mState)[j][i]);
            }
        }
    }

    void AES_ECB_Cipher::InvShiftRows() {
        uint8_t temp;

        // Rotate first row 1 columns to right
        temp = (*mState)[3][1];
        (*mState)[3][1] = (*mState)[2][1];
        (*mState)[2][1] = (*mState)[1][1];
        (*mState)[1][1] = (*mState)[0][1];
        (*mState)[0][1] = temp;

        // Rotate second row 2 columns to right
        temp = (*mState)[0][2];
        (*mState)[0][2] = (*mState)[2][2];
        (*mState)[2][2] = temp;

        temp = (*mState)[1][2];
        (*mState)[1][2] = (*mState)[3][2];
        (*mState)[3][2] = temp;

        // Rotate third row 3 columns to right
        temp = (*mState)[0][3];
        (*mState)[0][3] = (*mState)[1][3];
        (*mState)[1][3] = (*mState)[2][3];
        (*mState)[2][3] = (*mState)[3][3];
        (*mState)[3][3] = temp;
    }

    void AES_ECB_Cipher::InvCipher() {
        uint8_t round = 0;
        InvAddRoundKey(NR);

        for (round = NR - 1; round > 0; round--) {
            InvShiftRows();
            InvSubBytes();
            InvAddRoundKey(round);
            InvMixColumns();
        }

        InvShiftRows();
        InvSubBytes();
        InvAddRoundKey(0);
    }

    void AES_ECB_Cipher::AES128_ECB_decrypt(const unsigned char *input, unsigned char *output) {
        memcpy(output, input, AES_ECB_Cipher::KEYLEN);
        mState = (state_t *) output;

        KeyExpansion();
        InvCipher();
    }

}