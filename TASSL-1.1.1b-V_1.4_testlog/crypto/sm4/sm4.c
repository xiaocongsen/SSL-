/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/e_os2.h>
#include "internal/sm4.h"

static const uint8_t SM4_S[256] = {
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2,
    0x28, 0xFB, 0x2C, 0x05, 0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3,
    0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99, 0x9C, 0x42, 0x50, 0xF4,
    0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA,
    0x75, 0x8F, 0x3F, 0xA6, 0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA,
    0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8, 0x68, 0x6B, 0x81, 0xB2,
    0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B,
    0x01, 0x21, 0x78, 0x87, 0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52,
    0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E, 0xEA, 0xBF, 0x8A, 0xD2,
    0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1,
    0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30,
    0xF5, 0x8C, 0xB1, 0xE3, 0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60,
    0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F, 0xD5, 0xDB, 0x37, 0x45,
    0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51,
    0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41,
    0x1F, 0x10, 0x5A, 0xD8, 0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD,
    0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0, 0x89, 0x69, 0x97, 0x4A,
    0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84,
    0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E,
    0xD7, 0xCB, 0x39, 0x48
};

/*
 * SM4_SBOX_T[j] == L(SM4_SBOX[j]).
 */
static const uint32_t SM4_SBOX_T[256] = {
    0x8ED55B5B, 0xD0924242, 0x4DEAA7A7, 0x06FDFBFB, 0xFCCF3333, 0x65E28787,
    0xC93DF4F4, 0x6BB5DEDE, 0x4E165858, 0x6EB4DADA, 0x44145050, 0xCAC10B0B,
    0x8828A0A0, 0x17F8EFEF, 0x9C2CB0B0, 0x11051414, 0x872BACAC, 0xFB669D9D,
    0xF2986A6A, 0xAE77D9D9, 0x822AA8A8, 0x46BCFAFA, 0x14041010, 0xCFC00F0F,
    0x02A8AAAA, 0x54451111, 0x5F134C4C, 0xBE269898, 0x6D482525, 0x9E841A1A,
    0x1E061818, 0xFD9B6666, 0xEC9E7272, 0x4A430909, 0x10514141, 0x24F7D3D3,
    0xD5934646, 0x53ECBFBF, 0xF89A6262, 0x927BE9E9, 0xFF33CCCC, 0x04555151,
    0x270B2C2C, 0x4F420D0D, 0x59EEB7B7, 0xF3CC3F3F, 0x1CAEB2B2, 0xEA638989,
    0x74E79393, 0x7FB1CECE, 0x6C1C7070, 0x0DABA6A6, 0xEDCA2727, 0x28082020,
    0x48EBA3A3, 0xC1975656, 0x80820202, 0xA3DC7F7F, 0xC4965252, 0x12F9EBEB,
    0xA174D5D5, 0xB38D3E3E, 0xC33FFCFC, 0x3EA49A9A, 0x5B461D1D, 0x1B071C1C,
    0x3BA59E9E, 0x0CFFF3F3, 0x3FF0CFCF, 0xBF72CDCD, 0x4B175C5C, 0x52B8EAEA,
    0x8F810E0E, 0x3D586565, 0xCC3CF0F0, 0x7D196464, 0x7EE59B9B, 0x91871616,
    0x734E3D3D, 0x08AAA2A2, 0xC869A1A1, 0xC76AADAD, 0x85830606, 0x7AB0CACA,
    0xB570C5C5, 0xF4659191, 0xB2D96B6B, 0xA7892E2E, 0x18FBE3E3, 0x47E8AFAF,
    0x330F3C3C, 0x674A2D2D, 0xB071C1C1, 0x0E575959, 0xE99F7676, 0xE135D4D4,
    0x661E7878, 0xB4249090, 0x360E3838, 0x265F7979, 0xEF628D8D, 0x38596161,
    0x95D24747, 0x2AA08A8A, 0xB1259494, 0xAA228888, 0x8C7DF1F1, 0xD73BECEC,
    0x05010404, 0xA5218484, 0x9879E1E1, 0x9B851E1E, 0x84D75353, 0x00000000,
    0x5E471919, 0x0B565D5D, 0xE39D7E7E, 0x9FD04F4F, 0xBB279C9C, 0x1A534949,
    0x7C4D3131, 0xEE36D8D8, 0x0A020808, 0x7BE49F9F, 0x20A28282, 0xD4C71313,
    0xE8CB2323, 0xE69C7A7A, 0x42E9ABAB, 0x43BDFEFE, 0xA2882A2A, 0x9AD14B4B,
    0x40410101, 0xDBC41F1F, 0xD838E0E0, 0x61B7D6D6, 0x2FA18E8E, 0x2BF4DFDF,
    0x3AF1CBCB, 0xF6CD3B3B, 0x1DFAE7E7, 0xE5608585, 0x41155454, 0x25A38686,
    0x60E38383, 0x16ACBABA, 0x295C7575, 0x34A69292, 0xF7996E6E, 0xE434D0D0,
    0x721A6868, 0x01545555, 0x19AFB6B6, 0xDF914E4E, 0xFA32C8C8, 0xF030C0C0,
    0x21F6D7D7, 0xBC8E3232, 0x75B3C6C6, 0x6FE08F8F, 0x691D7474, 0x2EF5DBDB,
    0x6AE18B8B, 0x962EB8B8, 0x8A800A0A, 0xFE679999, 0xE2C92B2B, 0xE0618181,
    0xC0C30303, 0x8D29A4A4, 0xAF238C8C, 0x07A9AEAE, 0x390D3434, 0x1F524D4D,
    0x764F3939, 0xD36EBDBD, 0x81D65757, 0xB7D86F6F, 0xEB37DCDC, 0x51441515,
    0xA6DD7B7B, 0x09FEF7F7, 0xB68C3A3A, 0x932FBCBC, 0x0F030C0C, 0x03FCFFFF,
    0xC26BA9A9, 0xBA73C9C9, 0xD96CB5B5, 0xDC6DB1B1, 0x375A6D6D, 0x15504545,
    0xB98F3636, 0x771B6C6C, 0x13ADBEBE, 0xDA904A4A, 0x57B9EEEE, 0xA9DE7777,
    0x4CBEF2F2, 0x837EFDFD, 0x55114444, 0xBDDA6767, 0x2C5D7171, 0x45400505,
    0x631F7C7C, 0x50104040, 0x325B6969, 0xB8DB6363, 0x220A2828, 0xC5C20707,
    0xF531C4C4, 0xA88A2222, 0x31A79696, 0xF9CE3737, 0x977AEDED, 0x49BFF6F6,
    0x992DB4B4, 0xA475D1D1, 0x90D34343, 0x5A124848, 0x58BAE2E2, 0x71E69797,
    0x64B6D2D2, 0x70B2C2C2, 0xAD8B2626, 0xCD68A5A5, 0xCB955E5E, 0x624B2929,
    0x3C0C3030, 0xCE945A5A, 0xAB76DDDD, 0x867FF9F9, 0xF1649595, 0x5DBBE6E6,
    0x35F2C7C7, 0x2D092424, 0xD1C61717, 0xD66FB9B9, 0xDEC51B1B, 0x94861212,
    0x78186060, 0x30F3C3C3, 0x897CF5F5, 0x5CEFB3B3, 0xD23AE8E8, 0xACDF7373,
    0x794C3535, 0xA0208080, 0x9D78E5E5, 0x56EDBBBB, 0x235E7D7D, 0xC63EF8F8,
    0x8BD45F5F, 0xE7C82F2F, 0xDD39E4E4, 0x68492121 };

static ossl_inline uint32_t rotl(uint32_t a, uint8_t n)
{
    return (a << n) | (a >> (32 - n));
}

static ossl_inline uint32_t load_u32_be(const uint8_t *b, uint32_t n)
{
    return ((uint32_t)b[4 * n] << 24) |
           ((uint32_t)b[4 * n + 1] << 16) |
           ((uint32_t)b[4 * n + 2] << 8) |
           ((uint32_t)b[4 * n + 3]);
}

static ossl_inline void store_u32_be(uint32_t v, uint8_t *b)
{
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)(v);
}

static ossl_inline uint32_t SM4_T_slow(uint32_t X)
{
    uint32_t t = 0;

    t |= ((uint32_t)SM4_S[(uint8_t)(X >> 24)]) << 24;
    t |= ((uint32_t)SM4_S[(uint8_t)(X >> 16)]) << 16;
    t |= ((uint32_t)SM4_S[(uint8_t)(X >> 8)]) << 8;
    t |= SM4_S[(uint8_t)X];

    /*
     * L linear transform
     */
    return t ^ rotl(t, 2) ^ rotl(t, 10) ^ rotl(t, 18) ^ rotl(t, 24);
}

static ossl_inline uint32_t SM4_T(uint32_t X)
{
    return SM4_SBOX_T[(uint8_t)(X >> 24)] ^
           rotl(SM4_SBOX_T[(uint8_t)(X >> 16)], 24) ^
           rotl(SM4_SBOX_T[(uint8_t)(X >> 8)], 16) ^
           rotl(SM4_SBOX_T[(uint8_t)X], 8);
}

int SM4_set_key(const uint8_t *key, SM4_KEY *ks)
{
    /*
     * Family Key
     */
    static const uint32_t FK[4] =
        { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };

    /*
     * Constant Key
     */
    static const uint32_t CK[32] = {
        0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
        0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
        0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
        0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
        0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
        0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
        0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
        0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
    };

    uint32_t K[4];
    int i;

    K[0] = load_u32_be(key, 0) ^ FK[0];
    K[1] = load_u32_be(key, 1) ^ FK[1];
    K[2] = load_u32_be(key, 2) ^ FK[2];
    K[3] = load_u32_be(key, 3) ^ FK[3];

    for (i = 0; i != SM4_KEY_SCHEDULE; ++i) {
        uint32_t X = K[(i + 1) % 4] ^ K[(i + 2) % 4] ^ K[(i + 3) % 4] ^ CK[i];
        uint32_t t = 0;

        t |= ((uint32_t)SM4_S[(uint8_t)(X >> 24)]) << 24;
        t |= ((uint32_t)SM4_S[(uint8_t)(X >> 16)]) << 16;
        t |= ((uint32_t)SM4_S[(uint8_t)(X >> 8)]) << 8;
        t |= SM4_S[(uint8_t)X];

        t = t ^ rotl(t, 13) ^ rotl(t, 23);
        K[i % 4] ^= t;
        ks->rk[i] = K[i % 4];
    }

    return 1;
}

#define SM4_RNDS(k0, k1, k2, k3, F)          \
      do {                                   \
         B0 ^= F(B1 ^ B2 ^ B3 ^ ks->rk[k0]); \
         B1 ^= F(B0 ^ B2 ^ B3 ^ ks->rk[k1]); \
         B2 ^= F(B0 ^ B1 ^ B3 ^ ks->rk[k2]); \
         B3 ^= F(B0 ^ B1 ^ B2 ^ ks->rk[k3]); \
      } while(0)

void SM4_encrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks)
{
    uint32_t B0 = load_u32_be(in, 0);
    uint32_t B1 = load_u32_be(in, 1);
    uint32_t B2 = load_u32_be(in, 2);
    uint32_t B3 = load_u32_be(in, 3);

    /*
     * Uses byte-wise sbox in the first and last rounds to provide some
     * protection from cache based side channels.
     */
    SM4_RNDS( 0,  1,  2,  3, SM4_T_slow);
    SM4_RNDS( 4,  5,  6,  7, SM4_T);
    SM4_RNDS( 8,  9, 10, 11, SM4_T);
    SM4_RNDS(12, 13, 14, 15, SM4_T);
    SM4_RNDS(16, 17, 18, 19, SM4_T);
    SM4_RNDS(20, 21, 22, 23, SM4_T);
    SM4_RNDS(24, 25, 26, 27, SM4_T);
    SM4_RNDS(28, 29, 30, 31, SM4_T_slow);

    store_u32_be(B3, out);
    store_u32_be(B2, out + 4);
    store_u32_be(B1, out + 8);
    store_u32_be(B0, out + 12);
}

void SM4_decrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks)
{
    uint32_t B0 = load_u32_be(in, 0);
    uint32_t B1 = load_u32_be(in, 1);
    uint32_t B2 = load_u32_be(in, 2);
    uint32_t B3 = load_u32_be(in, 3);

    SM4_RNDS(31, 30, 29, 28, SM4_T_slow);
    SM4_RNDS(27, 26, 25, 24, SM4_T);
    SM4_RNDS(23, 22, 21, 20, SM4_T);
    SM4_RNDS(19, 18, 17, 16, SM4_T);
    SM4_RNDS(15, 14, 13, 12, SM4_T);
    SM4_RNDS(11, 10,  9,  8, SM4_T);
    SM4_RNDS( 7,  6,  5,  4, SM4_T);
    SM4_RNDS( 3,  2,  1,  0, SM4_T_slow);

    store_u32_be(B3, out);
    store_u32_be(B2, out + 4);
    store_u32_be(B1, out + 8);
    store_u32_be(B0, out + 12);
}



uint8_t GMold_SBOX[256] = {
	0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7,
	0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
	0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3,
	0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
	0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a,
	0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
	0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95,
	0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
	0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba,
	0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
	0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b,
	0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
	0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2,
	0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
	0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52,
	0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
	0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5,
	0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
	0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55,
	0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
	0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60,
	0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
	0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f,
	0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
	0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f,
	0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
	0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd,
	0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
	0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e,
	0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
	0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20,
	0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
};

static uint32_t FK[4] = {
	0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc,
};

static uint32_t CK[32] = {
	0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
	0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
	0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
	0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
	0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
	0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
	0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
	0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279,
};

#define ROT32(x,i)					\
	(((x) << i) | ((x) >> (32-i)))

#define S32(A)						\
	((GMold_SBOX[((A) >> 24)       ] << 24) ^		\
	 (GMold_SBOX[((A) >> 16) & 0xff] << 16) ^		\
	 (GMold_SBOX[((A) >>  8) & 0xff] <<  8) ^		\
	 (GMold_SBOX[((A))       & 0xff]))

#define L32(x)						\
	((x) ^						\
	ROT32((x),  2) ^				\
	ROT32((x), 10) ^				\
	ROT32((x), 18) ^				\
	ROT32((x), 24))

#define L32_(x)					\
	((x) ^ 					\
	ROT32((x), 13) ^			\
	ROT32((x), 23))

#define DEC_ROUND(x0, x1, x2, x3, x4, i)	\
	x4 = x1 ^ x2 ^ x3 ^ *(CK + i);		\
	x4 = S32(x4);				\
	x4 = x0 ^ L32_(x4);			\
	*(rk + 31 - i) = x4

#define ENC_ROUND(x0, x1, x2, x3, x4, i)	\
	x4 = x1 ^ x2 ^ x3 ^ *(CK + i);		\
	x4 = S32(x4);				\
	x4 = x0 ^ L32_(x4);			\
	*(rk + i) = x4

void GMold_sms4_encrypt(const unsigned char *in, unsigned char *out, const GMold_sms4_key_t *key)
{
	const uint32_t *rk = key->rk;
	uint32_t x0, x1, x2, x3, x4;

	x0 = ( ((uint32_t)(in)[0] << 24) ^ ((uint32_t)(in)[1] << 16) ^ ((uint32_t)(in)[2] << 8) ^ ((uint32_t)(in)[3]));
	x1 = ( ((uint32_t)(in + 4)[0] << 24) ^ ((uint32_t)(in + 4)[1] << 16) ^ ((uint32_t)(in + 4)[2] << 8) ^ ((uint32_t)(in + 4)[3]));
	x2 = ( ((uint32_t)(in + 8)[0] << 24) ^ ((uint32_t)(in + 8)[1] << 16) ^ ((uint32_t)(in + 8)[2] << 8) ^ ((uint32_t)(in + 8)[3]));
	x3 = ( ((uint32_t)(in + 12)[0] << 24) ^ ((uint32_t)(in + 12)[1] << 16) ^ ((uint32_t)(in + 12)[2] << 8) ^ ((uint32_t)(in + 12)[3]));

	x4 = x1 ^ x2 ^ x3 ^ *(rk + 0); x4 = S32(x4); x4 = x0 ^ L32(x4); 
	x0 = x2 ^ x3 ^ x4 ^ *(rk + 1); x0 = S32(x0); x0 = x1 ^ L32(x0); 
	x1 = x3 ^ x4 ^ x0 ^ *(rk + 2); x1 = S32(x1); x1 = x2 ^ L32(x1); 
	x2 = x4 ^ x0 ^ x1 ^ *(rk + 3); x2 = S32(x2); x2 = x3 ^ L32(x2); 
	x3 = x0 ^ x1 ^ x2 ^ *(rk + 4); x3 = S32(x3); x3 = x4 ^ L32(x3); 
	x4 = x1 ^ x2 ^ x3 ^ *(rk + 5); x4 = S32(x4); x4 = x0 ^ L32(x4); 
	x0 = x2 ^ x3 ^ x4 ^ *(rk + 6); x0 = S32(x0); x0 = x1 ^ L32(x0); 
	x1 = x3 ^ x4 ^ x0 ^ *(rk + 7); x1 = S32(x1); x1 = x2 ^ L32(x1); 
	x2 = x4 ^ x0 ^ x1 ^ *(rk + 8); x2 = S32(x2); x2 = x3 ^ L32(x2); 
	x3 = x0 ^ x1 ^ x2 ^ *(rk + 9); x3 = S32(x3); x3 = x4 ^ L32(x3); 
	x4 = x1 ^ x2 ^ x3 ^ *(rk + 10); x4 = S32(x4); x4 = x0 ^ L32(x4); 
	x0 = x2 ^ x3 ^ x4 ^ *(rk + 11); x0 = S32(x0); x0 = x1 ^ L32(x0); 
	x1 = x3 ^ x4 ^ x0 ^ *(rk + 12); x1 = S32(x1); x1 = x2 ^ L32(x1); 
	x2 = x4 ^ x0 ^ x1 ^ *(rk + 13); x2 = S32(x2); x2 = x3 ^ L32(x2); 
	x3 = x0 ^ x1 ^ x2 ^ *(rk + 14); x3 = S32(x3); x3 = x4 ^ L32(x3); 
	x4 = x1 ^ x2 ^ x3 ^ *(rk + 15); x4 = S32(x4); x4 = x0 ^ L32(x4); 
	x0 = x2 ^ x3 ^ x4 ^ *(rk + 16); x0 = S32(x0); x0 = x1 ^ L32(x0); 
	x1 = x3 ^ x4 ^ x0 ^ *(rk + 17); x1 = S32(x1); x1 = x2 ^ L32(x1); 
	x2 = x4 ^ x0 ^ x1 ^ *(rk + 18); x2 = S32(x2); x2 = x3 ^ L32(x2); 
	x3 = x0 ^ x1 ^ x2 ^ *(rk + 19); x3 = S32(x3); x3 = x4 ^ L32(x3); 
	x4 = x1 ^ x2 ^ x3 ^ *(rk + 20); x4 = S32(x4); x4 = x0 ^ L32(x4); 
	x0 = x2 ^ x3 ^ x4 ^ *(rk + 21); x0 = S32(x0); x0 = x1 ^ L32(x0); 
	x1 = x3 ^ x4 ^ x0 ^ *(rk + 22); x1 = S32(x1); x1 = x2 ^ L32(x1); 
	x2 = x4 ^ x0 ^ x1 ^ *(rk + 23); x2 = S32(x2); x2 = x3 ^ L32(x2); 
	x3 = x0 ^ x1 ^ x2 ^ *(rk + 24); x3 = S32(x3); x3 = x4 ^ L32(x3); 
	x4 = x1 ^ x2 ^ x3 ^ *(rk + 25); x4 = S32(x4); x4 = x0 ^ L32(x4); 
	x0 = x2 ^ x3 ^ x4 ^ *(rk + 26); x0 = S32(x0); x0 = x1 ^ L32(x0); 
	x1 = x3 ^ x4 ^ x0 ^ *(rk + 27); x1 = S32(x1); x1 = x2 ^ L32(x1); 
	x2 = x4 ^ x0 ^ x1 ^ *(rk + 28); x2 = S32(x2); x2 = x3 ^ L32(x2); 
	x3 = x0 ^ x1 ^ x2 ^ *(rk + 29); x3 = S32(x3); x3 = x4 ^ L32(x3); 
	x4 = x1 ^ x2 ^ x3 ^ *(rk + 30); x4 = S32(x4); x4 = x0 ^ L32(x4); 
	x0 = x2 ^ x3 ^ x4 ^ *(rk + 31); x0 = S32(x0); x0 = x1 ^ L32(x0);

	(out)[0] = (uint8_t)((x0) >> 24); (out)[1] = (uint8_t)((x0) >> 16); (out)[2] = (uint8_t)((x0) >> 8); (out)[3] = (uint8_t)(x0);
	(out + 4)[0] = (uint8_t)((x4) >> 24); (out + 4)[1] = (uint8_t)((x4) >> 16); (out + 4)[2] = (uint8_t)((x4) >> 8); (out + 4)[3] = (uint8_t)(x4);
	(out + 8)[0] = (uint8_t)((x3) >> 24); (out + 8)[1] = (uint8_t)((x3) >> 16); (out + 8)[2] = (uint8_t)((x3) >> 8); (out + 8)[3] = (uint8_t)(x3);
	(out + 12)[0] = (uint8_t)((x2) >> 24); (out + 12)[1] = (uint8_t)((x2) >> 16); (out + 12)[2] = (uint8_t)((x2) >> 8); (out + 12)[3] = (uint8_t)(x2);

	x0 = x1 = x2 = x3 = x4 = 0;
}

void GMold_sms4_set_encrypt_key(GMold_sms4_key_t *key, const unsigned char *user_key)
{
	uint32_t *rk = key->rk;
	uint32_t x0, x1, x2, x3, x4;

	x0 = ( ((uint32_t)(user_key)[0] << 24) ^ ((uint32_t)(user_key)[1] << 16) ^ ((uint32_t)(user_key)[2] << 8) ^ ((uint32_t)(user_key)[3])) ^ FK[0];
	x1 = ( ((uint32_t)(user_key + 4)[0] << 24) ^ ((uint32_t)(user_key + 4)[1] << 16) ^ ((uint32_t)(user_key + 4)[2] << 8) ^ ((uint32_t)(user_key + 4)[3])) ^ FK[1];
	x2 = ( ((uint32_t)(user_key + 8)[0] << 24) ^ ((uint32_t)(user_key + 8)[1] << 16) ^ ((uint32_t)(user_key + 8)[2] << 8) ^ ((uint32_t)(user_key + 8)[3])) ^ FK[2];
	x3 = ( ((uint32_t)(user_key + 12)[0] << 24) ^ ((uint32_t)(user_key + 12)[1] << 16) ^ ((uint32_t)(user_key + 12)[2] << 8) ^ ((uint32_t)(user_key + 12)[3])) ^ FK[3];

	x4 = x1 ^ x2 ^ x3 ^ *(CK + 0); x4 = S32(x4); x4 = x0 ^ L32_(x4); *(rk + 0) = x4; 
	ENC_ROUND(x1, x2, x3, x4, x0, 1); 
	ENC_ROUND(x2, x3, x4, x0, x1, 2); 
	ENC_ROUND(x3, x4, x0, x1, x2, 3); 
	ENC_ROUND(x4, x0, x1, x2, x3, 4); 
	ENC_ROUND(x0, x1, x2, x3, x4, 5); 
	ENC_ROUND(x1, x2, x3, x4, x0, 6); 
	ENC_ROUND(x2, x3, x4, x0, x1, 7); 
	ENC_ROUND(x3, x4, x0, x1, x2, 8); 
	ENC_ROUND(x4, x0, x1, x2, x3, 9); 
	ENC_ROUND(x0, x1, x2, x3, x4, 10); 
	ENC_ROUND(x1, x2, x3, x4, x0, 11); 
	ENC_ROUND(x2, x3, x4, x0, x1, 12); 
	ENC_ROUND(x3, x4, x0, x1, x2, 13); 
	ENC_ROUND(x4, x0, x1, x2, x3, 14); 
	ENC_ROUND(x0, x1, x2, x3, x4, 15); 
	ENC_ROUND(x1, x2, x3, x4, x0, 16); 
	ENC_ROUND(x2, x3, x4, x0, x1, 17); 
	ENC_ROUND(x3, x4, x0, x1, x2, 18); 
	ENC_ROUND(x4, x0, x1, x2, x3, 19); 
	ENC_ROUND(x0, x1, x2, x3, x4, 20); 
	ENC_ROUND(x1, x2, x3, x4, x0, 21); 
	ENC_ROUND(x2, x3, x4, x0, x1, 22); 
	ENC_ROUND(x3, x4, x0, x1, x2, 23); 
	ENC_ROUND(x4, x0, x1, x2, x3, 24); 
	ENC_ROUND(x0, x1, x2, x3, x4, 25); 
	ENC_ROUND(x1, x2, x3, x4, x0, 26); 
	ENC_ROUND(x2, x3, x4, x0, x1, 27); 
	ENC_ROUND(x3, x4, x0, x1, x2, 28); 
	ENC_ROUND(x4, x0, x1, x2, x3, 29); 
	ENC_ROUND(x0, x1, x2, x3, x4, 30); 
	ENC_ROUND(x1, x2, x3, x4, x0, 31);

	x0 = x1 = x2 = x3 = x4 = 0;
}

void GMold_sms4_set_decrypt_key(GMold_sms4_key_t *key, const unsigned char *user_key)
{
	uint32_t *rk = key->rk;
	uint32_t x0, x1, x2, x3, x4;

	x0 = ( ((uint32_t)(user_key)[0] << 24) ^ ((uint32_t)(user_key)[1] << 16) ^ ((uint32_t)(user_key)[2] << 8) ^ ((uint32_t)(user_key)[3])) ^ FK[0];
	x1 = ( ((uint32_t)(user_key + 4)[0] << 24) ^ ((uint32_t)(user_key + 4)[1] << 16) ^ ((uint32_t)(user_key + 4)[2] << 8) ^ ((uint32_t)(user_key + 4)[3])) ^ FK[1];
	x2 = ( ((uint32_t)(user_key + 8)[0] << 24) ^ ((uint32_t)(user_key + 8)[1] << 16) ^ ((uint32_t)(user_key + 8)[2] << 8) ^ ((uint32_t)(user_key + 8)[3])) ^ FK[2];
	x3 = ( ((uint32_t)(user_key + 12)[0] << 24) ^ ((uint32_t)(user_key + 12)[1] << 16) ^ ((uint32_t)(user_key + 12)[2] << 8) ^ ((uint32_t)(user_key + 12)[3])) ^ FK[3];

	DEC_ROUND(x0, x1, x2, x3, x4, 0); 
	DEC_ROUND(x1, x2, x3, x4, x0, 1); 
	DEC_ROUND(x2, x3, x4, x0, x1, 2); 
	DEC_ROUND(x3, x4, x0, x1, x2, 3); 
	DEC_ROUND(x4, x0, x1, x2, x3, 4); 
	DEC_ROUND(x0, x1, x2, x3, x4, 5); 
	DEC_ROUND(x1, x2, x3, x4, x0, 6); 
	DEC_ROUND(x2, x3, x4, x0, x1, 7); 
	DEC_ROUND(x3, x4, x0, x1, x2, 8); 
	DEC_ROUND(x4, x0, x1, x2, x3, 9); 
	DEC_ROUND(x0, x1, x2, x3, x4, 10); 
	DEC_ROUND(x1, x2, x3, x4, x0, 11); 
	DEC_ROUND(x2, x3, x4, x0, x1, 12); 
	DEC_ROUND(x3, x4, x0, x1, x2, 13); 
	DEC_ROUND(x4, x0, x1, x2, x3, 14); 
	DEC_ROUND(x0, x1, x2, x3, x4, 15); 
	DEC_ROUND(x1, x2, x3, x4, x0, 16); 
	DEC_ROUND(x2, x3, x4, x0, x1, 17); 
	DEC_ROUND(x3, x4, x0, x1, x2, 18); 
	DEC_ROUND(x4, x0, x1, x2, x3, 19); 
	DEC_ROUND(x0, x1, x2, x3, x4, 20); 
	DEC_ROUND(x1, x2, x3, x4, x0, 21); 
	DEC_ROUND(x2, x3, x4, x0, x1, 22); 
	DEC_ROUND(x3, x4, x0, x1, x2, 23); 
	DEC_ROUND(x4, x0, x1, x2, x3, 24); 
	DEC_ROUND(x0, x1, x2, x3, x4, 25); 
	DEC_ROUND(x1, x2, x3, x4, x0, 26); 
	DEC_ROUND(x2, x3, x4, x0, x1, 27); 
	DEC_ROUND(x3, x4, x0, x1, x2, 28); 
	DEC_ROUND(x4, x0, x1, x2, x3, 29); 
	DEC_ROUND(x0, x1, x2, x3, x4, 30); 
	DEC_ROUND(x1, x2, x3, x4, x0, 31);

	x0 = x1 = x2 = x3 = x4 = 0;
}
