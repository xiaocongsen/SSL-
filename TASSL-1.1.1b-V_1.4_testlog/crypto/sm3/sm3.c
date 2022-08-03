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
#include "sm3_locl.h"

int sm3_init(SM3_CTX *c)
{
    printf("ddddddddddd sm3_init \n");
    memset(c, 0, sizeof(*c));
    c->A = SM3_A;
    c->B = SM3_B;
    c->C = SM3_C;
    c->D = SM3_D;
    c->E = SM3_E;
    c->F = SM3_F;
    c->G = SM3_G;
    c->H = SM3_H;
    return 1;
}

void GMold_sm3_init(sm3_ctx_t *ctx)
{
    static int index = 0;
    index++;
	ctx->digest[0] = 0x7380166F;
	ctx->digest[1] = 0x4914B2B9;
	ctx->digest[2] = 0x172442D7;
	ctx->digest[3] = 0xDA8A0600;
	ctx->digest[4] = 0xA96F30BC;
	ctx->digest[5] = 0x163138AA;
	ctx->digest[6] = 0xE38DEE4D;
	ctx->digest[7] = 0xB0FB0E4E;

	ctx->nblocks = 0;
	ctx->num = 0;
}

void GMold_sm3_update(sm3_ctx_t *ctx, const unsigned char* data, size_t data_len)
{
    static int index = 0;
    index++;
	if (ctx->num) {
//                {
//                    int gi = 0;
//                    printf("GMold sm3 update begin index=%d data =[",index);
//                    for(gi=0; gi<data_len; gi++){
//                            printf("%02X-", data[gi]);
//                    }
//                    printf("]\n");
//                }         //TODO xcs test
		unsigned int left = SM3_CBLOCK - ctx->num;
		if (data_len < left) {
			memcpy(ctx->block + ctx->num, data, data_len);
			ctx->num += data_len;
//                        {
//                            int gi = 0;
//                            printf("GMold sm3 update end 1 data =[");
//                            for(gi=0; gi<data_len; gi++){
//                                    printf("%02X-", data[gi]);
//                            }
//                            printf("]\n");
//                        }         //TODO xcs test
			return;
		} else {
			memcpy(ctx->block + ctx->num, data, left);
			GMold_sm3_compress(ctx->digest, ctx->block);
			ctx->nblocks++;
			data += left;
			data_len -= left;
		}
	}
	while (data_len >= SM3_CBLOCK) {
		GMold_sm3_compress(ctx->digest, data);
		ctx->nblocks++;
		data += SM3_CBLOCK;
		data_len -= SM3_CBLOCK;
	}
	ctx->num = data_len;
	if (data_len) {
		memcpy(ctx->block, data, data_len);
	}
//        {
//            int gi = 0;
//            printf("GMold sm3 update end 2 data =[");
//            for(gi=0; gi<data_len; gi++){
//                    printf("%02X-", data[gi]);
//            }
//            printf("]\n");
//        }             //TODO xcs test
}

void GMold_sm3_final(sm3_ctx_t *ctx, unsigned char *digest)
{
    static int index = 0;
    index++;
	int i;
	uint32_t *pdigest = (uint32_t *)digest;
	uint32_t *count = (uint32_t *)(ctx->block + SM3_CBLOCK - 8);

	ctx->block[ctx->num] = 0x80;

	if (ctx->num + 9 <= SM3_CBLOCK) {
		memset(ctx->block + ctx->num + 1, 0, SM3_CBLOCK - ctx->num - 9);
	} else {
		memset(ctx->block + ctx->num + 1, 0, SM3_CBLOCK - ctx->num - 1);
		GMold_sm3_compress(ctx->digest, ctx->block);
		memset(ctx->block, 0, SM3_CBLOCK - 8);
	}

	count[0] = ((((ctx->nblocks) >> 23)>>24) | ((((ctx->nblocks) >> 23)>>8)&0xff00) | ((((ctx->nblocks) >> 23)<<8)&0xff0000) | (((ctx->nblocks) >> 23)<<24));
	count[1] = ((((ctx->nblocks << 9) + (ctx->num << 3))>>24) | ((((ctx->nblocks << 9) + (ctx->num << 3))>>8)&0xff00) | ((((ctx->nblocks << 9) + (ctx->num << 3))<<8)&0xff0000) | (((ctx->nblocks << 9) + (ctx->num << 3))<<24));

	GMold_sm3_compress(ctx->digest, ctx->block);
	for (i = 0; i < sizeof(ctx->digest)/sizeof(ctx->digest[0]); i++) {
		pdigest[i] = (((ctx->digest[i])>>24) | (((ctx->digest[i])>>8)&0xff00) | (((ctx->digest[i])<<8)&0xff0000) | ((ctx->digest[i])<<24));
	}
}

void sm3_block_data_order(SM3_CTX *ctx, const void *p, size_t num)
{
    printf("ddddddddddd sm3_block_data_order \n");
    const unsigned char *data = p;
    register unsigned MD32_REG_T A, B, C, D, E, F, G, H;

    unsigned MD32_REG_T W00, W01, W02, W03, W04, W05, W06, W07,
        W08, W09, W10, W11, W12, W13, W14, W15;

    for (; num--;) {

        A = ctx->A;
        B = ctx->B;
        C = ctx->C;
        D = ctx->D;
        E = ctx->E;
        F = ctx->F;
        G = ctx->G;
        H = ctx->H;

        /*
        * We have to load all message bytes immediately since SM3 reads
        * them slightly out of order.
        */
        (void)HOST_c2l(data, W00);
        (void)HOST_c2l(data, W01);
        (void)HOST_c2l(data, W02);
        (void)HOST_c2l(data, W03);
        (void)HOST_c2l(data, W04);
        (void)HOST_c2l(data, W05);
        (void)HOST_c2l(data, W06);
        (void)HOST_c2l(data, W07);
        (void)HOST_c2l(data, W08);
        (void)HOST_c2l(data, W09);
        (void)HOST_c2l(data, W10);
        (void)HOST_c2l(data, W11);
        (void)HOST_c2l(data, W12);
        (void)HOST_c2l(data, W13);
        (void)HOST_c2l(data, W14);
        (void)HOST_c2l(data, W15);

        R1(A, B, C, D, E, F, G, H, 0x79CC4519, W00, W00 ^ W04);
        W00 = EXPAND(W00, W07, W13, W03, W10);
        R1(D, A, B, C, H, E, F, G, 0xF3988A32, W01, W01 ^ W05);
        W01 = EXPAND(W01, W08, W14, W04, W11);
        R1(C, D, A, B, G, H, E, F, 0xE7311465, W02, W02 ^ W06);
        W02 = EXPAND(W02, W09, W15, W05, W12);
        R1(B, C, D, A, F, G, H, E, 0xCE6228CB, W03, W03 ^ W07);
        W03 = EXPAND(W03, W10, W00, W06, W13);
        R1(A, B, C, D, E, F, G, H, 0x9CC45197, W04, W04 ^ W08);
        W04 = EXPAND(W04, W11, W01, W07, W14);
        R1(D, A, B, C, H, E, F, G, 0x3988A32F, W05, W05 ^ W09);
        W05 = EXPAND(W05, W12, W02, W08, W15);
        R1(C, D, A, B, G, H, E, F, 0x7311465E, W06, W06 ^ W10);
        W06 = EXPAND(W06, W13, W03, W09, W00);
        R1(B, C, D, A, F, G, H, E, 0xE6228CBC, W07, W07 ^ W11);
        W07 = EXPAND(W07, W14, W04, W10, W01);
        R1(A, B, C, D, E, F, G, H, 0xCC451979, W08, W08 ^ W12);
        W08 = EXPAND(W08, W15, W05, W11, W02);
        R1(D, A, B, C, H, E, F, G, 0x988A32F3, W09, W09 ^ W13);
        W09 = EXPAND(W09, W00, W06, W12, W03);
        R1(C, D, A, B, G, H, E, F, 0x311465E7, W10, W10 ^ W14);
        W10 = EXPAND(W10, W01, W07, W13, W04);
        R1(B, C, D, A, F, G, H, E, 0x6228CBCE, W11, W11 ^ W15);
        W11 = EXPAND(W11, W02, W08, W14, W05);
        R1(A, B, C, D, E, F, G, H, 0xC451979C, W12, W12 ^ W00);
        W12 = EXPAND(W12, W03, W09, W15, W06);
        R1(D, A, B, C, H, E, F, G, 0x88A32F39, W13, W13 ^ W01);
        W13 = EXPAND(W13, W04, W10, W00, W07);
        R1(C, D, A, B, G, H, E, F, 0x11465E73, W14, W14 ^ W02);
        W14 = EXPAND(W14, W05, W11, W01, W08);
        R1(B, C, D, A, F, G, H, E, 0x228CBCE6, W15, W15 ^ W03);
        W15 = EXPAND(W15, W06, W12, W02, W09);
        R2(A, B, C, D, E, F, G, H, 0x9D8A7A87, W00, W00 ^ W04);
        W00 = EXPAND(W00, W07, W13, W03, W10);
        R2(D, A, B, C, H, E, F, G, 0x3B14F50F, W01, W01 ^ W05);
        W01 = EXPAND(W01, W08, W14, W04, W11);
        R2(C, D, A, B, G, H, E, F, 0x7629EA1E, W02, W02 ^ W06);
        W02 = EXPAND(W02, W09, W15, W05, W12);
        R2(B, C, D, A, F, G, H, E, 0xEC53D43C, W03, W03 ^ W07);
        W03 = EXPAND(W03, W10, W00, W06, W13);
        R2(A, B, C, D, E, F, G, H, 0xD8A7A879, W04, W04 ^ W08);
        W04 = EXPAND(W04, W11, W01, W07, W14);
        R2(D, A, B, C, H, E, F, G, 0xB14F50F3, W05, W05 ^ W09);
        W05 = EXPAND(W05, W12, W02, W08, W15);
        R2(C, D, A, B, G, H, E, F, 0x629EA1E7, W06, W06 ^ W10);
        W06 = EXPAND(W06, W13, W03, W09, W00);
        R2(B, C, D, A, F, G, H, E, 0xC53D43CE, W07, W07 ^ W11);
        W07 = EXPAND(W07, W14, W04, W10, W01);
        R2(A, B, C, D, E, F, G, H, 0x8A7A879D, W08, W08 ^ W12);
        W08 = EXPAND(W08, W15, W05, W11, W02);
        R2(D, A, B, C, H, E, F, G, 0x14F50F3B, W09, W09 ^ W13);
        W09 = EXPAND(W09, W00, W06, W12, W03);
        R2(C, D, A, B, G, H, E, F, 0x29EA1E76, W10, W10 ^ W14);
        W10 = EXPAND(W10, W01, W07, W13, W04);
        R2(B, C, D, A, F, G, H, E, 0x53D43CEC, W11, W11 ^ W15);
        W11 = EXPAND(W11, W02, W08, W14, W05);
        R2(A, B, C, D, E, F, G, H, 0xA7A879D8, W12, W12 ^ W00);
        W12 = EXPAND(W12, W03, W09, W15, W06);
        R2(D, A, B, C, H, E, F, G, 0x4F50F3B1, W13, W13 ^ W01);
        W13 = EXPAND(W13, W04, W10, W00, W07);
        R2(C, D, A, B, G, H, E, F, 0x9EA1E762, W14, W14 ^ W02);
        W14 = EXPAND(W14, W05, W11, W01, W08);
        R2(B, C, D, A, F, G, H, E, 0x3D43CEC5, W15, W15 ^ W03);
        W15 = EXPAND(W15, W06, W12, W02, W09);
        R2(A, B, C, D, E, F, G, H, 0x7A879D8A, W00, W00 ^ W04);
        W00 = EXPAND(W00, W07, W13, W03, W10);
        R2(D, A, B, C, H, E, F, G, 0xF50F3B14, W01, W01 ^ W05);
        W01 = EXPAND(W01, W08, W14, W04, W11);
        R2(C, D, A, B, G, H, E, F, 0xEA1E7629, W02, W02 ^ W06);
        W02 = EXPAND(W02, W09, W15, W05, W12);
        R2(B, C, D, A, F, G, H, E, 0xD43CEC53, W03, W03 ^ W07);
        W03 = EXPAND(W03, W10, W00, W06, W13);
        R2(A, B, C, D, E, F, G, H, 0xA879D8A7, W04, W04 ^ W08);
        W04 = EXPAND(W04, W11, W01, W07, W14);
        R2(D, A, B, C, H, E, F, G, 0x50F3B14F, W05, W05 ^ W09);
        W05 = EXPAND(W05, W12, W02, W08, W15);
        R2(C, D, A, B, G, H, E, F, 0xA1E7629E, W06, W06 ^ W10);
        W06 = EXPAND(W06, W13, W03, W09, W00);
        R2(B, C, D, A, F, G, H, E, 0x43CEC53D, W07, W07 ^ W11);
        W07 = EXPAND(W07, W14, W04, W10, W01);
        R2(A, B, C, D, E, F, G, H, 0x879D8A7A, W08, W08 ^ W12);
        W08 = EXPAND(W08, W15, W05, W11, W02);
        R2(D, A, B, C, H, E, F, G, 0x0F3B14F5, W09, W09 ^ W13);
        W09 = EXPAND(W09, W00, W06, W12, W03);
        R2(C, D, A, B, G, H, E, F, 0x1E7629EA, W10, W10 ^ W14);
        W10 = EXPAND(W10, W01, W07, W13, W04);
        R2(B, C, D, A, F, G, H, E, 0x3CEC53D4, W11, W11 ^ W15);
        W11 = EXPAND(W11, W02, W08, W14, W05);
        R2(A, B, C, D, E, F, G, H, 0x79D8A7A8, W12, W12 ^ W00);
        W12 = EXPAND(W12, W03, W09, W15, W06);
        R2(D, A, B, C, H, E, F, G, 0xF3B14F50, W13, W13 ^ W01);
        W13 = EXPAND(W13, W04, W10, W00, W07);
        R2(C, D, A, B, G, H, E, F, 0xE7629EA1, W14, W14 ^ W02);
        W14 = EXPAND(W14, W05, W11, W01, W08);
        R2(B, C, D, A, F, G, H, E, 0xCEC53D43, W15, W15 ^ W03);
        W15 = EXPAND(W15, W06, W12, W02, W09);
        R2(A, B, C, D, E, F, G, H, 0x9D8A7A87, W00, W00 ^ W04);
        W00 = EXPAND(W00, W07, W13, W03, W10);
        R2(D, A, B, C, H, E, F, G, 0x3B14F50F, W01, W01 ^ W05);
        W01 = EXPAND(W01, W08, W14, W04, W11);
        R2(C, D, A, B, G, H, E, F, 0x7629EA1E, W02, W02 ^ W06);
        W02 = EXPAND(W02, W09, W15, W05, W12);
        R2(B, C, D, A, F, G, H, E, 0xEC53D43C, W03, W03 ^ W07);
        W03 = EXPAND(W03, W10, W00, W06, W13);
        R2(A, B, C, D, E, F, G, H, 0xD8A7A879, W04, W04 ^ W08);
        R2(D, A, B, C, H, E, F, G, 0xB14F50F3, W05, W05 ^ W09);
        R2(C, D, A, B, G, H, E, F, 0x629EA1E7, W06, W06 ^ W10);
        R2(B, C, D, A, F, G, H, E, 0xC53D43CE, W07, W07 ^ W11);
        R2(A, B, C, D, E, F, G, H, 0x8A7A879D, W08, W08 ^ W12);
        R2(D, A, B, C, H, E, F, G, 0x14F50F3B, W09, W09 ^ W13);
        R2(C, D, A, B, G, H, E, F, 0x29EA1E76, W10, W10 ^ W14);
        R2(B, C, D, A, F, G, H, E, 0x53D43CEC, W11, W11 ^ W15);
        R2(A, B, C, D, E, F, G, H, 0xA7A879D8, W12, W12 ^ W00);
        R2(D, A, B, C, H, E, F, G, 0x4F50F3B1, W13, W13 ^ W01);
        R2(C, D, A, B, G, H, E, F, 0x9EA1E762, W14, W14 ^ W02);
        R2(B, C, D, A, F, G, H, E, 0x3D43CEC5, W15, W15 ^ W03);

        ctx->A ^= A;
        ctx->B ^= B;
        ctx->C ^= C;
        ctx->D ^= D;
        ctx->E ^= E;
        ctx->F ^= F;
        ctx->G ^= G;
        ctx->H ^= H;
    }
}

#define ROTATELEFT(X,n)  (((X)<<(n)) | ((X)>>(32-(n))))

#define P0(x) ((x) ^  ROTATELEFT((x),9)  ^ ROTATELEFT((x),17))
#define P1(x) ((x) ^  ROTATELEFT((x),15) ^ ROTATELEFT((x),23))

#define FF0(x,y,z) ( (x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z))
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )

void GMold_sm3_compress(uint32_t digest[8], const unsigned char block[64])
{
	int j;
	uint32_t W[68], W1[64];
	const uint32_t *pblock = (const uint32_t *)block;

	uint32_t A = digest[0];
	uint32_t B = digest[1];
	uint32_t C = digest[2];
	uint32_t D = digest[3];
	uint32_t E = digest[4];
	uint32_t F = digest[5];
	uint32_t G = digest[6];
	uint32_t H = digest[7];
	uint32_t SS1,SS2,TT1,TT2,T[64];

	for (j = 0; j < 16; j++) {
		W[j] = (((pblock[j])>>24) | (((pblock[j])>>8)&0xff00) | (((pblock[j])<<8)&0xff0000) | ((pblock[j])<<24));
	}
	for (j = 16; j < 68; j++) {
		W[j] = P1( W[j-16] ^ W[j-9] ^ ROTATELEFT(W[j-3],15)) ^ ROTATELEFT(W[j - 13],7 ) ^ W[j-6];;
	}
	for( j = 0; j < 64; j++) {
		W1[j] = W[j] ^ W[j+4];
	}

	for(j =0; j < 16; j++) {

		T[j] = 0x79CC4519;
		SS1 = ROTATELEFT((ROTATELEFT(A,12) + E + ROTATELEFT(T[j],j)), 7);
		SS2 = SS1 ^ ROTATELEFT(A,12);
		TT1 = FF0(A,B,C) + D + SS2 + W1[j];
		TT2 = GG0(E,F,G) + H + SS1 + W[j];
		D = C;
		C = ROTATELEFT(B,9);
		B = A;
		A = TT1;
		H = G;
		G = ROTATELEFT(F,19);
		F = E;
		E = P0(TT2);
	}

	for(j =16; j < 64; j++) {

		T[j] = 0x7A879D8A;
		SS1 = ROTATELEFT((ROTATELEFT(A,12) + E + ROTATELEFT(T[j],j)), 7);
		SS2 = SS1 ^ ROTATELEFT(A,12);
		TT1 = FF1(A,B,C) + D + SS2 + W1[j];
		TT2 = GG1(E,F,G) + H + SS1 + W[j];
		D = C;
		C = ROTATELEFT(B,9);
		B = A;
		A = TT1;
		H = G;
		G = ROTATELEFT(F,19);
		F = E;
		E = P0(TT2);
	}

	digest[0] ^= A;
	digest[1] ^= B;
	digest[2] ^= C;
	digest[3] ^= D;
	digest[4] ^= E;
	digest[5] ^= F;
	digest[6] ^= G;
	digest[7] ^= H;
}
