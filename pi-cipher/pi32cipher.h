/* pi32cipher.h */
/*
    This file is part of the AVR-Crypto-Lib.
    Copyright (C) 2015 Daniel Otte (daniel.otte@rub.de)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef PI32CIPHER_H_
#define PI32CIPHER_H_

#include <inttypes.h>
#include <stddef.h>

#define PI32_WORD_SIZE 32
#define PI32_N 4

#define PI32_IS_BITS (4 * PI32_N * PI32_WORD_SIZE)

#define PI32_RATE_BITS (PI32_IS_BITS / 2)
#define PI32_CAPACITY_BITS PI32_BITS - PI32_RATE_BITS

#define PI32_RATE_BYTES (PI32_RATE_BITS / 8)
#define PI32_CAPACITY_BYTES (PI32_CAPACITY_BITS / 8)

#define PI32_SMN_LENGTH_BITS  PI32_RATE_BITS
#define PI32_SMN_LENGTH_BYTES (PI32_RATE_BITS / 8)

#define PI32_AD_BLOCK_LENGTH_BITS PI32_RATE_BITS
#define PI32_AD_BLOCK_LENGTH_BYTES (PI32_AD_BLOCK_LENGTH_BITS / 8)

#define PI32_PT_BLOCK_LENGTH_BITS PI32_RATE_BITS
#define PI32_PT_BLOCK_LENGTH_BYTES (PI32_PT_BLOCK_LENGTH_BITS / 8)

#define PI32_CT_BLOCK_LENGTH_BITS PI32_RATE_BITS
#define PI32_CT_BLOCK_LENGTH_BYTES (PI32_CT_BLOCK_LENGTH_BITS / 8)

#define PI32_ROUNDS 3

extern const char* pi32_cipher_name;

typedef struct {
    uint32_t cis[4][4];
    uint32_t tag[8];
    uint64_t ctr;
} pi32_ctx_t;

int pi32_init(
        pi32_ctx_t *ctx,
        const void *key,
        size_t key_length_b,
        const void *pmn,
        size_t pmn_length_b);

void pi32_process_ad_block(
        pi32_ctx_t *ctx,
        const void *ad,
        unsigned long ad_num );

void pi32_process_last_ad_block(
        pi32_ctx_t *ctx,
        const void *ad,
        size_t ad_length_b,
        unsigned long ad_num );

void pi32_process_smn(
        pi32_ctx_t *ctx,
        void *c0,
        const void *smn);

void pi32_decrypt_smn(
        pi32_ctx_t *ctx,
        void *dest,
        const void *src,
		unsigned long  num );

void pi32_encrypt_block(
        pi32_ctx_t *ctx,
        void *dest,
        const void *src,
        unsigned long  num );

void pi32_encrypt_last_block(
        pi32_ctx_t *ctx,
        void *dest,
        const void *src,
        size_t length_b,
		unsigned long  num );

void pi32_extract_tag(
        pi32_ctx_t *ctx,
        void *dest );

void pi32_decrypt_block(
        pi32_ctx_t *ctx,
        void *dest,
        const void *src,
		unsigned long  num );

void pi32_decrypt_last_block(
        pi32_ctx_t *ctx,
        void *dest,
        const void *src,
        size_t length_b,
		unsigned long  num );

void pi32_encrypt_simple(
        void *cipher,
        size_t *cipher_len_B,
        const void *msg,
        size_t msg_len_B,
        const void *ad,
        size_t ad_len_B,
        const void *nonce_secret,
        const void *nonce_public,
        size_t nonce_public_len_B,
        const void *key,
        size_t key_len_B
        );

int pi32_decrypt_simple(
        void *msg,
        size_t *msg_len_B,
		void *nonce_secret,
		const void *cipher,
        size_t cipher_len_B,
        const void *ad,
        size_t ad_len_B,
        const void *nonce_public,
        size_t nonce_public_len_B,
        const void *key,
        size_t key_len_B
        );

#endif /* PI32CIPHER_H_ */
