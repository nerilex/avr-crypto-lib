/* pi16cipher.h */
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

#ifndef PI16CIPHER_H_
#define PI16CIPHER_H_

#include <inttypes.h>
#include <stddef.h>

#define PI16_WORD_SIZE 16
#define PI16_N 4

#define PI16_IS_BITS (4 * PI16_N * PI16_WORD_SIZE)

#define PI16_RATE_BITS (PI16_IS_BITS / 2)
#define PI16_CAPACITY_BITS PI16_BITS - PI16_RATE_BITS

#define PI16_RATE_BYTES (PI16_RATE_BITS / 8)
#define PI16_CAPACITY_BYTES (PI16_CAPACITY_BITS / 8)

#define PI16_SMN_LENGTH_BITS  PI16_RATE_BITS
#define PI16_SMN_LENGTH_BYTES (PI16_RATE_BITS / 8)

#define PI16_AD_BLOCK_LENGTH_BITS PI16_RATE_BITS
#define PI16_AD_BLOCK_LENGTH_BYTES (PI16_AD_BLOCK_LENGTH_BITS / 8)

#define PI16_PT_BLOCK_LENGTH_BITS PI16_RATE_BITS
#define PI16_PT_BLOCK_LENGTH_BYTES (PI16_PT_BLOCK_LENGTH_BITS / 8)

#define PI16_CT_BLOCK_LENGTH_BITS PI16_RATE_BITS
#define PI16_CT_BLOCK_LENGTH_BYTES (PI16_CT_BLOCK_LENGTH_BITS / 8)

#define PI16_ROUNDS 3

extern const char* pi16_cipher_name;

typedef struct {
    uint16_t cis[4][4];
    uint16_t tag[8];
    uint64_t ctr;
} pi16_ctx_t;

int pi16_init(
        pi16_ctx_t *ctx,
        const void *key,
        size_t key_length_b,
        const void *pmn,
        size_t pmn_length_b);

void pi16_process_ad_block(
        pi16_ctx_t *ctx,
        const void *ad,
        unsigned long ad_num );

void pi16_process_ad_last_block(
        pi16_ctx_t *ctx,
        const void *ad,
        size_t ad_length_b,
        unsigned long ad_num );

void pi16_encrypt_smn(
        pi16_ctx_t *ctx,
        void *c0,
        const void *smn);

void pi16_decrypt_smn(
        pi16_ctx_t *ctx,
        void *dest,
        const void *src,
		unsigned long  num );

void pi16_encrypt_block(
        pi16_ctx_t *ctx,
        void *dest,
        const void *src,
        unsigned long  num );

void pi16_encrypt_last_block(
        pi16_ctx_t *ctx,
        void *dest,
        const void *src,
        size_t length_b,
		unsigned long  num );

void pi16_extract_tag(
        pi16_ctx_t *ctx,
        void *dest );

void pi16_decrypt_block(
        pi16_ctx_t *ctx,
        void *dest,
        const void *src,
		unsigned long  num );

void pi16_decrypt_last_block(
        pi16_ctx_t *ctx,
        void *dest,
        const void *src,
        size_t length_b,
		unsigned long  num );

void pi16_encrypt_simple(
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

int pi16_decrypt_simple(
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

#endif /* PI16CIPHER_H_ */
