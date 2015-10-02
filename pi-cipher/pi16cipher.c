/* pi16cipher.c */
/*
    This file is part of the AVR-Crypto-Lib.
    Copyright (C) 2006-2015 Daniel Otte (bg@nerilex.org)

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

#define PI_SIZE 16


#include <string.h>
#include <stdlib.h>
#include <avr/pgmspace.h>
#include "pi-cipher.h"

#define MAX(a,b) ((a) > (b) ? (a) : (b))
#define MIN(a,b) ((a) < (b) ? (a) : (b))

#define DEBUG 0

#if (PI_WORD_SIZE == 16)
#  define load_word_little(mem) load_u16_little(mem)
#  define store_word_little(mem, val) store_u16_little((mem), (val))
#  define PRI_xw "04"PRIx16


#elif (PI_WORD_SIZE == 32)
#  define load_word_little(mem) load_u32_little(mem)
#  define store_word_little(mem, val) store_u32_little((mem), (val))
#  define PRI_xw "08"PRIx32

static uint32_t load_u32_little(const void *mem)
{
    uint32_t ret;
    const uint8_t *x = (const uint8_t *)mem;
    ret =   (uint32_t)x[0] <<  0
          | (uint32_t)x[1] <<  8
          | (uint32_t)x[2] << 16
          | (uint32_t)x[3] << 24;
    return ret;
}

static void store_u32_little(void *mem, uint32_t val)
{
    uint8_t *x = (uint8_t *)mem;
    x[0] = val & 0xff; val >>= 8;
    x[1] = val & 0xff; val >>= 8;
    x[2] = val & 0xff; val >>= 8;
    x[3] = val & 0xff;
}

#elif (PI_WORD_SIZE == 64)
#  define load_word_little(mem) load_u64_little(mem)
#  define store_word_little(mem, val) store_u64_little((mem), (val))
#  define PRI_xw "016"PRIx64

static uint64_t load_u64_little(const void *mem)
{
    uint64_t ret;
    const uint8_t *x = (const uint8_t *)mem;
    ret =   (uint64_t)x[0] <<  0
          | (uint64_t)x[1] <<  8
          | (uint64_t)x[2] << 16
          | (uint64_t)x[3] << 24
          | (uint64_t)x[4] << 32
          | (uint64_t)x[5] << 40
          | (uint64_t)x[6] << 48
          | (uint64_t)x[7] << 56;
    return ret;
}

static void store_u64_little(void *mem, uint64_t val)
{
    uint8_t *x = (uint8_t *)mem;
    x[0] = val & 0xff; val >>= 8;
    x[1] = val & 0xff; val >>= 8;
    x[2] = val & 0xff; val >>= 8;
    x[3] = val & 0xff; val >>= 8;
    x[4] = val & 0xff; val >>= 8;
    x[5] = val & 0xff; val >>= 8;
    x[6] = val & 0xff; val >>= 8;
    x[7] = val & 0xff;
}

#endif


typedef word_t state_t[4][4];
const char* PI_CIPHER_NAME_X = XSTR(PI_CIPHER_NAME);


#if DEBUG
#include <stdio.h>
#include <inttypes.h>

size_t dbg_l;
const uint8_t *dbg_x;
uint8_t dump;


static
void hexdump_block(
        const void *data,
        size_t length,
        unsigned short indent,
        unsigned short width)
{
    unsigned short column = 0;
    char f = 0;
    while (length--) {
        if (column == 0) {
            unsigned short i;
            if (f) {
                putchar('\n');
            } else {
                f = 1;
            }
            for (i = 0; i < indent; ++i) {
                putchar(' ');
            }
            column = width;
        }
        column -= 1;
        printf("%02x ", *((unsigned char *)data));
        data = (void *)((char *)data + 1);
    }
}

//static
void dump_state(const word_t* a)
{
    if (dump || 1) {
        printf("\tCIS:\n");
        printf("\t%"PRI_xw" %"PRI_xw" %"PRI_xw" %"PRI_xw"\n",   a[ 0], a[ 1], a[ 2], a[ 3]);
        printf("\t%"PRI_xw" %"PRI_xw" %"PRI_xw" %"PRI_xw"\n",   a[ 4], a[ 5], a[ 6], a[ 7]);
        printf("\t%"PRI_xw" %"PRI_xw" %"PRI_xw" %"PRI_xw"\n",   a[ 8], a[ 9], a[10], a[11]);
        printf("\t%"PRI_xw" %"PRI_xw" %"PRI_xw" %"PRI_xw"\n\n", a[12], a[13], a[14], a[15]);
    }
}
#else
#define printf(...)
#endif

void pi(
        word_t *a );

void add_tag(
        PI_CTX *ctx,
        state_t a );

void ctr_trans(
        const PI_CTX *ctx,
        state_t a,
        uint32_t ctr );

void inject_tag(
        state_t a,
        const word_t x[8] );


void extract_block(
        void *block,
        state_t a);

void inject_block(
        state_t a,
        const void *block );

void inject_last_block(
        state_t a,
        const void *block,
        size_t length_B );

void replace_block(
        state_t a,
        const void *block );

void replace_last_block(
        state_t a,
        const void *block,
        size_t length_B  );
/*
void PI_ENCRYPT_SIMPLE(
        void *cipher,
        size_t *cipher_len_B,
        void *tag,
        size_t *tag_length_B,
        const void *msg,
        size_t msg_len_B,
        const void *ad,
        size_t ad_len_B,
        const void *nonce_secret,
        const void *nonce_public,
        size_t nonce_public_len_B,
        const void *key,
        size_t key_len_B
        )
{
    unsigned i;
    PI_CTX ctx;
    if (PI_INIT(&ctx, key, key_len_B, nonce_public, nonce_public_len_B)) {
        printf("ERROR! <%s %s %d>\n", __FILE__, __func__, __LINE__);
        return;
    }
    i = 1;
    while (ad_len_B >= PI_AD_BLOCK_LENGTH_BYTES) {
        PI_PROCESS_AD_BLOCK(&ctx, ad, i++);
        ad_len_B -= PI_AD_BLOCK_LENGTH_BYTES;
        ad = &((const uint8_t*)ad)[PI_AD_BLOCK_LENGTH_BYTES];
    }
    PI_PROCESS_AD_LAST_BLOCK(&ctx, ad, ad_len_B, i);
    *cipher_len_B = 0;
    if (nonce_secret) {
        PI_ENCRYPT_SMN(&ctx, cipher, nonce_secret);
        *cipher_len_B += PI_CT_BLOCK_LENGTH_BYTES;
        cipher = &((uint8_t*)cipher)[PI_CT_BLOCK_LENGTH_BYTES];
    }
    i = 1;
/ *
    while (msg_len_B >= PI_PT_BLOCK_LENGTH_BYTES) {
        PI_ENCRYPT_BLOCK(&ctx, cipher, msg, i++);
        msg = &((const uint8_t*)msg)[PI_PT_BLOCK_LENGTH_BYTES];
        cipher = &((uint8_t*)cipher)[PI_CT_BLOCK_LENGTH_BYTES];
        *cipher_len_B += PI_CT_BLOCK_LENGTH_BYTES;
        msg_len_B -= PI_PT_BLOCK_LENGTH_BYTES;
    }
* /
    PI_ENCRYPT_LAST_BLOCK(&ctx, cipher, msg, msg_len_B, i);
    *cipher_len_B += msg_len_B;
    PI_EXTRACT_TAG(&ctx, tag);
    if (tag_length_B) {
        *tag_length_B = PI_TAG_BYTES;
    }
}
*/
/*
int PI_DECRYPT_SIMPLE(
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
        )
{
    unsigned i;
    PI_CTX ctx;

    unsigned long clen = cipher_len_B, alen = ad_len_B;
    uint8_t bck_c[clen], bck_ad[alen];
    memcpy(bck_c, cipher, clen);
    memcpy(bck_ad, ad, alen);

    uint8_t tmp_tag[PI_TAG_BYTES];
    if (nonce_secret && (cipher_len_B < PI_CT_BLOCK_LENGTH_BYTES + PI_TAG_BYTES)) {
        return -3;
    }
    if (PI_INIT(&ctx, key, key_len_B, nonce_public, nonce_public_len_B)) {
        printf("ERROR! <%s %s %d>\n", __FILE__, __func__, __LINE__);
        return -2;
    }
    i = 1;
    while (ad_len_B >= PI_AD_BLOCK_LENGTH_BYTES) {
        PI_PROCESS_AD_BLOCK(&ctx, ad, i++);
        ad_len_B -= PI_AD_BLOCK_LENGTH_BYTES;
        ad = &((const uint8_t*)ad)[PI_AD_BLOCK_LENGTH_BYTES];
    }
    PI_PROCESS_AD_LAST_BLOCK(&ctx, ad, ad_len_B, i);
    *msg_len_B = 0;
    if (nonce_secret) {
        PI_DECRYPT_SMN(&ctx, nonce_secret, cipher);
        cipher_len_B -= PI_CT_BLOCK_LENGTH_BYTES;
    cipher = &((uint8_t*)cipher)[PI_CT_BLOCK_LENGTH_BYTES];
    }
    i = 1;
    while (cipher_len_B - PI_TAG_BYTES >= PI_PT_BLOCK_LENGTH_BYTES) {
        PI_DECRYPT_BLOCK(&ctx, msg, cipher, i++);
        msg = &((uint8_t*)msg)[PI_PT_BLOCK_LENGTH_BYTES];
        cipher = &((uint8_t*)cipher)[PI_CT_BLOCK_LENGTH_BYTES];
        cipher_len_B -= PI_CT_BLOCK_LENGTH_BYTES;
        *msg_len_B += PI_PT_BLOCK_LENGTH_BYTES;
    }
    PI_DECRYPT_LAST_BLOCK(&ctx, msg, cipher, cipher_len_B - PI_TAG_BYTES, i);
    *msg_len_B += cipher_len_B - PI_TAG_BYTES;
    cipher = &((uint8_t*)cipher)[cipher_len_B - PI_TAG_BYTES];
    PI_EXTRACT_TAG(&ctx, tmp_tag);
    if (memcmp(tmp_tag, cipher, PI_TAG_BYTES)) {
#if DEBUG
        printf("DBG: verification failed: clen = %lu; alen = %lu\n", clen, alen);
        printf("Key:\n");
        hexdump_block(key, key_len_B, 4, 16);
        printf("\nNonce:\n");
        hexdump_block(nonce_public, nonce_public_len_B, 4, 16);
        printf("\nAD:\n");
        hexdump_block(bck_ad, alen, 4, 16);
        printf("\nCiphertext:\n");
        hexdump_block(bck_c, clen, 4, 16);
        printf("\nShould-Tag:\n");
        hexdump_block(cipher, PI_TAG_BYTES, 4, 16);
        printf("\nIS-Tag:\n");
        hexdump_block(tmp_tag, PI_TAG_BYTES, 4, 16);
        puts("");
#endif
        return -1;
    }
    return 0;
}
*/
