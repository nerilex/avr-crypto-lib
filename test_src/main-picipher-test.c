/* main-picipher-test.c */
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



#include "main-test-common.h"

#include <pi16cipher.h>
#include <pi32cipher.h>
#include <pi64cipher.h>

#include <arcfour.h>
#include "performance_test.h"

char *algo_name = "pi16cipher";

/*****************************************************************************
 *  additional validation-functions                                          *
 *****************************************************************************/

#define DUMP_LEN(x, s) do {                   \
    printf("%s", "\n\n" #x ":");              \
    cli_hexdump_block((x), (s), 4, 16);       \
    uart0_flush();                            \
} while (0)

#define DUMP(x) DUMP_LEN((x), (sizeof(x)))

arcfour_ctx_t prng;

static
void fill_random(void *buf, size_t length) {
    while (length--) {
        *(uint8_t *)buf = arcfour_gen(&prng);
        buf = (uint8_t *)buf + 1;
    }
}

void testrun_performance_pi16cipher(void){
    pi16_ctx_t ctx;
    uint32_t t;
    const uint8_t key[16] = { 15, 14, 13, 12 , 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
    uint8_t msg[19] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 };
    const uint8_t ad[17] = { 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34 };
    uint8_t nsec[16] = { 0xff, 0x00, 0xff, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 };
    const uint8_t npub[4] = { 10, 11, 12, 13 };
    uint8_t crypt[16 + 19 + 16];
    uint8_t *tag = &crypt[16 + 19];
//    size_t crypt_len, tag_len, msg_len = sizeof(msg);
//    int v;

    calibrateTimer();
    print_overhead();

    uart0_flush();
    startTimer(1);
    pi16_init(&ctx, key, sizeof(key), npub, sizeof(npub));
    t = stopTimer();
    printf_P(PSTR("\tinit time (16 + 4)           : %10"PRIu32"\n"), t);
    uart0_flush();
    startTimer(1);
    pi16_process_ad_block(&ctx, ad, 1);
    t = stopTimer();
    printf_P(PSTR("\tprocess ad(16)               : %10"PRIu32"\n"), t);
    uart0_flush();
    startTimer(1);
    pi16_process_ad_last_block(&ctx, &ad[16], 1, 2);
    t = stopTimer();
    printf_P(PSTR("\tprocess last ad(1)           : %10"PRIu32"\n"), t);
    uart0_flush();
    startTimer(1);
    pi16_encrypt_smn(&ctx, crypt, nsec);
    t = stopTimer();
    printf_P(PSTR("\tprocess smn(16)              : %10"PRIu32"\n"), t);
    uart0_flush();
    startTimer(1);
    pi16_encrypt_block(&ctx, &crypt[16], msg, 1);
    t = stopTimer();
    printf_P(PSTR("\tprocess encrypt block(16)    : %10"PRIu32"\n"), t);
    uart0_flush();
    startTimer(1);
    pi16_encrypt_last_block(&ctx, &crypt[32], &msg[16], 3, 2);
    t = stopTimer();
    printf_P(PSTR("\tprocess encrypt last block(3): %10"PRIu32"\n"), t);
    uart0_flush();
    startTimer(1);
    pi16_extract_tag(&ctx, tag);
    t = stopTimer();
    printf_P(PSTR("\tprocess extract tag(16)      : %10"PRIu32"\n"), t);
}

void testrun_pi16(void)
{
    const uint8_t key[16] = { 15, 14, 13, 12 , 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 };
    uint8_t msg[19] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 };
    const uint8_t ad[17] = { 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34 };
    uint8_t nsec[16] = { 0xff, 0x00, 0xff, 0x00, 0xff, 0xff, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 };
    const uint8_t npub[4] = { 10, 11, 12, 13 };
    uint8_t crypt[16 + 19 + 16];
    size_t crypt_len, msg_len = sizeof(msg);
    int v;
//    printf("crypt = %p, crypt_len = %d, tag = %p, tag_len = %d\n", crypt, crypt_len, tag, tag_len);
    pi16_encrypt_simple(crypt, &crypt_len, msg, sizeof(msg), ad, sizeof(ad), nsec, npub, sizeof(npub), key, sizeof(key));
//    printf("crypt = %p, crypt_len = %d, tag = %p, tag_len = %d\n", crypt, crypt_len, tag, tag_len);
    DUMP(key);
    DUMP(msg);
    DUMP(ad);
    DUMP(nsec);
    DUMP(npub);
    DUMP_LEN(crypt, crypt_len);
    puts("");
    crypt[0] ^= 0;
    v = pi16_decrypt_simple(msg, &msg_len, nsec, crypt, crypt_len, ad, sizeof(ad), npub, sizeof(npub), key, sizeof(key));
    DUMP(key);
    DUMP(msg);
    DUMP(ad);
    DUMP(nsec);
    DUMP(npub);
    DUMP_LEN(crypt, crypt_len);
    printf("\nverification: >> %s (%d) <<\n", v ? "FAILED!" : "ok", v);
    puts("");
}

void testrun_pi32(void)
{
    const uint8_t key[16] = { 0 };
    const uint8_t msg[1] = { 0xf };
    const uint8_t ad[1] = { 0 };
    const uint8_t nsec[PI32_SMN_LENGTH_BYTES] = { 0 };
    const uint8_t npub[16] = { 0 };
    uint8_t crypt[sizeof(nsec) + sizeof(msg) + 32];
    uint16_t crypt_len;
    pi32_encrypt_simple(crypt, &crypt_len, msg, sizeof(msg), ad, sizeof(ad), nsec, npub, sizeof(npub), key, sizeof(key));
    DUMP(key);
    DUMP(msg);
    DUMP(ad);
    DUMP(nsec);
    DUMP(npub);
    DUMP(crypt);
}

void testrun_pi64(void)
{
    const uint8_t key[16] = { 0 };
    const uint8_t msg[1] = { 0xf };
    const uint8_t ad[1] = { 0 };
    const uint8_t nsec[PI64_SMN_LENGTH_BYTES] = { 0 };
    const uint8_t npub[16] = { 0 };
    uint8_t crypt[sizeof(nsec) + sizeof(msg) + 64];
    uint16_t crypt_len;
    pi64_encrypt_simple(crypt, &crypt_len, msg, sizeof(msg), ad, sizeof(ad), nsec, npub, sizeof(npub), key, sizeof(key));
    DUMP(key);
    DUMP(msg);
    DUMP(ad);
    DUMP(nsec);
    DUMP(npub);
    DUMP(crypt);
}

void testrun(void) {
    testrun_pi16();
    testrun_pi32();
    testrun_pi64();
}

static
void print_item(const char *label, const void* data, size_t length) {
    printf("%s (%u) = ", label, length);
    while (length--) {
        printf("%02X", *(uint8_t*)data);
        data = (uint8_t*)data + 1;
    }
    putchar('\n');
}

void generate_single_testvector(
        const uint8_t *m, size_t mlen,
        const uint8_t *ad, size_t adlen,
        const uint8_t *nsec,
        const uint8_t *npub, size_t npub_len,
        const uint8_t *key, size_t key_len,
        void(*encrypt)(void*, size_t*, const void*, size_t, const void*, size_t, const void*, const void*, size_t, const void*, size_t),
        int(*decrypt)(void*, size_t*, void*, const void*, size_t, const void*, size_t, const void*, size_t, const void*, size_t),
        size_t block_length
    ) {
    uint8_t c[block_length + mlen + block_length];
    uint8_t m_check[mlen];
    uint8_t nsec_check[block_length];
    size_t clen, mlen_check;
    int v;

    print_item("KEY", key, key_len);
    print_item("NPUB", npub, npub_len);
    print_item("NSEC", nsec, block_length);
    print_item("MSG", m, mlen);
    print_item("AD", ad, adlen);

    fflush(stdout);
    encrypt(c, &clen, m, mlen, ad, adlen, nsec, npub, npub_len, key, key_len);

    print_item("CIPHER", c, clen);
    fflush(stdout);

    v = decrypt(m_check, &mlen_check, nsec_check, c, clen, ad, adlen, npub, npub_len, key, key_len);

    if (v) {
        printf("!verification failed (%d)\n", v);
    }

    if (mlen != mlen_check || memcmp(m, m_check, mlen)) {
        print_item("!ERROR MSG", m_check, mlen_check);
    }
    if (memcmp(nsec, nsec_check, block_length)) {
        print_item("!ERROR MSG", m_check, mlen_check);
    }
    putchar('\n');
    fflush(stdout);
}

void generate_testvectors(
        size_t key_len, size_t npub_len,
        void(*encrypt)(void*, size_t*, const void*, size_t, const void*, size_t, const void*, const void*, size_t, const void*, size_t),
        int(*decrypt)(void*, size_t*, void*, const void*, size_t, const void*, size_t, const void*, size_t, const void*, size_t),
        size_t block_length, const char *cipher_name) {
    size_t ad_len, msg_len, i, c = 1;
    uint8_t ad[3 * block_length / 2];
    uint8_t msg[3 * block_length / 2];
    uint8_t key[key_len];
    uint8_t npub[npub_len];
    uint8_t nsec[block_length];
    {
        char seed[64];
        snprintf(seed, sizeof(seed), "%s%03uv2 (%u byte nonce)", cipher_name, key_len * 8, npub_len);
        arcfour_init(seed, strlen(seed) * 8, &prng);
    }
    for (msg_len = 0; msg_len <= sizeof(msg); ++msg_len) {
        for (ad_len = 0; ad_len <= sizeof(ad); ++ad_len) {
            printf("[msg_len = %u]\n", msg_len);
            printf("[ad_len = %u]\n\n", ad_len);
            for (i = 0; i < 8; ++i) {
                printf("[vector #%u (%u)]\n", c, i + 1);
                ++c;
                fill_random(key, sizeof(key));
                fill_random(npub, sizeof(npub));
                fill_random(nsec, sizeof(nsec));
                fill_random(ad, ad_len);
                fill_random(msg, msg_len);
                generate_single_testvector(msg, msg_len, ad, ad_len, nsec, npub, npub_len, key, key_len, encrypt, decrypt, block_length);
            }
        }
    }
}

void tv16(void) {
    puts("\n=====\n");
    printf("# Testvectors for %s\n", pi16_cipher_name);
    printf("#   key size: %u bits\n", 128);
    printf("#   nonce size: %u bits\n\n", 32);
    generate_testvectors(16, 4, pi16_encrypt_simple, pi16_decrypt_simple, PI16_PT_BLOCK_LENGTH_BYTES, pi16_cipher_name);
    puts("\n=====\n");
}

/*****************************************************************************
 *  main                                                                     *
 *****************************************************************************/

const char nessie_str[]      PROGMEM = "nessie";
const char test_str[]        PROGMEM = "test";
const char tv16_str[]        PROGMEM = "tv16";
const char test16_str[]      PROGMEM = "test16";
const char test32_str[]      PROGMEM = "test32";
const char test64_str[]      PROGMEM = "test64";
const char ftest_str[]       PROGMEM = "ftest";
const char gtest_str[]       PROGMEM = "gtest";
const char performance_str[] PROGMEM = "performance";
const char echo_str[]        PROGMEM = "echo";

const cmdlist_entry_t cmdlist[] PROGMEM = {
//    { nessie_str,      NULL, NULL },
    { test_str,          NULL, testrun},
    { tv16_str,          NULL, tv16},
    { test16_str,        NULL, testrun_pi16},
    { test32_str,        NULL, testrun_pi32},
    { test64_str,        NULL, testrun_pi64},
//    { ftest_str,       NULL, testrun_f32},
//    { gtest_str,       NULL, testrun_g32},
    { performance_str,   NULL, testrun_performance_pi16cipher},
    { echo_str,    (void*)1, (void_fpt)echo_ctrl},
    { NULL,            NULL, NULL}
};

int main(void) {
    main_setup();

    for(;;){
        welcome_msg(algo_name);
        cmd_interface(cmdlist);
    }

}


