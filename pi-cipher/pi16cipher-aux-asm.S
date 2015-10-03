/* pi16cipher-asm.S */
/*
    This file is part of the AVR-Crypto-Lib.
    Copyright (C) 2015 Daniel Otte (bg@nerilex.org)

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

#include <avr/io.h>
#include "avr-asm-macros.S"

	.struct 0
ctx:
ctx_state:
	.struct ctx_state + 4 * 4 * 2
ctx_tag:
	.struct ctx_tag + 4 * 2 * 2
ctx_ctr:
	.struct ctx_ctr + 8
ctx_end:
ctx_size:

.text

/******************************************************************************/
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
        PI_PROCESS_SMN(&ctx, cipher, nonce_secret);
        *cipher_len_B += PI_CT_BLOCK_LENGTH_BYTES;
        cipher = &((uint8_t*)cipher)[PI_CT_BLOCK_LENGTH_BYTES];
    }
    i = 1;
    while (msg_len_B >= PI_PT_BLOCK_LENGTH_BYTES) {
        PI_ENCRYPT_BLOCK(&ctx, cipher, msg, i++);
        msg = &((const uint8_t*)msg)[PI_PT_BLOCK_LENGTH_BYTES];
        cipher = &((uint8_t*)cipher)[PI_CT_BLOCK_LENGTH_BYTES];
        *cipher_len_B += PI_CT_BLOCK_LENGTH_BYTES;
        msg_len_B -= PI_PT_BLOCK_LENGTH_BYTES;
    }
    PI_ENCRYPT_LAST_BLOCK(&ctx, cipher, msg, msg_len_B, i);
    *cipher_len_B += msg_len_B;
    PI_EXTRACT_TAG(&ctx, tag);
    if (tag_length_B) {
        *tag_length_B = PI_TAG_BYTES;
    }
}
*/
/*
        void *cipher,                    -- r24:r25  -- Y[16]
        size_t *cipher_len_B,            -- r22:r23  -- Y[14]
        const void *msg,                 -- r20:r21  -- Y[12]
        size_t msg_len_B,                -- r18:r19  -- Y[10]
        const void *ad,                  -- r16:r17  -- Y[ 8]
        size_t ad_len_B,                 -- r14:r15  -- Y[ 6]
        const void *nonce_secret,        -- r12:r13  -- Y[ 4]
        const void *nonce_public,        -- r10:r11  -- Y[ 2]
        size_t nonce_public_len_B,       --  r8: r9  -- Y[ 0]
        const void *key,                 -- SP[2]    -- Y[22]
        size_t key_len_B                 -- SP[4]    -- Y[24]
*/
.equ cipher, 16
.equ cipher_len_B, 14
.equ msg, 12
.equ msg_len_B, 10
.equ ad, 8
.equ ad_len_B, 6
.equ nonce_secret, 4
.equ nonce_public, 2
.equ nonce_public_len_B, 0
.equ key, 22
.equ key_len_B, 24

.global pi16_encrypt_simple
pi16_encrypt_simple:
	push r28
	push r29
	stack_alloc_large ctx_size + 9 * 2, reg1 = r30, reg2 = r31
	adiw r30, 1 + ctx_size
	ldi r26, 18
	clr r29
	ldi r28, 8

1:
	ld r0, Y+
	st Z+, r0
	dec r26
	brne 1b
	sbiw r30, 18
	movw r28, r30      ; Y points at var backup
	sbiw r30, ctx_size ; Z points at ctx
	movw r8, r30

	movw r24, r8
	ldd r22, Y + key ; load key
	ldd r23, Y + key + 1 ;
	ldd r20, Y + key_len_B ; load key_len_B
	ldd r21, Y + key_len_B + 1 ;
	ldd r18, Y + nonce_public ; load nonce_public
	ldd r19, Y + nonce_public + 1 ;
	ldd r16, Y + nonce_public_len_B ; load nonce_public_len_B
	ldd r17, Y + nonce_public_len_B + 1 ;
	rcall pi16_init
	or r25, 24
	brne encrypt_simple_init_fault

	movw r24, r8
	ldd r22, Y + ad ; load ad
	ldd r23, Y + ad + 1 ;
	ldd r20, Y + ad_len_B ; ad_len_B
	ldd r21, Y + ad_len_B + 1 ;
	clr r18
	clr r19
	ldi r16, 1     ; set num = 1
	clr r17
	rcall pi16_process_ad_last_block

	ldd r26, Y + cipher_len_B ; load cipher_len_B
	ldd r27, Y + cipher_len_B + 1 ; load cipher_len_B
	ldi r16, 16
	st X+, r16
	st X+, r1    ; set cipher_len_B = 0
	ldd r10, Y + cipher ; load *cipher
	ldd r11, Y + cipher + 1
	movw r24, r10

	ldd r20, Y + nonce_secret ; load smn
	ldd r21, Y + nonce_secret + 1
	cp r20, r1
	cpc r21, r1
	breq 2f

	sbiw r26, 2
	ldi r16, 32
	st X+, r16     ; store "incermented" cipher counter
	movw r22, r10
	movw r24, r8
	rcall pi16_encrypt_smn
	movw r24, r10
	adiw r24, 16
2:
	movw r22, r24
	movw r24, r8
	ldd r18, Y + msg_len_B ; load msg_len_B
	ldd r19, Y + msg_len_B + 1 ;
	ldd r20, Y + msg ; load msg
	ldd r21, Y + msg + 1 ;
	ldd r26, Y + cipher_len_B ; load cipher_len_B
	ldd r27, Y + cipher_len_B + 1 ; load cipher_len_B
	ld r16, X
	add r16, r18
	st X+, r16
	ld r17, X
	adc r17, r19
	st X+, r17
	movw r12, r22
	add r12, r18
	adc r13, r19
	clr r17
	clr r16
	clr r15
	clr r14
	inc r14 ; set num = 1
	rcall pi16_encrypt_last_block

	movw r24, r8
	movw r22, r12
	rcall pi16_extract_tag

	rjmp 1f
; Y must point at var backup!
encrypt_simple_init_fault:
	ldd r26, Y + cipher_len_B ; load cipher_len_B
	ldd r27, Y + cipher_len_B + 1 ; load cipher_len_B
	st X+, r1
	st X+, r1

1:
	ldi r26, 18
	clr r31
	ldi r30, 8

1:
	ld r0, Y+
	st Z+, r0
	dec r26
	brne 1b

	stack_free_large ctx_size + 9 * 2
	pop r29
	pop r28
	ret


/******************************************************************************/
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

/*
        void *msg,                  -- r24:r25  -- Y[16]
        size_t *msg_len_B,          -- r22:r23  -- Y[14]
        void *nonce_secret,         -- r20:r21  -- Y[12]
        const void *cipher,         -- r18:r19  -- Y[10]
        size_t cipher_len_B,        -- r16:r17  -- Y[ 8]
        const void *ad,             -- r14:r15  -- Y[ 6]
        size_t ad_len_B,            -- r12:r13  -- Y[ 4]
        const void *nonce_public,   -- r10:r11  -- Y[ 2]
        size_t nonce_public_len_B,  --  r8: r9  -- Y[ 0]
        const void *key,            -- SP[2]    -- Y[22]
        size_t key_len_B            -- SP[4]    -- Y[24]
*/
.equ msg, 16
.equ msg_len_B, 14
.equ nonce_secret, 12
.equ cipher, 10
.equ cipher_len_B, 8
.equ ad, 6
.equ ad_len_B, 4
.equ nonce_public, 2
.equ nonce_public_len_B, 0
.equ key, 22
.equ key_len_B, 24

.global pi16_decrypt_simple
pi16_decrypt_simple:
	push r28
	push r29
	stack_alloc_large ctx_size + 9 * 2, reg1 = r30, reg2 = r31
	adiw r30, 1 + ctx_size
	ldi r26, 18
	clr r29
	ldi r28, 8

1:
	ld r0, Y+
	st Z+, r0
	dec r26
	brne 1b
	sbiw r30, 18
	movw r28, r30      ; Y points at var backup
	sbiw r30, ctx_size ; Z points at ctx
	movw r8, r30

	movw r24, r8
	ldd r22, Y + key ; load key
	ldd r23, Y + key + 1 ;
	ldd r20, Y + key_len_B ; load key_len_B
	ldd r21, Y + key_len_B + 1 ;
	ldd r18, Y + nonce_public ; load nonce_public
	ldd r19, Y + nonce_public + 1 ;
	ldd r16, Y + nonce_public_len_B ; load nonce_public_len_B
	ldd r17, Y + nonce_public_len_B + 1 ;
	rcall pi16_init
	or r25, 24
	breq 1f
	rjmp decrypt_simple_init_fault
1:

	movw r24, r8
	ldd r22, Y + ad ; load ad
	ldd r23, Y + ad + 1 ;
	ldd r20, Y + ad_len_B ; ad_len_B
	ldd r21, Y + ad_len_B + 1 ;
	ldi r16, 1     ; set num = 1
	clr r17
	clr r18
	clr r19
	rcall pi16_process_ad_last_block

	ldd r26, Y + cipher_len_B ; load cipher_len_B
	ldd r27, Y + cipher_len_B + 1 ; load cipher_len_B
	ldd r10, Y + cipher ; load *cipher
	ldd r11, Y + cipher + 1
	movw r24, r10
	ldd r22, Y + nonce_secret ; load smn
	ldd r23, Y + nonce_secret + 1
	cp r22, r1
	cpc r23, r1
	breq 2f

	movw r20, r10
	movw r24, r8
	rcall pi16_decrypt_smn
	movw r24, r10
	adiw r24, 16
	ldd r26, Y + cipher_len_B ; load cipher_len_B
	ldd r27, Y + cipher_len_B + 1 ; load cipher_len_B
	sbiw r26, 16
2:
	sbiw r26, 16 ; subtract 16 for tag
	movw r20, r24 ; transfer cipher
	movw r24, r8
	movw r18, r26
	ldd r22, Y + msg ; load msg
	ldd r23, Y + msg + 1 ;
	ldd r26, Y + msg_len_B ; load msg_len_B
	ldd r27, Y + msg_len_B + 1 ; load msg_len_B
	st X+, r18
	st X+, r19
	movw r12, r20
	add r12, r18
	adc r13, r19
	clr r17
	clr r16
	clr r15
	clr r14
	inc r14 ; set num = 1
	rcall pi16_decrypt_last_block

	ldi r24, 16
	movw r30, r12
	sbiw r28, ctx_size - ctx_tag
	clr r25
1:
	ld r0, Z+
	ld r16, Y+
	eor r0, r16
	or r25, r0
	dec r24
	brne 1b

	adiw r28, ctx_size - ctx_ctr

	tst r25
	brne 1f
	push r1
	push r1
	rjmp 2f
1:
	ser r24
	ser r25
; Y must point at var backup!
	rjmp 1f
decrypt_simple_init_fault:
	ldd r26, Y + msg_len_B ; load cipher_len_B
	ldd r27, Y + msg_len_B ; load cipher_len_B
	st X+, r1
	st X+, r1
	ser r24
	ser r25
	sbiw r24, 1
1:
	push r24
	push r25
2:
	ldi r26, 18
	clr r31
	ldi r30, 8

1:
	ld r0, Y+
	st Z+, r0
	dec r26
	brne 1b

	pop r25
	pop r24
	stack_free_large ctx_size + 9 * 2
	pop r29
	pop r28
	ret

