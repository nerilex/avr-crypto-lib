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
/*
void phi16(
        word_t dest[4],
        const word_t x[4],
        const word_t c[4],
        const uint8_t v[8],
        const uint8_t rot[4])
{
    word_t sum = 0;
    uint8_t i;
    i = 4;
    do {
        --i;
        sum += x[i];
    } while (i);
    i = 4;
    do {
        --i;
        dest[i] = rotl(pgm_read_word(&c[i]) + sum - x[pgm_read_byte(&v[i])], pgm_read_byte(&rot[i]) );
    } while (i);
    sum = 0;
    i = 4;
    do {
        --i;
        sum ^= dest[i];
    } while (i);
    i = 4;
    do {
        --i;
        dest[i] ^= sum;
    } while (i);
}

*/

.global phi16

/*
	r24:r25 - destination
	r22:r23 - input
	r20:r21 - constants
	r18:r19 - drop constants (v)
	r16:r17 - rotation constants
*/
phi16:
	movw r28, r24
	movw r26, r22
	movw r6, r16
	ldi r16, 3
	ld r24, X+
	ld r25, X+
1:
	ld r0, X+
	add r24, r0
	ld r0, X+
	adc r25, r0
	dec r16
	brne 1b
	sbiw r26, 8
	movw r2, r26
	/* --- */
	ldi r16, 4
2:
	movw r30, r20
	lpm r22, Z+
	lpm r23, Z+
	movw r20, r30
	add r22, r24
	adc r23, r25
	movw r30, r18
	lpm r0, Z+
	movw r18, r30
	movw r26, r2
	add r26, r0
	adc r27, r1
	ld r4, X+
	ld r5, X+
	sub r22, r4
	sbc r23, r5
	movw r30, r6
	lpm r0, Z+
	movw r6, r30
5:
	mov r17, r23
	lsl r17
	rol r22
	rol r23
	dec r0
	brne 5b
	/* --- */
	st Y+, r22
	st Y+, r23
	dec r16
	brne 2b
	/* --- */
	sbiw r28, 8
	movw r26, r28
	ldi r16, 3
	ld r24, X+
	ld r25, X+
1:
	ld r0, X+
	eor r24, r0
	ld r0, X+
	eor r25, r0
	dec r16
	brne 1b
	/* --- */
	ldi r16, 4
1:
	ld r0, Y
	eor r0, r24
	st Y+, r0
	ld r0, Y
	eor r0, r25
	st Y+, r0
	dec r16
	brne 1b
	sbiw r28, 8
	ret


/******************************************************************************/
/*
static void ny(
        word_t dest[4],
        const word_t x[4])
{
    phi16(dest, x, ny_const, ny_v_const, ny_rot_const);
}
*/

ny16_const:
	.word  0xD1CC, 0xCAC9, 0xC6C5, 0xC3B8

ny16_v_const:
	.byte 1 * 2, 0 * 2, 3 * 2, 2 * 2

ny16_rot_const:
	.byte 2, 5, 7, 13

/******************************************************************************/
/*
static void mu(
        word_t dest[4],
        const word_t x[4])
{
    phi16(dest, x, mu_const, mu_v_const, mu_rot_const);
}
*/
mu16_const:
	.word 0xF0E8, 0xE4E2, 0xE1D8, 0xD4D2

mu16_v_const:
	.byte 3 * 2, 2 * 2, 1 * 2, 0 * 2

mu16_rot_const:
	.byte 1, 4, 9, 11


.global ast16

ast16:
	push_range 2, 7
	push r16
	push r17
	push r28
	push r29
	stack_alloc 8 ; pointer to stack space is stored in Z
	adiw r30, 1
	push r20
	push r21
	push r30
	push r31
mu16:
	ldi r16, lo8(mu16_rot_const)
	ldi r17, hi8(mu16_rot_const)
	ldi r18, lo8(mu16_v_const)
	ldi r19, hi8(mu16_v_const)
	ldi r20, lo8(mu16_const)
	ldi r21, hi8(mu16_const)
	rcall phi16
	pop r25
	pop r24
	pop r23
	pop r22
	push r28
	push r29
ny16:
	ldi r16, lo8(ny16_rot_const)
	ldi r17, hi8(ny16_rot_const)
	ldi r18, lo8(ny16_v_const)
	ldi r19, hi8(ny16_v_const)
	ldi r20, lo8(ny16_const)
	ldi r21, hi8(ny16_const)
	rcall phi16
	pop r31
	pop r30
	ldd r16, Z + 0
	ldd r17, Z + 1

	ldd r18, Z + 3 * 2 + 0
	ldd r19, Z + 3 * 2 + 1
	ldd r20, Y + 1 * 2 + 0
	ldd r21, Y + 1 * 2 + 1
	add r18, r20
	adc r19, r21
	std Z + 0 * 2 + 0, r18
	std Z + 0 * 2 + 1, r19

	ldd r18, Z + 2 * 2 + 0
	ldd r19, Z + 2 * 2 + 1
	ldd r20, Y + 0 * 2 + 0
	ldd r21, Y + 0 * 2 + 1
	add r18, r20
	adc r19, r21
	std Z + 3 * 2 + 0, r18
	std Z + 3 * 2 + 1, r19

	ldd r18, Z + 1 * 2 + 0
	ldd r19, Z + 1 * 2 + 1
	ldd r20, Y + 3 * 2 + 0
	ldd r21, Y + 3 * 2 + 1
	add r18, r20
	adc r19, r21
	std Z + 2 * 2 + 0, r18
	std Z + 2 * 2 + 1, r19

	movw r18, r16
	ldd r20, Y + 2 * 2 + 0
	ldd r21, Y + 2 * 2 + 1
	add r18, r20
	adc r19, r21
	std Z + 1 * 2 + 0, r18
	std Z + 1 * 2 + 1, r19

	stack_free 8, reg1 = r26, reg2 = r27
	pop r29
	pop r28
	pop r17
	pop r16
	pop_range 2, 7
	ret

/******************************************************************************/
/*
void e1_16(
        word_t *dest,
        const word_t c[4],
        const word_t *i )
{
    uint8_t n = PI_N - 1;
    {
        word_t t[4];
        memcpy_P(t, c, sizeof(word_t) * 4);
        ast16(dest, t, i);
    }
    do {
        i = &i[4];
        ast16(&dest[4], dest, i);
        dest = &dest[4];
    } while (--n);
}
*/

.global e1_16

e1_16:
	push_range 8, 10
	movw r8, r20
	movw r30, r22
	stack_alloc 8, reg1=r26, reg2=r27
	adiw r26, 1
	movw r22, r26
	ldi r18, 8
1:
	lpm r0, Z+
	st X+, r0
	dec r18
	brne 1b
	/* --- */
	ldi r18, 3
	mov r10, r18
	rcall ast16
1:
	movw r22, r30
	adiw r30, 8
	movw r24, r30
	movw r26, r8
	adiw r26, 8
	movw r20, r26
	movw r8, r26
	rcall ast16
	dec r10
	brne 1b
	sbiw r30, 3 * 4 * 2
	/* --- */
	stack_free 8, reg1=r26, reg2=r27
	pop_range 8, 10
	ret

/******************************************************************************/
/*
void e2_16(
        word_t *dest,
        const word_t c[4],
        const word_t *i )
{
    uint8_t n = PI_N - 1;
    {
        word_t t[4];
        memcpy_P(t, c, sizeof(word_t) * 4);
        ast16(&dest[4 * n], &i[4 * n], t);
    }
    while (n--) {
        ast16(&dest[4 * n], &i[4 * n], &dest[4 * (n + 1)]);
    }
}
*/

.global e2_16

e2_16:
	push_range 8, 10
	movw r30, r22
	movw r26, r20
	adiw r26, 24
	movw r8, r26
	movw r22, r26
	stack_alloc 8, reg1 = r26, reg2 = r27
	adiw r26, 1
	movw r20, r26
	ldi r18, 8
1:
	lpm r0, Z+
	st X+, r0
	dec r18
	brne 1b
	/* --- */
	ldi r18, 3
	mov r10, r18
	adiw r24, 24
	rcall ast16
1:
	movw r20, r30
	sbiw r30, 8
	movw r24, r30
	movw r26, r8
	sbiw r26, 8
	movw r22, r26
	movw r8, r26
	rcall ast16
	dec r10
	brne 1b
	/* --- */
	stack_free 8, reg1 = r26, reg2 = r27
	pop_range 8, 10
	ret


/******************************************************************************/
/*
void pi(
        word_t *a )
{
    uint8_t r = PI_ROUNDS;
    word_t t[4 * 4];
    const word_t *c = (const word_t *)pi_const;
    do {
        e1_16(t, c, a);
        c = &c[4];
        e2_16(a, c, t);
        c = &c[4];
    } while (--r);
}
*/

PI_CONST:
	.word 0xB4B2, 0xB1AC, 0xAAA9, 0xA6A5
	.word 0xA39C, 0x9A99, 0x9695, 0x938E
	.word 0x8D8B, 0x8778, 0x7472, 0x716C
	.word 0x6A69, 0x6665, 0x635C, 0x5A59
	.word 0x5655, 0x534E, 0x4D4B, 0x473C
	.word 0x3A39, 0x3635, 0x332E, 0x2D2B
	.word 0x271E, 0x1D1B, 0x170F, 0xF0E8
	.word 0xE4E2, 0xE1D8, 0xD4D2, 0xD1CC


/******************************************************************************/
/*
void ctr_trans(
        const PI_CTX *ctx,
        state_t a,
        unsigned long ctr )
{
    uint64_t t;
    int i;
    if ((void *)ctx->cis != (void *)a) {
        memcpy(a, ctx->cis, sizeof(state_t));
    }
    t = ctx->ctr + ctr;
    for (i = 0; i * PI_WORD_SIZE < 64; ++i) {
        a[0][i] ^= (word_t)t;
        t >>= PI_WORD_SIZE;
    }
    pi((word_t*)a);
}
*/

.global ctr_trans

ctr_trans:
	push_range 16, 17
	push r28
	push r29
	movw r30, r24
	movw r26, r22
	cp r24, r22
	cpc r25, r23
	breq 2f
	ldi r22, 32
1:
	ld r0, Z+
	st X+, r0
	dec r22
	brne 1b
	/* --- */
	sbiw r30, 32
	sbiw r26, 32
2:
	movw r16, r18
	movw r18, r20
	clr r20
	clr r21
	movw r22, r20
	adiw r30, ctx_ctr ; Z points at lsb of ctr
	ldi r28, 16 ; Y points at r16
	clr r29
	clc
	ldi r25, 8
3:
	ld r0, Y+
	ld r24, Z+
	adc r24, r0
	ld r0, X
	eor r0, r24
	st X+, r0
	dec r25
	brne 3b
	/* --- */
	sbiw r26, 8
	movw r24, r26
	pop r29
	pop r28
	pop_range 16, 17
;	rjmp pi

/* at the end of pi dest is in Z */

.global pi
pi:
	push r6
	push r7
	push r16
	push r28
	push r29
	stack_alloc 32, reg1 = r28, reg2 = r29
	adiw r28, 1
	movw r6, r28
	ldi r28, lo8(PI_CONST - 8)
	ldi r29, hi8(PI_CONST - 8)
	ldi r16, 3
	movw r30, r24
1:
	movw r24, r6
	movw r6, r30
	movw r20, r30
	adiw r28, 8
	movw r22, r28
	rcall e1_16

	movw r24, r6
	movw r6, r30
	movw r20, r30
	adiw r28, 8
	movw r22, r28
	rcall e2_16
	dec r16
	brne 1b
	/* --- */
	stack_free 32, reg1 = r26, reg2 = r27
	pop r29
	pop r28
	pop r16
	pop r7
	pop r6
	ret


/******************************************************************************/
/*
void add_tag(
        PI_CTX *ctx,
        state_t a )
{
    uint8_t i;
    i = 3;
    do {
        ctx->tag[i + 0] += a[0][i];
        ctx->tag[i + 4] += a[2][i];
    } while(i--);
}
*/

.global add_tag
add_tag:
	push r28
	push r29
	movw r30, r24
	adiw r30, ctx_tag
	movw r28, r22
	ldi r19, 2
1:
	ldi r18, 4
2:
	ld r24, Y+
	ld r25, Y+
	ldd r22, Z + 0
	ldd r23, Z + 1
	add r24, r22
	adc r25, r23
	st Z+, r24
	st Z+, r25
	dec r18
	brne 2b
	adiw r28, 8
	dec r19
	brne 1b
	/* --- */
	pop r29
	pop r28
	ret


/******************************************************************************/
/*
void inject_tag(
        state_t a,
        const word_t x[8] )
{
    int i;
    for (i = 0; i < 4; ++i) {
        a[0][i] ^= x[i];
    }
    for (; i < 8; ++i) {
        a[2][i - 4] ^= x[i];
    }
}
*/
.global inject_block
.global inject_tag


inject_block:
inject_tag:
	movw r30, r24
	movw r26, r22
	ldi r23, 2
1:
	ldi r22, 8
2:
	ld r24, Z
	ld r25, X+
	eor r24, r25
	st Z+, r24
	dec r22
	brne 2b
	adiw r30, 8
	dec r23
	brne 1b
	ret

/******************************************************************************/
/*
void extract_block(
        void *block,
        state_t a)
{
    int i;
    for (i = 0; i < 4; ++i) {
        store_word_little(&((word_t *)block)[i], a[0][i]);
    }
    for (; i < 8; ++i) {
        store_word_little(&((word_t *)block)[i], a[2][i - 4]);
    }
}
*/

.global extract_block

extract_block:
	movw r26, r24
	movw r30, r22
	ldi r23, 2
1:
	ldi r22, 8
2:
	ld r24, Z+
	st X+, r24
	dec r22
	brne 2b
	adiw r30, 8
	dec r23
	brne 1b
	ret


/******************************************************************************/
/*
void replace_block(
        state_t a,
        const void *block )
{
    word_t x;
    int i;
    for (i = 0; i < 4; ++i) {
        x = load_word_little(&((const word_t *)block)[i]);
        a[0][i] = x;
    }
    for (; i < 8; ++i) {
        x = load_word_little(&((const word_t *)block)[i]);
        a[2][i - 4] = x;
    }
}
*/
/*
.global replace_block

replace_block:
	movw r30, r24
	movw r26, r22
	ldi r23, 2
1:
	ldi r22, 8
2:
	ld r24, X+
	st Z+, r24
	dec r22
	brne 2b
	adiw r30, 8
	dec r23
	brne 1b
	ret
*/
/******************************************************************************/
/*
void inject_last_block(
        state_t a,
        const void *block,
        size_t length_Bb )
{
    uint8_t t[PI_RATE_BYTES];
    if (length_b >= PI_RATE_BITS) {
        / * error * /
        printf("ERROR <%s %s %d>\n", __FILE__, __func__, __LINE__);
        return;
    }
    memset(t, 0, sizeof(t));
    memcpy(t, block, (length_b + 7) / 8);
    t[length_b / 8] |= 1 << (length_b & 7);
    inject_block(a, t);
}
*/

.global inject_last_block

inject_last_block:
	movw r30, r24
	movw r26, r22
	ldi r23, 2
1:
	ldi r22, 8
2:
	tst r20
	brne 3f
	ld r24, Z
	ldi r25, 1
	eor r24, r25
	st Z, r24
return:
	ret
3:
	dec r20
	ld r25, X+
	ld r24, Z
	eor r24, r25
	st Z+, r24
	dec r22
	brne 2b
	adiw r30, 8
	dec r23
	brne 1b
;	ret ; this should never been reached

/******************************************************************************/
/*
void replace_last_block(
        state_t a,
        const void *block,
        size_t length_B  )
{
    uint8_t t[PI_RATE_BYTES];
    if (length_B >= PI_RATE_BYTES) {
        / * error * /
        printf("ERROR <%s %s %d>\n", __FILE__, __func__, __LINE__);
        return;
    }
    extract_block(t, a);
    memcpy(t, block, length_B);
    replace_block(a, t);
}
*/

.global replace_last_block
.global replace_block

replace_block:
	ldi r20, 32
replace_last_block:
	movw r30, r24
	movw r26, r22
	ldi r23, 2
1:
	ldi r22, 8
2:
	tst r20
	breq return
	dec r20
	ld r24, X+
	st Z+, r24
	dec r22
	brne 2b
	adiw r30, 8
	dec r23
	brne 1b
	ret

/******************************************************************************/
/*
int PI_INIT(
        PI_CTX *ctx,
        const void *key,
        size_t key_length_B,
        const void *pmn,
        size_t pmn_length_B)
{
    int i;
    uint8_t setup_buf[PI_IS_BYTES];
    if (key_length_B + pmn_length_B + 1 > PI_IS_BYTES) {
        return -1;
    }
    memset(ctx->tag, 0, sizeof(ctx->tag));
    memset(setup_buf, 0, sizeof(setup_buf));
    memcpy(setup_buf, key, key_length_B);
    memcpy(&setup_buf[key_length_B], pmn, pmn_length_B);
    setup_buf[key_length_B + pmn_length_B] = 1;
    for (i = 0; i < 16; ++i) {
        ctx->cis[i / 4][i % 4] = load_word_little(&setup_buf[i * PI_WORD_SIZE / 8]);
    }
    pi((word_t*)ctx->cis);
    ctx->ctr = 0;
    for (i = 0; i * PI_WORD_SIZE < 64; ++i) {
        ctx->ctr |= (uint64_t)ctx->cis[1][i] << (i * PI_WORD_SIZE);
    }
    return 0;
}
*/

.global pi16_init

pi16_init:
	movw r26, 20
	add r26, r16
	adc r27, r17
	mov r21, r26 ; r21 = key_len + nonce_len
	sbiw r26, 32
	brmi 1f
return_error:
	ser r24
	ser r25
	ret
1:
	push r16
	ldi r17, 32 + 16 - 1 ; state_size + tag_size - 1
	sub r17, r21 ; r17 = rest of state to clear
	movw r30, r24 ; Z points at ctx->cis
	movw r26, r22 ; X points at key
3:
	tst r20
	brne 5f
	movw r26, r18 ; set X to pi´oint at nonce
5:
	dec r20
	ld r0, X+
	st Z+, r0
	dec r21
	brne 3b
	/* --- */
	ldi r21, 1
	st Z+, r21 ; store padding '1'
6:
	st Z+, r1
	dec r17
	brne 6b
	/* --- */
	movw r24, r30
	sbiw r24, 32 + 16
	rcall pi
	movw r26, r30
	adiw r26, 32 + 16 ; X points at ctx->ctr
	adiw r30, 8  ; Z points at ctx->cis[1][0]
	ldi r24, 8
1:
	ld r0, Z+
	st X+, r0
	dec r24
	brne 1b
	pop r16
	clr r25
	ret


/******************************************************************************/
/*
void PI_PROCESS_AD_BLOCK(
        PI_CTX *ctx,
        const void *ad,
        unsigned long ad_num )
{
    state_t a;
    ctr_trans(ctx, a, ad_num);
    inject_block(a, ad);
    pi((word_t*)a);
    add_tag(ctx, a);
}
*/

.global pi16_process_ad_block

pi16_process_ad_block:
	push r28
	push r29
	stack_alloc 32, reg1 = r28, reg2 = r29
	adiw r28, 1
	push r24
	push r25
	push r22
	push r23
	movw r22, r28
	rcall ctr_trans
	movw r24, r28
	pop r23
	pop r22
	rcall inject_block
	movw r24, r28
	rcall pi
	movw r22, r28
	pop r25
	pop r24
	rcall add_tag
	stack_free 32, reg1 = r28, reg2 = r29
	pop r29
	pop r28
	ret

/******************************************************************************/
/*
void PI_PROCESS_AD_LAST_BLOCK(
        PI_CTX *ctx,
        const void *ad,
        size_t ad_length_B,
        unsigned long ad_num )
{
    state_t a;
    while (ad_length_B >= PI_AD_BLOCK_LENGTH_BYTES) {
        PI_PROCESS_AD_BLOCK(ctx, ad, ad_num);
        ad_num++;
        ad_length_B -= PI_AD_BLOCK_LENGTH_BYTES;
        ad = &((uint8_t*)ad)[PI_AD_BLOCK_LENGTH_BYTES];
    }

    ctr_trans(ctx, a, ad_num);
    inject_last_block(a, ad, ad_length_B);
    pi((word_t*)a);
    add_tag(ctx, a);
    ctx->ctr += ad_num;
    inject_tag(ctx->cis, ctx->tag);
    pi((word_t*)ctx->cis);
}
*/

.global pi16_process_ad_last_block

pi16_process_ad_last_block:
	push_range 10, 17
	push r28
	push r29
	movw r10, r24  ; ctx
	movw r12, r22 ; ad
	movw r14, r16 ; lo16(ad_num)
	movw r16, r18 ; hi16(ad_num)
	movw r28, r20 ; r28:r29 contains ad_length_B
1:
	sbiw r28, 16
	brmi 6f
	movw r18, r14
	movw r20, r16
	movw r22, r12
	movw r24, r10
	rcall pi16_process_ad_block
	; increment num_counter
	sec
	adc r14, r1
	adc r15, r1
	adc r16, r1
	adc r17, r1
	ldi r24, 16
	add r12, r24
	adc r13, r1
	rjmp 1b
	/* --- */
6:
	adiw r28, 16
	stack_alloc 32, reg1 = r30, reg2 = r31
	adiw r30, 1
	push r28
	movw r28, r30 ; Y points at a (on stack)
	movw r18, r14
	movw r20, r16
	movw r22, r28
	movw r24, r10
	rcall ctr_trans
	movw r24, r28
	movw r22, r12
	clr r21
	pop r20
	rcall inject_last_block
	movw r24, r28
	rcall pi
	movw r24, r10
	movw r22, r28
	rcall add_tag
	stack_free 32, reg1 = r30, reg2 = r31
	movw r30, r10
	adiw r30, ctx_ctr
	clr r0
	movw r18, r0 ; clear top 4 bytes to have 64-bit ad_num in  register-file
	movw r20, r0
	ldi r28, 14 ; Y points to r14 (ad_num)
	clr r29
	ldi r25, 8
1:
	ld r24, Y+
	ld r0, Z
	adc r0, r24
	st Z+, r0
	dec r25
	brne 1b

	sbiw r30, 8 + 16
	movw r22, r30
	movw r24, r10
	rcall inject_tag
	movw r24, r10

	pop r29
	pop r28
	pop_range 10, 17
	rjmp pi

/******************************************************************************/
/*
void PI_PROCESS_SMN(
        PI_CTX *ctx,
        void *c0,
        const void *smn)
{
    ctx->ctr++;
    ctr_trans(ctx, ctx->cis, 0);
    inject_block(ctx->cis, smn);
    if (c0) {
        extract_block(c0, ctx->cis);
    }
    pi((word_t*)ctx->cis);
    add_tag(ctx, ctx->cis);
}
*/

.global pi16_encrypt_smn

pi16_encrypt_smn:
	clt
pi16_process_smn:
	push_range 12, 17
	movw r12, r24 ; ctx
	movw r14, r22 ; c0
	movw r16, r20 ; smn
	movw r26, r24
	adiw r26, ctx_ctr
	ldi r18, 8
	sec
1:
	ld r0, X
	adc r0, r1
	st X+, r0
	dec r18
	brne 1b

	movw r22, r24
	clr r0
	movw r20, r0
	movw r18, r0
	rcall ctr_trans

	movw r24, r12
	movw r22, r16
	rcall inject_block

	cp r14, r1
	cpc r15, r1
	breq 4f

	movw r24, r14
	movw r22, r12
	rcall extract_block
4:
	brtc 5f
	movw r24, r12
	movw r22, r16
	rcall replace_block
5:
	movw r24, r12
	rcall pi

	movw r22, r12
	movw r24, r12
	pop_range 12, 17
	rjmp add_tag

/******************************************************************************/
/*
void PI_DECRYPT_SMN(
        PI_CTX *ctx,
        void *smn,
        const void *c0)
{
    ctx->ctr++;
    ctr_trans(ctx, ctx->cis, 0);
    inject_block(ctx->cis, c0);
    if (smn) {
        extract_block(smn, ctx->cis);
    }
    replace_block(ctx->cis, c0);
    pi((word_t*)ctx->cis);
    add_tag(ctx, ctx->cis);
}
*/

.global pi16_decrypt_smn

pi16_decrypt_smn:
	set
	rjmp pi16_process_smn
/*
	push_range 12, 17
	movw r12, r24 ; ctx
	movw r14, r22 ; smn
	movw r16, r20 ; c0
	movw r26, r24
	adiw r26, ctx_ctr
	ldi r18, 8
	sec
1:
	ld r0, X
	adc r0, r1
	st X+, r0
	dec r18
	brne 1b

	movw r22, r24
	clr r0
	movw r20, r0
	movw r18, r0
	rcall ctr_trans

	movw r24, r12
	movw r22, r16
	rcall inject_block

	cp r14, r1
	cpc r15, r1
	breq 4f

	movw r24, r14
	movw r22, r12
	rcall extract_block

4:
	movw r24, r12
	movw r22, r16
	rcall replace_block

	movw r24, r12
	rcall pi

	movw r22, r12
	movw r24, r12
	pop_range 12, 17
	rjmp add_tag
*/

/******************************************************************************/
/*
void PI_EXTRACT_TAG(
        PI_CTX *ctx,
        void *dest )
{
    uint8_t buf[8 * PI_WORD_SIZE / 8];
    int i;
    for (i = 0; i < 8; ++i) {
        store_word_little(&buf[i * PI_WORD_SIZE / 8], ctx->tag[i]);
    }
    memcpy(dest, buf, PI_TAG_BYTES);
}
*/

.global pi16_extract_tag

pi16_extract_tag:
	movw r30, r24
	movw r26, r22
	adiw r30, ctx_tag
	ldi r24, 16
1:
	ld r0, Z+
	st X+, r0
	dec r24
	brne 1b
	ret

/******************************************************************************/
/*
void PI_ENCRYPT_BLOCK(
        PI_CTX *ctx,
        void *dest,
        const void *src,
        unsigned long num )
{
    state_t a;
    ctr_trans(ctx, a, num);
    inject_block(a, src);
    if (dest) {
        extract_block(dest, a);
    }
    pi((word_t*)a);
    add_tag(ctx, a);
}
*/
.global pi16_encrypt_block

pi16_encrypt_block:
	clt
pi16_process_block:
	push_range 8, 17
	push r28
	push r29
	stack_alloc 32, reg1 = r28, reg2 = r29
	adiw r28, 1
	movw  r8, r24 ; ctx
	movw r10, r22 ; dest
	movw r12, r20 ; src

	movw r22, r28
	movw r20, r18
	movw r18, r16
	rcall ctr_trans

	movw r24, r30
	movw r22, r12
	rcall inject_block

	cp r10, r1
	cpc r11, r1
	breq 4f

	movw r24, r10
	movw r22, r28
	rcall extract_block

4:
	brtc 5f
	movw r24, r28
	movw r22, r12
	rcall replace_block
5:
	movw r24, r28
	rcall pi

	movw r22, r28
	movw r24, r8
	rcall add_tag

	stack_free 32, reg1 = r30, reg2 = r31
	pop r29
	pop r28
	pop_range 8, 17
	ret

/******************************************************************************/
/*
void PI_DECRYPT_BLOCK(
        PI_CTX *ctx,
        void *dest,
        const void *src,
        unsigned long num )
{
    state_t a;
    ctr_trans(ctx, a, num);
    inject_block(a, src);
    if (dest) {
        extract_block(dest, a);
    }
    replace_block(a, src);
    pi((word_t*)a);
    add_tag(ctx, a);
}
*/
.global pi16_decrypt_block

pi16_decrypt_block:
	set
	rjmp pi16_process_block
/*
	push_range 8, 17
	push r28
	push r29
	stack_alloc 32, reg1 = r28, reg2 = r29
	adiw r28, 1
	movw  r8, r24 ; ctx
	movw r10, r22 ; dest
	movw r12, r20 ; src

	movw r22, r28
	movw r20, r18
	movw r18, r16
	rcall ctr_trans

	movw r24, r30
	movw r22, r12
	rcall inject_block

	cp r10, r1
	cpc r11, r1
	breq 4f

	movw r24, r10
	movw r22, r28
	rcall extract_block

4:
	movw r24, r28
	movw r22, r12
	rcall replace_block

	movw r24, r28
	rcall pi

	movw r22, r28
	movw r24, r8
	rcall add_tag

	stack_free 32, reg1 = r30, reg2 = r31
	pop r29
	pop r28
	pop_range 8, 17
	ret
*/
/******************************************************************************/
/*
void PI_ENCRYPT_LAST_BLOCK(
        PI_CTX *ctx,
        void *dest,
        const void *src,
        size_t length_B,
        unsigned long num )
{
    state_t a;
    while (length_B >= PI_PT_BLOCK_LENGTH_BYTES) {
        PI_ENCRYPT_BLOCK(ctx, dest, src, num);
        num++;
        length_B -= PI_PT_BLOCK_LENGTH_BYTES;
        src = &((uint8_t*)src)[PI_PT_BLOCK_LENGTH_BYTES];
        if (dest) {
            dest = &((uint8_t*)dest)[PI_CT_BLOCK_LENGTH_BYTES];
        }
    }
    ctr_trans(ctx, a, num);
    inject_last_block(a, src, length_B);
    if (dest) {
        uint8_t tmp[PI_PT_BLOCK_LENGTH_BYTES];
        extract_block(tmp, a);
        memcpy(dest, tmp, length_B);
    }
    pi((word_t*)a);
    add_tag(ctx, a);
}
*/
.global pi16_encrypt_last_block

pi16_encrypt_last_block:
	clt
pi16_process_last_block:
	push r28
	push r29
	push_range 4, 15
	movw  r4, r24 ; ctx
	movw  r6, r22 ; dest
	movw  r8, r20 ; src
	movw r10, r18 ; len
	movw r12, r14 ; lo16(num)
	movw r14, r16 ; hi16(num)
	movw r28, r18
1:
	sbiw r28, 16
	brmi 4f
	movw r24, r4
	movw r22, r6
	movw r20, r8
	movw r18, r14
    movw r16, r12
    brts 2f
	rcall pi16_encrypt_block
	rjmp 3f
2:	rcall pi16_decrypt_block
3:
	sec
	adc r12, r1
	adc r13, r1
	adc r14, r1
	adc r15, r1
	ldi r24, 16
	add r8, r24
	adc r9, r1
	cp r6, r1
	cpc r7, r1
	breq 1b
	add r6, r24
	adc r7, r1
	rjmp 1b
4:
	stack_alloc 32 + 16, reg1 = r30, reg2 = r31
	adiw r28, 16
	movw r10, r28
	adiw r30, 1
	movw r28, r30

	movw r24, r4
	movw r22, r28
	movw r20, r14
	movw r18, r12
	rcall ctr_trans

	movw r24, r28
	movw r22,  r8
	movw r20, r10
	rcall inject_last_block

	cp r6, r1
	cpc r7, r1
	breq 6f
	tst r10
	breq 6f

	movw r24, r28
	adiw r24, 32
	movw r22, r28
	rcall extract_block
	movw r30, r28
	adiw r30, 32
	movw r26, r6
	mov r24, r10
3:
	ld r0, Z+
	st X+, r0
	dec r24
	brne 3b
6:
	brtc 7f
	movw r24, r28
	movw r22,  r8
	movw r20, r10
	rcall replace_last_block
7:
	movw r24, r28
	rcall pi

	movw r24, r4
	movw r22, r28
	rcall add_tag

	stack_free 32 + 16
	pop_range 4, 15
	pop r29
	pop r28
	ret

/******************************************************************************/
/*
void PI_DECRYPT_LAST_BLOCK(
        PI_CTX *ctx,
        void *dest,
        const void *src,
        size_t length_B,
        unsigned long num )
{
    state_t a;
    ctr_trans(ctx, a, num);
    inject_last_block(a, src, length_B);
    if (dest) {
        uint8_t tmp[PI_PT_BLOCK_LENGTH_BYTES];
        extract_block(tmp, a);
        memcpy(dest, tmp, length_B);
    }
    replace_last_block(a, src, length_B);
    pi((word_t*)a);
    add_tag(ctx, a);
}
*/
.global pi16_decrypt_last_block

pi16_decrypt_last_block:
	set
	rjmp pi16_process_last_block
/*
		push r28
	push r29
	push_range 4, 15
	movw  r4, r24 ; ctx
	movw  r6, r22 ; dest
	movw  r8, r20 ; src
	movw r10, r18 ; len
	movw r12, r14 ; lo16(num)
	movw r14, r16 ; hi16(num)
	movw r28, r18
1:
	sbiw r28, 16
	brmi 2f
	movw r24, r4
	movw r22, r6
	movw r20, r8
	movw r18, r14
	; movw r16, r16
	rcall pi16_encrypt_block

	sec
	adc r12, r1
	adc r13, r1
	adc r14, r1
	adc r15, r1
	ldi r24, 16
	add r8, r24
	adc r9, r1
	cp r6, r1
	cpc r7, r1
	breq 1b
	add r6, r24
	adc r7, r1
	rjmp 1b
2:
	stack_alloc 32 + 16, reg1 = r30, reg2 = r31
	adiw r28, 16
	movw r10, r28
	adiw r30, 1
	movw r28, r30

	movw r24, r4
	movw r22, r28
	movw r20, r14
	movw r18, r12
	rcall ctr_trans

	movw r24, r28
	movw r22,  r8
	movw r20, r10
	rcall inject_last_block

	cp r6, r1
	cpc r7, r1
	breq 6f
	tst r10
	breq 6f

	movw r24, r28
	adiw r24, 32
	movw r22, r28
	rcall extract_block
	movw r30, r28
	adiw r30, 32
	movw r26, r6
	mov r24, r10
3:
	ld r0, Z+
	st X+, r0
	dec r24
	brne 3b
6:
	movw r24, r28
	movw r22,  r8
	movw r20, r10
	rcall replace_last_block

	movw r24, r28
	rcall pi

	movw r24, r4
	movw r22, r28
	rcall add_tag

	stack_free 32 + 16
	pop_range 4, 15
	pop r29
	pop r28
	ret
*/


