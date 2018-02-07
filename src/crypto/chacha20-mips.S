/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2016-2018 René van Dorst <opensource@vdorst.com>. All Rights Reserved.
 * Copyright (C) 2015-2017 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define MSB 0
#define LSB 3
#define ROTx rotl
#define ROTR(n) rotr n, 24
#define	WSBH(n) \
	wsbh	n; \
	rotr	n, 16;
#else
#define MSB 3
#define LSB 0
#define ROTx rotr
#define WSBH(n)
#define ROTR(n)
#endif

#define STORE_UNALIGNED(x, a, s, o) \
.Lchacha20_mips_xor_unaligned_ ## x ## _b: ; \
	lw	T0, o(s); \
	lwl	T1, x-4+MSB ## (IN); \
	lwr	T1, x-4+LSB ## (IN); \
	addu	X ## a, T0; \
	WSBH(X ## a); \
	xor	X ## a, T1; \
	swl	X ## a, x-4+MSB ## (OUT); \
	swr	X ## a, x-4+LSB ## (OUT);

#define STORE_ALIGNED(x, a, s, o) \
.Lchacha20_mips_xor_aligned_ ## x ## _b: ; \
	lw	T0, o(s); \
	lw	T1, x-4 ## (IN); \
	addu	X ## a, T0; \
	WSBH(X ## a); \
	xor	X ## a, T1; \
	sw	X ## a, x-4 ## (OUT);

/*
 * SETUP
 * X15 is free to STORE Xn
 */
#define SETUP_UNALIGNED(x, a, s, o) \
	move	SAVED_X, X ## a ; \
	bal	.Lchacha20_mips_xor_bytes; \
	lw	SAVED_CA, o(s);  \
	b	.Lchacha20_mips_xor_unaligned_ ## x ## _b;
	/* nop, it is safe to next "move" instruction in this delay slot */

#define SETUP_ALIGNED(x, a, s, o) \
	move	SAVED_X, X ## a ; \
	bal	.Lchacha20_mips_xor_bytes; \
	lw	SAVED_CA, o(s);  \
	b	.Lchacha20_mips_xor_aligned_ ## x ## _b;
	/* nop, it is safe to next "move" instruction in this delay slot */

#define MASK_U32	0x3c
#define MASK_BYTES	0x03

#define X0  $v0
#define X1  $v1
#define X2  $t2
#define X3  $fp
#define X4  $s0
#define X5  $s1
#define X6  $s2
#define X7  $s3
#define X8  $s4
#define X9  $s5
#define X10 $s6
#define X11 $s7
#define X12 $t6
#define X13 $t7
#define X14 $t8
#define X15 $t9
#define T0  $t0
#define T1  $t1
#define T(n) T ## n
#define X(n) X ## n

#define AXR(A, B, C, D,  K, L, M, N,  V, W, Y, Z,  S) \
	addu	X(A), X(K); \
	addu	X(B), X(L); \
	addu	X(C), X(M); \
	addu	X(D), X(N); \
	xor	X(V), X(A); \
	xor	X(W), X(B); \
	xor	X(Y), X(C); \
	xor	X(Z), X(D); \
	rotl	X(V), S;    \
	rotl	X(W), S;    \
	rotl	X(Y), S;    \
	rotl	X(Z), S;

#define CHACHA20_BLOCK_SIZE 64
#define STACK_SIZE	8*16

#define OUT		$a0
#define IN		$a1
#define BYTES		$a2
#define KEY		$a3

#define COUNTER		$t5
#define COUNTER_0	$t3
#define SAVED_X		X15
#define SAVED_CA	T1
#define PTR_START_LAST_BLOCK	$t4
#define PTR_START_LAST_BYTES	$ra

#define CONSTANT_1	0x61707865
#define CONSTANT_2	0x3320646e
#define CONSTANT_3	0x79622d32
#define CONSTANT_4	0x6b206574

.text
.set reorder
.set noat
.globl chacha20_mips
.ent   chacha20_mips
chacha20_mips:
	/* This is in the fifth argument */
	lw	COUNTER, 16($sp)

	/* Return 0 bytes. */
	.set noreorder
	beqz	BYTES, .Lchacha20_mips_end
	subu	$sp, STACK_SIZE
	.set reorder

	/* Calculate PTR_START_LAST_BLOCK */
	addiu	PTR_START_LAST_BLOCK, BYTES, -1
	ins	PTR_START_LAST_BLOCK, $zero, 0, 6
	addu	PTR_START_LAST_BLOCK, OUT

	/* Save s0-s7 on stack. */
	sw	$ra,  0($sp)
	sw	$fp,  4($sp)
	sw	$s0,  8($sp)
	sw	$s1, 12($sp)
	sw	$s2, 16($sp)
	sw	$s3, 20($sp)
	sw	$s4, 24($sp)
	sw	$s5, 28($sp)
	sw	$s6, 32($sp)
	sw	$s7, 36($sp)

	/* Calculate PTR_START_LAST_BYTE */
	addu	PTR_START_LAST_BYTES, OUT, BYTES
	andi	BYTES, (CHACHA20_BLOCK_SIZE-1)
	subu	PTR_START_LAST_BYTES, BYTES

	/* Load constant */
	lui	X0, %hi(CONSTANT_1)
	lui	X1, %hi(CONSTANT_2)
	lui	X2, %hi(CONSTANT_3)
	lui	X3, %hi(CONSTANT_4)
	ori	X0, %lo(CONSTANT_1)
	ori	X1, %lo(CONSTANT_2)
	ori	X2, %lo(CONSTANT_3)
	ori	X3, %lo(CONSTANT_4)

	/* Load key */
	andi	$at, KEY, 0x3
	lwl	X4,   0+MSB(KEY)
	lwl	X5,   4+MSB(KEY)
	lwl	X6,   8+MSB(KEY)
	lwl	X7,  12+MSB(KEY)
	lwl	X8,  16+MSB(KEY)
	lwl	X9,  20+MSB(KEY)
	lwl	X10, 24+MSB(KEY)
	lwl	X11, 28+MSB(KEY)
	.set noreorder
	bnez	$at, .Lchacha20_key_unaligned
	lwl	X11, 28+MSB(KEY)
	.set reorder

.Lchacha20_key_aligned:
	/* Load nonce */
	andi	$at, COUNTER, 0x3
	lwr	X12,  0+LSB(COUNTER)
	lwr	X13,  4+LSB(COUNTER)
	lwr	X14,  8+LSB(COUNTER)
	.set noreorder
	bnez	$at, .Lchacha20_counter_unaligned
	lwr	X15, 12+LSB(COUNTER)
	.set reorder

.Lchacha20_counter_aligned:
	/* test SRC and DST are unaligned.
	 * UNALIGNED = ( IN | OUT ) & 0x00000003
	 */
	or	$at, IN, OUT
	andi	$at, 0x3

	/* Store constant on stack. */
	sw	X0, 64($sp)
	sw	X1, 68($sp)
	sw	X2, 72($sp)
	sw	X3, 76($sp)

	/* Data aligned? */
	.set noreorder
	beqz	$at, .Loop_chacha20_start_aligned
	move	COUNTER_0, X12
	.set reorder

	/* Data unaligned */
	.set noreorder
	b	.Loop_chacha20_start_unaligned
	nop	/* Delay slot */
	.set reorder

.Lchacha20_key_unaligned:
	/* Load remaining key unaligned */
	lwr	X4,   0+LSB(KEY)
	lwr	X5,   4+LSB(KEY)
	lwr	X6,   8+LSB(KEY)
	lwr	X7,  12+LSB(KEY)
	lwr	X8,  16+LSB(KEY)
	lwr	X9,  20+LSB(KEY)
	lwr	X10, 24+LSB(KEY)
	lwr	X11, 28+LSB(KEY)
	/* Store key on stack */
	sw	X4,   80($sp)
	sw	X5,   84($sp)
	sw	X6,   88($sp)
	sw	X7,   92($sp)
	sw	X8,   96($sp)
	sw	X9,  100($sp)
	sw	X10, 104($sp)
	sw	X11, 108($sp)
	.set noreorder
	b	.Lchacha20_key_aligned
	/* Point KEY to stack location */
	addiu	KEY, $sp, 80
	.set reorder

.Lchacha20_counter_unaligned:
	/* Load remaining nonce unaligned */
	lwl	X12,  0+MSB(COUNTER)
	lwl	X13,  4+MSB(COUNTER)
	lwl	X14,  8+MSB(COUNTER)
	lwl	X15, 12+MSB(COUNTER)
	/* Store nonce on stack */
	sw	X12, 112($sp)
	sw	X13, 116($sp)
	sw	X14, 120($sp)
	sw	X15, 124($sp)
	.set noreorder
	b	.Lchacha20_counter_aligned
	/* Point COUNTER to stack location */
	addiu	COUNTER, $sp, 112
	.set reorder

/*
 * Aligned Code Path
 */

.align 4
.Loop_chacha20_aligned:
	addiu	IN,  CHACHA20_BLOCK_SIZE
	addiu	OUT, CHACHA20_BLOCK_SIZE

	lw	X0,  64($sp)
	lw	X1,  68($sp)
	lw	X2,  72($sp)
	lw	X3,  76($sp)
	lw	X4,   0(KEY)
	lw	X5,   4(KEY)
	lw	X6,   8(KEY)
	lw	X7,  12(KEY)
	lw	X8,  16(KEY)
	lw	X9,  20(KEY)
	lw	X10, 24(KEY)
	lw	X11, 28(KEY)
	move	X12, COUNTER_0
	lw	X13,  4(COUNTER)
	lw	X14,  8(COUNTER)
	lw	X15, 12(COUNTER)

.Loop_chacha20_start_aligned:
	li	$at, 9
.Loop_chacha20_xor_rounds_aligned:
	AXR( 0, 1, 2, 3,  4, 5, 6, 7, 12,13,14,15, 16);
	AXR( 8, 9,10,11, 12,13,14,15,  4, 5, 6, 7, 12);
	AXR( 0, 1, 2, 3,  4, 5, 6, 7, 12,13,14,15,  8);
	AXR( 8, 9,10,11, 12,13,14,15,  4, 5, 6, 7,  7);
	AXR( 0, 1, 2, 3,  5, 6, 7, 4, 15,12,13,14, 16);
	AXR(10,11, 8, 9, 15,12,13,14,  5, 6, 7, 4, 12);
	AXR( 0, 1, 2, 3,  5, 6, 7, 4, 15,12,13,14,  8);
	AXR(10,11, 8, 9, 15,12,13,14,  5, 6, 7, 4,  7);

	.set noreorder
	bnez	$at, .Loop_chacha20_xor_rounds_aligned
	addiu	$at, -1
	.set reorder

	/* FULL BLOCK, jump */
	.set noreorder
	beq	OUT, PTR_START_LAST_BYTES, .Lchacha20_mips_xor_aligned_nonfull_block
	andi	$at, BYTES, MASK_BYTES
	.set reorder

	STORE_ALIGNED(64, 15, COUNTER,12)
	STORE_ALIGNED(60, 14, COUNTER, 8)
	STORE_ALIGNED(56, 13, COUNTER, 4)
	/* STORE_ALIGNED(52, 12, COUNTER, 0) */
.Lchacha20_mips_xor_aligned_52_b:
	addu	X12, COUNTER_0
	lw	T1, 48(IN)
	addiu	COUNTER_0, 1
	WSBH(X12)
	xor	X12, T1
	sw	X12, 48(OUT)

	STORE_ALIGNED(48, 11, KEY, 28)
	STORE_ALIGNED(44, 10, KEY, 24)
	STORE_ALIGNED(40,  9, KEY, 20)
	STORE_ALIGNED(36,  8, KEY, 16)
	STORE_ALIGNED(32,  7, KEY, 12)
	STORE_ALIGNED(28,  6, KEY,  8)
	STORE_ALIGNED(24,  5, KEY,  4)
	STORE_ALIGNED(20,  4, KEY,  0)
	STORE_ALIGNED(16,  3, $sp, 76)
	STORE_ALIGNED(12,  2, $sp, 72)
	STORE_ALIGNED( 8,  1, $sp, 68)
	/* STORE_ALIGNED( 4,  0, $sp, 64) */
.Lchacha20_mips_xor_aligned_4_b:
	lw	T0, 64($sp)
	lw	T1, 0(IN)
	addu	X0, T0
	WSBH(X0)
	xor	X0, T1
	.set noreorder
	bne	OUT, PTR_START_LAST_BLOCK, .Loop_chacha20_aligned
.Lchacha20_mips_xor_aligned_0bytes:
	sw	X0, 0(OUT)
	.set reorder

.Lchacha20_mips_xor_aligned_0_b:
	/* Restore used registers */
	lw	$ra,  0($sp)
	lw	$fp,  4($sp)
	lw	$s0,  8($sp)
	lw	$s1, 12($sp)
	lw	$s2, 16($sp)
	lw	$s3, 20($sp)
	lw	$s4, 24($sp)
	lw	$s5, 28($sp)
	lw	$s6, 32($sp)
	lw	$s7, 36($sp)

	.set noreorder
	jr	$ra
	addiu	$sp, STACK_SIZE
	.set reorder
	.set at

.set noat
.Lchacha20_mips_xor_aligned_nonfull_block:
	/* Multipul of 4 Bytes? */
	.set noreorder
	bnez	$at, .Lchacha20_mips_calc_setup_aligned
	lui	$at, %hi(.Lchacha20_mips_xor_aligned_0bytes)
	.set reorder

	/* $at = ADDRESS(.Lchacha20_mips_xor_aligned_0bytes) - ( num of u32 [BYTES & MASK_U32] ) * instructions */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	/* 7 instuction * num of u32 */
	sll	T0, BYTES, 3
	subu	T0, BYTES
#else
	/* 5 instuction * num of u32 */
	sll	T0, BYTES, 2
	addu	T0, BYTES
#endif
	subu	$at, T0
	addiu	$at, %lo(.Lchacha20_mips_xor_aligned_0bytes)
	jr	$at
	nop	/* Delay slot */

.Lchacha20_mips_calc_setup_aligned:
	/* $at = ADDRESS(.Lchacha20_mips_setup_aligned) + ((BYTES & MASK_U32) << 2) */
	andi	T0, BYTES, MASK_U32
	ins	$at, T0, 2, 6
	addiu	$at, %lo(.Lchacha20_mips_setup_aligned)
	addu	IN, T0
	.set noreorder
	jr	$at
	addu	OUT, T0
	.set noreorder

.set noreorder
.Lchacha20_mips_setup_aligned:
	SETUP_ALIGNED( 0,  0, $sp, 64)
	SETUP_ALIGNED( 4,  1, $sp, 68)
	SETUP_ALIGNED( 8,  2, $sp, 72)
	SETUP_ALIGNED(12,  3, $sp, 76)
	SETUP_ALIGNED(16,  4, KEY,  0)
	SETUP_ALIGNED(20,  5, KEY,  4)
	SETUP_ALIGNED(24,  6, KEY,  8)
	SETUP_ALIGNED(28,  7, KEY, 12)
	SETUP_ALIGNED(32,  8, KEY, 16)
	SETUP_ALIGNED(36,  9, KEY, 20)
	SETUP_ALIGNED(40, 10, KEY, 24)
	SETUP_ALIGNED(44, 11, KEY, 28)
	/* SETUP_ALIGNED(48, 12, COUNTER, 0) */
	move	SAVED_CA, COUNTER_0
	bal	.Lchacha20_mips_xor_bytes
	move	SAVED_X, X12
	b	.Lchacha20_mips_xor_aligned_48_b
	SETUP_ALIGNED(52, 13, COUNTER, 4)
	SETUP_ALIGNED(56, 14, COUNTER, 8)
	SETUP_ALIGNED(60, 15, COUNTER,12)
	nop	/* Delay slot */
	.set reorder

/*
 * Unaligned Code Path
 */

.Loop_chacha20_unaligned:
	addiu	IN,  CHACHA20_BLOCK_SIZE
	addiu	OUT, CHACHA20_BLOCK_SIZE

	lw	X0,  64($sp)
	lw	X1,  68($sp)
	lw	X2,  72($sp)
	lw	X3,  76($sp)
	lw	X4,   0(KEY)
	lw	X5,   4(KEY)
	lw	X6,   8(KEY)
	lw	X7,  12(KEY)
	lw	X8,  16(KEY)
	lw	X9,  20(KEY)
	lw	X10, 24(KEY)
	lw	X11, 28(KEY)
	move	X12, COUNTER_0
	lw	X13,  4(COUNTER)
	lw	X14,  8(COUNTER)
	lw	X15, 12(COUNTER)

.Loop_chacha20_start_unaligned:
	li	$at, 9
.Loop_chacha20_xor_rounds_unaligned:
	AXR( 0, 1, 2, 3,  4, 5, 6, 7, 12,13,14,15, 16);
	AXR( 8, 9,10,11, 12,13,14,15,  4, 5, 6, 7, 12);
	AXR( 0, 1, 2, 3,  4, 5, 6, 7, 12,13,14,15,  8);
	AXR( 8, 9,10,11, 12,13,14,15,  4, 5, 6, 7,  7);
	AXR( 0, 1, 2, 3,  5, 6, 7, 4, 15,12,13,14, 16);
	AXR(10,11, 8, 9, 15,12,13,14,  5, 6, 7, 4, 12);
	AXR( 0, 1, 2, 3,  5, 6, 7, 4, 15,12,13,14,  8);
	AXR(10,11, 8, 9, 15,12,13,14,  5, 6, 7, 4,  7);

	.set noreorder
	bnez	$at, .Loop_chacha20_xor_rounds_unaligned
	addiu	$at, -1
	.set reorder

	/* FULL BLOCK, jump */
	.set noreorder
	beq	OUT, PTR_START_LAST_BYTES, .Lchacha20_mips_xor_unaligned_nonfull_block
	andi	$at, BYTES, MASK_BYTES
	.set reorder

	STORE_UNALIGNED(64, 15, COUNTER,12)
	STORE_UNALIGNED(60, 14, COUNTER, 8)
	STORE_UNALIGNED(56, 13, COUNTER, 4)
	/* STORE_UNALIGNED(52, 12, COUNTER, 0) */
.Lchacha20_mips_xor_unaligned_52_b:
	addu	X12, COUNTER_0
	lwl	T1, 48+MSB(IN)
	lwr	T1, 48+LSB(IN)
	addiu	COUNTER_0, 1
	WSBH(X12)
	xor	X12, T1
	swl	X12, 48+MSB(OUT)
	swr	X12, 48+LSB(OUT)
	STORE_UNALIGNED(48, 11, KEY, 28)
	STORE_UNALIGNED(44, 10, KEY, 24)
	STORE_UNALIGNED(40,  9, KEY, 20)
	STORE_UNALIGNED(36,  8, KEY, 16)
	STORE_UNALIGNED(32,  7, KEY, 12)
	STORE_UNALIGNED(28,  6, KEY,  8)
	STORE_UNALIGNED(24,  5, KEY,  4)
	STORE_UNALIGNED(20,  4, KEY,  0)
	STORE_UNALIGNED(16,  3, $sp, 76)
	STORE_UNALIGNED(12,  2, $sp, 72)
	STORE_UNALIGNED( 8,  1, $sp, 68)
	/* STORE_UNALIGNED( 4,  0, $sp, 64) */
.Lchacha20_mips_xor_unaligned_4_b:
	lw	T0, 64($sp)
	lwl	T1, 0+MSB(IN)
	lwr	T1, 0+LSB(IN)
	addu	X0, T0
	WSBH(X0)
	xor	X0, T1
	.set noreorder
	swl	X0, 0+MSB(OUT)
	bne	OUT, PTR_START_LAST_BLOCK, .Loop_chacha20_unaligned
.Lchacha20_mips_xor_unaligned_0bytes:
	swr	X0, 0+LSB(OUT)
	.set reorder

.Lchacha20_mips_xor_unaligned_0_b:
	/* Restore s0-s7 */
	lw	$ra,  0($sp)
	lw	$fp,  4($sp)
	lw	$s0,  8($sp)
	lw	$s1, 12($sp)
	lw	$s2, 16($sp)
	lw	$s3, 20($sp)
	lw	$s4, 24($sp)
	lw	$s5, 28($sp)
	lw	$s6, 32($sp)
	lw	$s7, 36($sp)

.Lchacha20_mips_end:
	.set noreorder
	jr	$ra
	addiu	$sp, STACK_SIZE
	.set reorder
.set at

.set noat
.Lchacha20_mips_xor_unaligned_nonfull_block:
	/* Multipul of 4 Bytes? */
	.set noreorder
	bnez	$at, .Lchacha20_mips_calc_setup_unaligned
	lui	$at, %hi(.Lchacha20_mips_xor_unaligned_0bytes)
	.set reorder

	/* $at = ADDRESS(.Lchacha20_mips_xor_unaligned_0bytes) - ( num of u32 [BYTES & MASK_U32] ) * instructions */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	/* 9 instuction * num of u32 */
	sll	T0, BYTES, 3
	addu	T0, BYTES
#else
	/* 7 instuction * num of u32 */
	sll	T0, BYTES, 3
	subu	T0, BYTES
#endif
	subu	$at, T0
	addiu	$at, %lo(.Lchacha20_mips_xor_unaligned_0bytes)
	jr	$at
	nop	/* Delay slot */

.Lchacha20_mips_calc_setup_unaligned:
	/* $AT = ADDRESS(.Lchacha20_mips_setup_unaligned) + ((BYTES & MASK_U32) << 2) */
	andi	T0, BYTES, MASK_U32
	ins	$at, T0, 2, 6
	addiu	$at, %lo(.Lchacha20_mips_setup_unaligned)
	addu	IN, T0
	.set noreorder
	jr	$at
	addu	OUT, T0
	.set noreorder

.set noreorder
.Lchacha20_mips_setup_unaligned:
	SETUP_UNALIGNED( 0,  0, $sp, 64)
	SETUP_UNALIGNED( 4,  1, $sp, 68)
	SETUP_UNALIGNED( 8,  2, $sp, 72)
	SETUP_UNALIGNED(12,  3, $sp, 76)
	SETUP_UNALIGNED(16,  4, KEY,  0)
	SETUP_UNALIGNED(20,  5, KEY,  4)
	SETUP_UNALIGNED(24,  6, KEY,  8)
	SETUP_UNALIGNED(28,  7, KEY, 12)
	SETUP_UNALIGNED(32,  8, KEY, 16)
	SETUP_UNALIGNED(36,  9, KEY, 20)
	SETUP_UNALIGNED(40, 10, KEY, 24)
	SETUP_UNALIGNED(44, 11, KEY, 28)
	/* SETUP_UNALIGNED(48, 12, COUNTER, 0) */
	move	SAVED_CA, COUNTER_0
	bal	.Lchacha20_mips_xor_bytes
	move	SAVED_X, X12
	b	.Lchacha20_mips_xor_unaligned_48_b
	SETUP_UNALIGNED(52, 13, COUNTER, 4)
	SETUP_UNALIGNED(56, 14, COUNTER, 8)
	SETUP_UNALIGNED(60, 15, COUNTER,12)
	nop	/* Delay slot */
.set reorder

.set noat
.Lchacha20_mips_xor_bytes:
	andi	$at, BYTES, 0x02
	addu	SAVED_X, SAVED_CA

	/* First Byte */
	lbu	T1, 0(IN)
	WSBH(SAVED_X)
	ROTR(SAVED_X)

	xor	T1, SAVED_X
	.set noreorder
	beqz	$at, .Lchacha20_mips_xor_bytes_done
	sb	T1, 0(OUT)
	.set reorder

	/* Second Byte */
	lbu	T1, 1(IN)
	andi	$at, BYTES, 1
	ROTx	SAVED_X, 8
	xor	T1, SAVED_X
	.set noreorder
	beqz	$at, .Lchacha20_mips_xor_bytes_done
	sb	T1, 1(OUT)
	.set reorder

	/* Third Byte */
	lbu	T1, 2(IN)
	ROTx	SAVED_X, 8
	xor	T1, SAVED_X
	sb	T1, 2(OUT)

.Lchacha20_mips_xor_bytes_done:
	subu	IN, T0
	.set noreorder
	jr	$ra
	subu	OUT, T0
	.set reorder

.end chacha20_mips
.set at
