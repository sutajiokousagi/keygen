 

















































	.text
	
	.globl mpsetmul
	
	.type mpsetmul,function

mpsetmul:

	stmfd sp!, {r4, r5, lr}
	add r1, r1, r0, asl #2
	add r2, r2, r0, asl #2
	mov ip, #0
.Lmpsetmul_loop:
	ldr r4, [r2, #-4]!
	mov r5, #0
	umlal ip, r5, r3, r4
	str ip, [r1, #-4]!
	mov ip, r5
	subs r0, r0, #1
	bne .Lmpsetmul_loop
	mov r0, ip
	ldmfd sp!, {r4, r5, pc}

.Lmpsetmul_size:
	.size mpsetmul, .Lmpsetmul_size  - mpsetmul


	

	.text
	
	.globl mpaddmul
	
	.type mpaddmul,function

mpaddmul:

	stmfd sp!, {r4, r5, r6, lr}
	add r1, r1, r0, asl #2
	add r2, r2, r0, asl #2
	mov ip, #0
.Lmpaddmul_loop:
	ldr r4, [r2, #-4]!
	ldr r5, [r1, #-4]
	mov r6, #0
	umlal ip, r6, r3, r4
	adds r5, r5, ip
	adc ip, r6, #0
	str r5, [r1, #-4]!
	subs r0, r0, #1
	bne .Lmpaddmul_loop
	mov r0, ip
	ldmfd sp!, {r4, r5, r6, pc}

.Lmpaddmul_size:
	.size mpaddmul, .Lmpaddmul_size  - mpaddmul




	.text
	
	.globl mpaddsqrtrc
	
	.type mpaddsqrtrc,function

mpaddsqrtrc:

	stmfd sp!, {r4, r5, r6, lr}
	add r1, r1, r0, asl #3
	add r2, r2, r0, asl #2
	mov r3, #0
	mov ip, #0
.Lmpaddsqrtrc_loop:
	ldr r4, [r2, #-4]!
	mov r6, #0
	umlal ip, r6, r4, r4
	ldr r5, [r1, #-4]
	ldr r4, [r1, #-8]
	adds r5, r5, ip
	adcs r4, r4, r6
	str r5, [r1, #-4]
	str r4, [r1, #-8]!
	adc ip, r3, #0
	subs r0, r0, #1
	bne .Lmpaddsqrtrc_loop
	mov r0, ip
	ldmfd sp!, {r4, r5, r6, pc}

.Lmpaddsqrtrc_size:
	.size mpaddsqrtrc, .Lmpaddsqrtrc_size  - mpaddsqrtrc

