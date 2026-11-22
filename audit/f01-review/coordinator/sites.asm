# Coordinator's extract (not the reviewer's): the two doubling loops inside f01_sign_core, from
# objdump -d --no-show-raw-insn of target/release/libf01b.so as run_all.sh rebuilt it from clean on
# 2026-11-22 with rustc 1.97.0 and the workspace's release profile. memcheck reports the je at
# 16276 (loop 1, R mod p), and at 164f7 and 16506 (loop 2, R^2 mod p). %r14 holds nat::add's carry,
# 0x518(%rsp) nat::sub's borrow. Symbol names shortened.

## up to 16276
   1618d:	movups 0x4d8(%rsp),%xmm0
   16195:	movaps %xmm0,0x40(%rsp)
   1619a:	movups 0x498(%rsp),%xmm0
   161a2:	movups 0x4a8(%rsp),%xmm1
   161aa:	movups 0x4b8(%rsp),%xmm2
   161b2:	movups 0x4c8(%rsp),%xmm3
   161ba:	movaps %xmm3,0x30(%rsp)
   161bf:	movaps %xmm2,0x20(%rsp)
   161c4:	movaps %xmm1,0x10(%rsp)
   161c9:	movaps %xmm0,(%rsp)
   161cd:	mov    0x518(%rsp),%r14
   161d5:	mov    %r12,%rdi
   161d8:	mov    %rbp,%rsi
   161db:	mov    %r15,%rdx
   161de:	call   15900 <bouncycastle_ec::nat::sub>
   161e3:	movups 0x508(%rsp),%xmm0
   161eb:	movaps %xmm0,0x400(%rsp)
   161f3:	movups 0x4f8(%rsp),%xmm0
   161fb:	movaps %xmm0,0x3f0(%rsp)
   16203:	movups 0x4e8(%rsp),%xmm0
   1620b:	movaps %xmm0,0x3e0(%rsp)
   16213:	movups 0x4d8(%rsp),%xmm0
   1621b:	movaps %xmm0,0x3d0(%rsp)
   16223:	movups 0x498(%rsp),%xmm0
   1622b:	movups 0x4a8(%rsp),%xmm1
   16233:	movups 0x4b8(%rsp),%xmm2
   1623b:	movups 0x4c8(%rsp),%xmm3
   16243:	movaps %xmm3,0x3c0(%rsp)
   1624b:	movaps %xmm2,0x3b0(%rsp)
   16253:	movaps %xmm1,0x3a0(%rsp)
   1625b:	movaps %xmm0,0x390(%rsp)
   16263:	cmp    $0x1,%r14
   16267:	je     160d0 <f01_sign_core+0xd0>
   1626d:	cmpq   $0x0,0x518(%rsp)
   16276:	je     160d0 <f01_sign_core+0xd0>
   1627c:	movaps 0x70(%rsp),%xmm0

## up to 16506
   1641d:	movups 0x4d8(%rsp),%xmm0
   16425:	movaps %xmm0,0x40(%rsp)
   1642a:	movups 0x498(%rsp),%xmm0
   16432:	movups 0x4a8(%rsp),%xmm1
   1643a:	movups 0x4b8(%rsp),%xmm2
   16442:	movups 0x4c8(%rsp),%xmm3
   1644a:	movaps %xmm3,0x30(%rsp)
   1644f:	movaps %xmm2,0x20(%rsp)
   16454:	movaps %xmm1,0x10(%rsp)
   16459:	movaps %xmm0,(%rsp)
   1645d:	mov    0x518(%rsp),%r14
   16465:	mov    %r12,%rdi
   16468:	mov    %rbp,%rsi
   1646b:	mov    %r15,%rdx
   1646e:	call   15900 <bouncycastle_ec::nat::sub>
   16473:	movups 0x508(%rsp),%xmm0
   1647b:	movaps %xmm0,0x400(%rsp)
   16483:	movups 0x4f8(%rsp),%xmm0
   1648b:	movaps %xmm0,0x3f0(%rsp)
   16493:	movups 0x4e8(%rsp),%xmm0
   1649b:	movaps %xmm0,0x3e0(%rsp)
   164a3:	movups 0x4d8(%rsp),%xmm0
   164ab:	movaps %xmm0,0x3d0(%rsp)
   164b3:	movups 0x498(%rsp),%xmm0
   164bb:	movups 0x4a8(%rsp),%xmm1
   164c3:	movups 0x4b8(%rsp),%xmm2
   164cb:	movups 0x4c8(%rsp),%xmm3
   164d3:	movaps %xmm3,0x3c0(%rsp)
   164db:	movaps %xmm2,0x3b0(%rsp)
   164e3:	movaps %xmm1,0x3a0(%rsp)
   164eb:	movaps %xmm0,0x390(%rsp)
   164f3:	cmp    $0x1,%r14
   164f7:	je     16360 <f01_sign_core+0x360>
   164fd:	cmpq   $0x0,0x518(%rsp)
   16506:	je     16360 <f01_sign_core+0x360>
   1650c:	movaps 0x70(%rsp),%xmm0
