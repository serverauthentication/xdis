.code

scan_byte_avx2 PROC
    xor     rax, rax
    test    rdx, rdx
    jz      sba_done

    vmovd   xmm0, r8d
    vpbroadcastb ymm0, xmm0

    mov     r9, rdx
    and     r9, -32
    cmp     rax, r9
    jae     sba_tail

sba_loop:
    vmovdqu ymm1, ymmword ptr [rcx + rax]
    vpcmpeqb ymm1, ymm1, ymm0
    vpmovmskb r10d, ymm1
    test    r10d, r10d
    jnz     sba_hit
    add     rax, 32
    cmp     rax, r9
    jb      sba_loop

sba_tail:
    cmp     rax, rdx
    jae     sba_done
    cmp     byte ptr [rcx + rax], r8b
    je      sba_done
    inc     rax
    jmp     sba_tail

sba_hit:
    bsf     r10d, r10d
    add     rax, r10

sba_done:
    vzeroupper
    ret
scan_byte_avx2 ENDP

scan_calls_avx2 PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    .endprolog

    xor     rax, rax
    cmp     rdx, 5
    jb      sca_done
    test    r9, r9
    jz      sca_done

    sub     rdx, 4
    mov     r10d, 0E8h
    vmovd   xmm0, r10d
    vpbroadcastb ymm0, xmm0

    xor     rbx, rbx
    mov     rsi, rdx
    and     rsi, -32
    cmp     rbx, rsi
    jae     sca_tail

sca_loop:
    vmovdqu ymm1, ymmword ptr [rcx + rbx]
    vpcmpeqb ymm1, ymm1, ymm0
    vpmovmskb r10d, ymm1
    test    r10d, r10d
    jz      sca_next

sca_bits:
    bsf     r11d, r10d
    add     r11, rbx
    mov     dword ptr [r8 + rax * 4], r11d
    inc     rax
    cmp     rax, r9
    jae     sca_done
    lea     r11d, [r10d - 1]
    and     r10d, r11d
    jnz     sca_bits

sca_next:
    add     rbx, 32
    cmp     rbx, rsi
    jb      sca_loop

sca_tail:
    cmp     rbx, rdx
    jae     sca_done
    cmp     byte ptr [rcx + rbx], 0E8h
    jne     sca_tail_next
    mov     dword ptr [r8 + rax * 4], ebx
    inc     rax
    cmp     rax, r9
    jae     sca_done

sca_tail_next:
    inc     rbx
    jmp     sca_tail

sca_done:
    vzeroupper
    pop     rsi
    pop     rbx
    ret
scan_calls_avx2 ENDP

END
