.code

scan_byte_x64 PROC
    xor     rax, rax
    test    rdx, rdx
    jz      sb_done

    movzx   r9d, r8b
    movd    xmm0, r9d
    punpcklbw xmm0, xmm0
    punpcklwd xmm0, xmm0
    pshufd  xmm0, xmm0, 0

    mov     r9, rdx
    and     r9, -16
    cmp     rax, r9
    jae     sb_tail

sb_loop:
    movdqu  xmm1, xmmword ptr [rcx + rax]
    pcmpeqb xmm1, xmm0
    pmovmskb r10d, xmm1
    test    r10d, r10d
    jnz     sb_hit
    add     rax, 16
    cmp     rax, r9
    jb      sb_loop

sb_tail:
    cmp     rax, rdx
    jae     sb_done
    cmp     byte ptr [rcx + rax], r8b
    je      sb_done
    inc     rax
    jmp     sb_tail

sb_hit:
    bsf     r10d, r10d
    add     rax, r10

sb_done:
    ret
scan_byte_x64 ENDP

scan_calls_x64 PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    .endprolog

    xor     rax, rax
    cmp     rdx, 5
    jb      sc_done
    test    r9, r9
    jz      sc_done

    sub     rdx, 4
    mov     r10d, 0E8E8E8E8h
    movd    xmm0, r10d
    pshufd  xmm0, xmm0, 0

    xor     rbx, rbx
    mov     rsi, rdx
    and     rsi, -16
    cmp     rbx, rsi
    jae     sc_tail

sc_loop:
    movdqu  xmm1, xmmword ptr [rcx + rbx]
    pcmpeqb xmm1, xmm0
    pmovmskb r10d, xmm1
    test    r10d, r10d
    jz      sc_next

sc_bits:
    bsf     r11d, r10d
    add     r11, rbx
    mov     dword ptr [r8 + rax * 4], r11d
    inc     rax
    cmp     rax, r9
    jae     sc_done
    lea     r11d, [r10d - 1]
    and     r10d, r11d
    jnz     sc_bits

sc_next:
    add     rbx, 16
    cmp     rbx, rsi
    jb      sc_loop

sc_tail:
    cmp     rbx, rdx
    jae     sc_done
    cmp     byte ptr [rcx + rbx], 0E8h
    jne     sc_tail_next
    mov     dword ptr [r8 + rax * 4], ebx
    inc     rax
    cmp     rax, r9
    jae     sc_done

sc_tail_next:
    inc     rbx
    jmp     sc_tail

sc_done:
    pop     rsi
    pop     rbx
    ret
scan_calls_x64 ENDP

scan_ascii_next_x64 PROC
    mov     rax, r8
    cmp     rax, rdx
    jae     sn_end

    mov     r9d, 1F1F1F1Fh
    movd    xmm0, r9d
    pshufd  xmm0, xmm0, 0
    mov     r9d, 7F7F7F7Fh
    movd    xmm1, r9d
    pshufd  xmm1, xmm1, 0

    mov     r9, rdx
    sub     r9, rax
    cmp     r9, 16
    jb      sn_tail

    mov     r9, rdx
    sub     r9, 16

sn_loop:
    movdqu  xmm2, xmmword ptr [rcx + rax]
    movdqa  xmm3, xmm2
    pcmpgtb xmm3, xmm0
    movdqa  xmm4, xmm1
    pcmpgtb xmm4, xmm2
    pand    xmm3, xmm4
    pmovmskb r10d, xmm3
    test    r10d, r10d
    jnz     sn_hit
    add     rax, 16
    cmp     rax, r9
    jbe     sn_loop

sn_tail:
    cmp     rax, rdx
    jae     sn_end
    movzx   r10d, byte ptr [rcx + rax]
    sub     r10d, 20h
    cmp     r10d, 5Fh
    jb      sn_done
    inc     rax
    jmp     sn_tail

sn_hit:
    bsf     r10d, r10d
    add     rax, r10
    ret

sn_end:
    mov     rax, rdx
sn_done:
    ret
scan_ascii_next_x64 ENDP

scan_ascii_run_x64 PROC
    xor     rax, rax
    test    rdx, rdx
    jz      sr_done

    mov     r9d, 1F1F1F1Fh
    movd    xmm0, r9d
    pshufd  xmm0, xmm0, 0
    mov     r9d, 7F7F7F7Fh
    movd    xmm1, r9d
    pshufd  xmm1, xmm1, 0

    mov     r9, rdx
    and     r9, -16
    cmp     rax, r9
    jae     sr_tail

sr_loop:
    movdqu  xmm2, xmmword ptr [rcx + rax]
    movdqa  xmm3, xmm2
    pcmpgtb xmm3, xmm0
    movdqa  xmm4, xmm1
    pcmpgtb xmm4, xmm2
    pand    xmm3, xmm4
    pmovmskb r10d, xmm3
    xor     r10d, 0FFFFh
    test    r10d, r10d
    jnz     sr_hit
    add     rax, 16
    cmp     rax, r9
    jb      sr_loop

sr_tail:
    cmp     rax, rdx
    jae     sr_done
    movzx   r10d, byte ptr [rcx + rax]
    sub     r10d, 20h
    cmp     r10d, 5Fh
    jae     sr_done
    inc     rax
    jmp     sr_tail

sr_hit:
    bsf     r10d, r10d
    add     rax, r10

sr_done:
    ret
scan_ascii_run_x64 ENDP

END
