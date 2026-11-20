#pragma once

static const char *const x86_r8[16] = {
    "al","cl","dl","bl","ah","ch","dh","bh",
    "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"
};

static const char *const x86_r8_rex[16] = {
    "al","cl","dl","bl","spl","bpl","sil","dil",
    "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"
};

static const char *const x86_r16[16] = {
    "ax","cx","dx","bx","sp","bp","si","di",
    "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"
};

static const char *const x86_r32[16] = {
    "eax","ecx","edx","ebx","esp","ebp","esi","edi",
    "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"
};

static const char *const x86_r64[16] = {
    "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15"
};

static const char *const x86_seg[8] = {
    "es","cs","ss","ds","fs","gs","?","?"
};

static const char *const x86_alu[8] = {
    "add","or","adc","sbb","and","sub","xor","cmp"
};

static const char *const x86_shift[8] = {
    "rol","ror","rcl","rcr","shl","shr","sal","sar"
};

static const char *const x86_cc[16] = {
    "o","no","b","ae","e","ne","be","a",
    "s","ns","p","np","l","ge","le","g"
};

static const char *const x86_grp3[8] = {
    "test","test","not","neg","mul","imul","div","idiv"
};

static const char *const x86_grp5[8] = {
    "inc","dec","call","callf","jmp","jmpf","push","??"
};

static const char *const x86_bt[8] = {
    "??","??","??","??","bt","bts","btr","btc"
};
