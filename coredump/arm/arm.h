// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#ifndef ARM_DEFS_H_
#define ARM_DEFS_H_

#include "coredump/core.h"

#define elf_hdr     Elf32_Ehdr
#define elf_phdr    Elf32_Phdr
#define elf_note    Elf32_Nhdr
#define elf_addr_t  Elf32_Off

struct user_fp {
    struct fp_reg {
        unsigned int sign1:1;
        unsigned int unused:15;
        unsigned int sign2:1;
        unsigned int exponent:14;
        unsigned int j:1;
        unsigned int mantissa1:31;
        unsigned int mantissa0:32;
    } fpregs[8];
    unsigned int fpsr:32;
    unsigned int fpcr:32;
    unsigned char ftype[8];
    unsigned int init_flag;
};

struct user_vfp {
    unsigned long long fpregs[32];
    unsigned long fpscr;
};

struct arm32_pt_regs{
    unsigned long r0;
    unsigned long r1;
    unsigned long r2;
    unsigned long r3;
    unsigned long r4;
    unsigned long r5;
    unsigned long r6;
    unsigned long r7;
    unsigned long r8;
    unsigned long r9;
    unsigned long r10;
    unsigned long fp;
    unsigned long ip;
    unsigned long sp;
    unsigned long lr;
    unsigned long pc;
    unsigned long cpsr;
    unsigned long ORIG_r0;
};

#define ARM_VFPREGS_SIZE ( 32 * 8 /*fpregs*/ + 4 /*fpscr*/ )

struct elf_siginfo {
    int si_signo;
    int si_errno;
    int si_code;
    // char padding[20];
};

struct elf32_prstatus {
    struct elf_siginfo pr_info;
    short pr_cursig;
    unsigned long pr_sigpend;
    unsigned long pr_sighold;
    pid_t pr_pid;
    pid_t pr_ppid;
    pid_t pr_pgrp;
    pid_t pr_sid;
    struct timeval pr_utime;
    struct timeval pr_stime;
    struct timeval pr_cutime;
    struct timeval pr_cstime;
    struct arm32_pt_regs pr_reg;
    int pr_fpvalid;
};

class Arm : public Core {
    protected:
        elf_hdr* hdr;
    public:
        Arm(std::shared_ptr<Swapinfo> swap);
        ~Arm();
        void parser_auvx() override;
        void write_pt_note_phdr(size_t note_size) override;
        void write_pt_load_phdr(std::shared_ptr<vma> vma_ptr, size_t& vma_offset) override;
        void writenote(std::shared_ptr<memelfnote> note_ptr) override;
        int notesize(std::shared_ptr<memelfnote> note_ptr) override;
        void write_elf_header(int phnum) override;
        int get_phdr_start() override;
        int get_pt_note_data_start() override;
        void parser_prpsinfo() override;
        void parser_siginfo() override;
        void* parser_prstatus(ulong task_addr,int* data_size) override;
        void* parser_nt_prfpreg(ulong task_addr) override;
        void* parser_nt_arm_tls(ulong task_addr) override;
        void* parser_nt_arm_hw_break(ulong task_addr) override;
        void* parser_nt_arm_hw_watch(ulong task_addr) override;
        void* parser_nt_arm_system_call(ulong task_addr) override;
        void* parser_nt_arm_sve(ulong task_addr) override;
        void* parser_nt_arm_pac_mask(ulong task_addr) override;
        void* parser_nt_arm_pac_enabled_keys(ulong task_addr) override;
        void* parser_nt_arm_paca_keys(ulong task_addr) override;
        void* parser_nt_arm_pacg_keys(ulong task_addr) override;
        void* parser_nt_arm_tagged_addr_ctrl(ulong task_addr) override;
        void* parser_nt_arm_vfp(ulong task_addr) override;
};

#endif // ARM_DEFS_H_
