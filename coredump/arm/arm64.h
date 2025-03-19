// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#ifndef ARM64_DEFS_H_
#define ARM64_DEFS_H_

#include "coredump/core.h"

#define elf_hdr     Elf64_Ehdr
#define elf_phdr    Elf64_Phdr
#define elf_note    Elf64_Nhdr
#define elf_addr_t  Elf64_Off

#define BIT(nr)         (1UL << (nr))
#define GENMASK_ULL(h, l) (((1ULL<<(h+1))-1)&(~((1ULL<<l)-1)))

#define SCTLR_ELx_ENIA (BIT(31))
#define SCTLR_ELx_ENIB (BIT(30))
#define SCTLR_ELx_ENDA (BIT(27))
#define SCTLR_ELx_ENDB (BIT(13))

#define PR_PAC_APIAKEY (1UL << 0)
#define PR_PAC_APIBKEY (1UL << 1)
#define PR_PAC_APDAKEY (1UL << 2)
#define PR_PAC_APDBKEY (1UL << 3)
#define PR_PAC_APGAKEY (1UL << 4)

#define TIF_TAGGED_ADDR 26
#define PR_TAGGED_ADDR_ENABLE (1UL << 0)
#define MTE_CTRL_GCR_USER_EXCL_SHIFT 0
#define SYS_GCR_EL1_EXCL_MASK 0xffffUL

#define MTE_CTRL_TCF_SYNC (1UL << 16)
#define MTE_CTRL_TCF_ASYNC (1UL << 17)

#define PR_MTE_TAG_SHIFT 3
#define PR_MTE_TCF_SYNC (1UL << 1)
#define PR_MTE_TCF_ASYNC (1UL << 2)

struct user_pac_mask {
    uint64_t data_mask;
    uint64_t insn_mask;
};

struct elf_siginfo {
    int si_signo;
    int si_errno;
    int si_code;
    // char padding[36];
};

struct __kernel_old_timeval {
    long tv_sec;
    long tv_usec;
};

struct elf64_prstatus {
    struct elf_siginfo pr_info;
    short pr_cursig;
    unsigned long pr_sigpend;
    unsigned long pr_sighold;
    pid_t pr_pid;
    pid_t pr_ppid;
    pid_t pr_pgrp;
    pid_t pr_sid;
    long pr_utime[2]; // __kernel_old_timeval
    long pr_stime[2];
    long pr_cutime[2];
    long pr_cstime[2];
    struct user_pt_regs pr_reg;
    int pr_fpvalid;
};

class Arm64 : public Core {
    protected:
        elf_hdr* hdr;
    public:
        Arm64(std::shared_ptr<Swapinfo> swap);
        ~Arm64();
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

#endif // ARM64_DEFS_H_
