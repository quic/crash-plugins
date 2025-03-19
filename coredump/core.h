// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear
#ifndef CORE_DEFS_H_
#define CORE_DEFS_H_

#include "plugin.h"
#include <elf.h>
#include <linux/types.h>
#include "memory/swapinfo.h"

#define MMF_DUMP_ANON_PRIVATE  2
#define MMF_DUMP_ANON_SHARED  3
#define MMF_DUMP_MAPPED_PRIVATE  4
#define MMF_DUMP_MAPPED_SHARED  5
#define MMF_DUMP_ELF_HEADERS  6
#define MMF_DUMP_HUGETLB_PRIVATE  7
#define MMF_DUMP_HUGETLB_SHARED  8
#define MMF_DUMP_DAX_PRIVATE  9
#define MMF_DUMP_DAX_SHARED  10

#define NT_ARM_PAC_ENABLED_KEYS 0x40a
#define NT_ARM_TAGGED_ADDR_CTRL 0x409

#define VFP_FPSCR_STAT_MASK 0xf800009f
#define VFP_FPSCR_CTRL_MASK 0x07f79f00
typedef unsigned long long __ull[2];

/*
# +--------------------------------+
# |             elf header         |
# +--------------------------------+
# |    program header(PT_NOTE)     |
# +--------------------------------+
# |    program header(PT_Load)     |
# +--------------------------------+
# |          ...........           |
# +--------------------------------+<---- note_info_offset
# |                                |   ^
# |                                |   |
# |         PT_NOTE(data)          | total_note_size
# |                                |   |
# |                                |   v
# +--------------------------------+<---- vma_offset
# |          PT_LOAD(data)         |
# +--------------------------------+
# |          ...........           |
# +--------------------------------+
*/

struct elf_prpsinfo {
    char pr_state;
    char pr_sname;
    char pr_zomb;
    char pr_nice;
    unsigned long pr_flag;
    __kernel_uid_t pr_uid;
    __kernel_uid_t pr_gid;
    int pr_pid;
    int pr_ppid;
    int pr_pgrp;
    int pr_sid;
    char pr_fname[16];
    char pr_psargs[80];
};

struct vma {
    ulong addr;
    ulong vm_start;
    ulong vm_end;
    ulong vm_mm;
    ulong vm_flags;
    ulong vm_file;
    ulong vm_pgoff;
    ulong anon_name;
    ulong anon_vma;
    ulong file_inode;
    uint i_nlink;
    std::string name;
};

struct user_regset {
    unsigned int n;
    unsigned int size;
    unsigned int align;
    unsigned int bias;
    unsigned int core_note_type;
};

struct user_regset_view {
    std::string name;
    std::vector<std::shared_ptr<user_regset>> regsets;
    unsigned int n;
    uint32_t e_flags;
    uint16_t e_machine;
    uint8_t ei_osabi;
};

struct memelfnote{
    std::string name;
    int type;
    int datasz;
    void *data;
};

struct elf_thread_info {
    ulong task_addr;
    std::shared_ptr<memelfnote> prstatus_ptr;
    std::vector<std::shared_ptr<memelfnote>> note_list;
};

struct elf_pt_note_data {
    std::vector<std::shared_ptr<elf_thread_info>> thread_list;
    std::shared_ptr<memelfnote> psinfo;
    std::shared_ptr<memelfnote> signote;
    std::shared_ptr<memelfnote> auxv;
    std::shared_ptr<memelfnote> files;
};

struct mm_info {
    int mm_count;
    ulong start_code;
    ulong end_code;
    ulong start_data;
    ulong end_data;
    ulong start_brk;
    ulong brk;
    ulong start_stack;
    ulong arg_start;
    ulong arg_end;
    ulong env_start;
    ulong env_end;
    ulong flags;
};

struct user_pt_regs {
    unsigned long long regs[31];
    unsigned long long  sp;
    unsigned long long  pc;
    unsigned long long  pstate;
};

struct pt_regs {
    union {
        struct user_pt_regs user_regs;
        struct {
            unsigned long long regs[31];
            unsigned long long sp;
            unsigned long long pc;
            unsigned long long pstate;
        };
    };
    unsigned long long orig_x0;
    int syscallno;
    unsigned int unused2;
    unsigned long long sdei_ttbr1;
    unsigned long long pmr_save;
    unsigned long long stackframe[2];
    unsigned long long lockdep_hardirqs;
    unsigned long long exit_rcu;
};

struct user_fpsimd_state {
    __ull/*__uint128_t*/ vregs[32];
    unsigned int   fpsr;
    unsigned int   fpcr;
    unsigned int   __reserved[2];
};

class Core : public PaserPlugin {
protected:
    bool debug = false;
    bool is_compat = false;
    std::string core_path;
    int core_filter;
    int core_pid;
    FILE* corefile;
    ulong thread_info_flags;
    int elf_class;
    std::string user_view_var_name;
    std::shared_ptr<user_regset_view> urv_ptr;
    std::vector<std::shared_ptr<vma>> vma_list;
    struct task_context *tc;
    struct mm_info mm;
    struct elf_pt_note_data pt_note;
    std::shared_ptr<Swapinfo> swap_ptr;

public:
    Core(std::shared_ptr<Swapinfo> swap);
    ~Core();
    void cmd_main(void) override;

    void set_core_pid(int pid){
        core_pid = pid;
    };
    template <size_t N>
    void copy_and_fill_char(char (&dest)[N], const char* src, size_t src_len){
        size_t len = (src_len < (N - 1)) ? src_len : (N - 1);
        std::copy_n(src, len, dest);
        dest[len] = '\0';
    }
    void parser_core_dump(void);
    void write_core_file(void);
    bool parser_mm_struct(int pid);
    bool parser_user_regset_view(void);
    int task_pid_nr_ns(ulong task_addr, long type, ulong ns_addr = 0);
    int pid_nr_ns(ulong pids_addr, ulong pid_ns_addr);
    int pid_alive(ulong task_addr);
    ulong ns_of_pid(ulong thread_pid_addr);
    ulong task_pid_ptr(ulong task_addr, long type);
    int get_vma_count(ulong task_addr);
    void parser_vma_list(ulong task_addr);
    void parser_nt_file();
    void parser_thread_core_info();
    ulong vma_dump_size(std::shared_ptr<vma> vma_ptr);
    void dump_align(std::streampos position, std::streamsize align);
    virtual void parser_auvx()=0;
    virtual void write_pt_note_phdr(size_t note_size)=0;
    virtual void write_pt_load_phdr(std::shared_ptr<vma> vma_ptr, size_t& vma_offset)=0;
    virtual void writenote(std::shared_ptr<memelfnote> note_ptr)=0;
    virtual int notesize(std::shared_ptr<memelfnote> note_ptr)=0;
    virtual int get_phdr_start()=0;
    virtual int get_pt_note_data_start()=0;
    virtual void write_elf_header(int phnum)=0;
    virtual void parser_prpsinfo()=0;
    virtual void parser_siginfo()=0;
    virtual void* parser_prstatus(ulong task_addr,int* data_size)=0;
    virtual void* parser_nt_prfpreg(ulong task_addr)=0; // NT_PRFPREG
    virtual void* parser_nt_arm_tls(ulong task_addr)=0; // NT_ARM_TLS
    virtual void* parser_nt_arm_hw_break(ulong task_addr)=0; // NT_ARM_HW_BREAK
    virtual void* parser_nt_arm_hw_watch(ulong task_addr)=0; // NT_ARM_HW_WATCH
    virtual void* parser_nt_arm_system_call(ulong task_addr)=0; // NT_ARM_SYSTEM_CALL
    virtual void* parser_nt_arm_sve(ulong task_addr)=0; // NT_ARM_SVE
    virtual void* parser_nt_arm_pac_mask(ulong task_addr)=0; // NT_ARM_PAC_MASK
    virtual void* parser_nt_arm_pac_enabled_keys(ulong task_addr)=0; // NT_ARM_PAC_ENABLED_KEYS
    virtual void* parser_nt_arm_paca_keys(ulong task_addr)=0; // NT_ARM_PACA_KEYS
    virtual void* parser_nt_arm_pacg_keys(ulong task_addr)=0; // NT_ARM_PACG_KEYS
    virtual void* parser_nt_arm_tagged_addr_ctrl(ulong task_addr)=0; // NT_ARM_TAGGED_ADDR_CTRL
    virtual void* parser_nt_arm_vfp(ulong task_addr)=0; // NT_ARM_VFP
};

#endif // CORE_DEFS_H_
