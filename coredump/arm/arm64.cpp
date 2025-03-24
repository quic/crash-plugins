/**
 * Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include "arm64.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

Arm64::Arm64(std::shared_ptr<Swapinfo> swap) : Core(swap){
    elf_class = ELFCLASS64;
    field_init(task_struct, thread);
    field_init(thread_struct, sctlr_user);
    field_init(thread_struct, mte_ctrl);
    field_init(thread_struct, uw);
    hdr = (elf_hdr*)std::malloc(sizeof(elf_hdr));
}

Arm64::~Arm64(){
    std::free(hdr);
}

void* Arm64::parser_nt_arm_vfp(ulong task_addr) {
    return nullptr;
}

void* Arm64::parser_nt_prfpreg(ulong task_addr) {
    size_t data_len = sizeof(struct user_fpsimd_state);
    struct user_fpsimd_state* uregs = (struct user_fpsimd_state*)std::malloc(data_len);
    BZERO(uregs, data_len);
    ulong fpsimd_state_addr = task_addr + field_offset(task_struct, thread) + field_offset(thread_struct, uw) + sizeof(unsigned long) /*tp_value*/ + sizeof(unsigned long) /*tp2_value*/;
    if(!read_struct(fpsimd_state_addr, uregs, sizeof(struct user_fpsimd_state),"parser_nt_prfpreg uregs")){
        fprintf(fp, "fpr_get failed \n");
    }
    if (debug){
        fprintf(fp,  "\n\nNT_PRFPREG: task_addr:%#lx \n", task_addr);
        fprintf(fp, "%s", hexdump(0x1000,(char*)uregs, data_len).c_str());
    }
    return uregs;
}

void* Arm64::parser_nt_arm_tls(ulong task_addr) {
    return nullptr;
}

void* Arm64::parser_nt_arm_hw_break(ulong task_addr) {
    return nullptr;
}

void* Arm64::parser_nt_arm_hw_watch(ulong task_addr) {
    return nullptr;
}

void* Arm64::parser_nt_arm_system_call(ulong task_addr) {
    return nullptr;
}

void* Arm64::parser_nt_arm_sve(ulong task_addr) {
    return nullptr;
}

void* Arm64::parser_nt_arm_pac_mask(ulong task_addr) {
    size_t data_len = sizeof(struct user_pac_mask);
    struct user_pac_mask* uregs = (struct user_pac_mask*)std::malloc(data_len);
    BZERO(uregs, data_len);
    // #define ptrauth_user_pac_mask()        GENMASK_ULL(54, vabits_actual)
    ulong vabits_actual = machdep->machspec->VA_BITS_ACTUAL;
    uint64_t mask = GENMASK_ULL(54, vabits_actual); // default
    uregs->data_mask = mask;
    uregs->insn_mask = mask;
    if (debug){
        fprintf(fp,  "\n\nNT_ARM_PAC_MASK:\n");
        fprintf(fp, "%s", hexdump(0x1000, (char*)uregs, data_len).c_str());
    }
    return uregs;
}

void* Arm64::parser_nt_arm_pac_enabled_keys(ulong task_addr) {
    size_t data_len = sizeof(uint64_t);
    uint64_t sctlr_user = read_ulonglong(task_addr + field_offset(task_struct, thread) + field_offset(thread_struct, sctlr_user), "task_struct thread_struct sctlr_user");
    uint64_t* retval = (uint64_t*)std::malloc(data_len);
    *retval = 0;
    if (sctlr_user & SCTLR_ELx_ENIA)
        *retval |= PR_PAC_APIAKEY;
    if (sctlr_user & SCTLR_ELx_ENIB)
        *retval |= PR_PAC_APIBKEY;
    if (sctlr_user & SCTLR_ELx_ENDA)
        *retval |= PR_PAC_APDAKEY;
    if (sctlr_user & SCTLR_ELx_ENDB)
        *retval |= PR_PAC_APDBKEY;
    if (debug){
        fprintf(fp,  "\n\nNT_ARM_PAC_ENABLED_KEYS:\n");
        fprintf(fp, "%s", hexdump(0x1000, (char*)retval, data_len).c_str());
    }
    return retval;
}

void* Arm64::parser_nt_arm_paca_keys(ulong task_addr) {
    return nullptr;
}

void* Arm64::parser_nt_arm_pacg_keys(ulong task_addr) {
    return nullptr;
}

void* Arm64::parser_nt_arm_tagged_addr_ctrl(ulong task_addr) {
    uint64_t ret = 0;
    // ulong thread_info_flags = read_ulong(task_addr + field_offset(task_struct, thread_info) + field_offset(thread_info, flags), "arm64 task_struct thread_info flags");

    if (thread_info_flags & (1 << TIF_TAGGED_ADDR)){
        ret = PR_TAGGED_ADDR_ENABLE;
    }
    if (field_offset(thread_struct, mte_ctrl) != -1) {
        uint64_t mte_ctrl = read_ulonglong(task_addr + field_offset(task_struct, thread) + field_offset(thread_struct, mte_ctrl), "task_struct thread_struct mte_ctrl");
        uint64_t incl = (~mte_ctrl >> MTE_CTRL_GCR_USER_EXCL_SHIFT) & SYS_GCR_EL1_EXCL_MASK;
        ret |= incl << PR_MTE_TAG_SHIFT;
        if (mte_ctrl & MTE_CTRL_TCF_ASYNC)
            ret |= PR_MTE_TCF_ASYNC;
        if (mte_ctrl & MTE_CTRL_TCF_SYNC)
            ret |= PR_MTE_TCF_SYNC;
    }
    size_t data_len = sizeof(uint64_t);
    uint64_t* retval = (uint64_t*)std::malloc(data_len);
    *retval = ret;
    if (debug){
        fprintf(fp,  "\n\nNT_ARM_TAGGED_ADDR_CTRL:\n");
        fprintf(fp, "%s", hexdump(0x1000, (char*)retval, data_len).c_str());
    }
    return retval;
}

void Arm64::parser_auvx(){
    size_t data_size = field_size(mm_struct, saved_auxv);
    elf_addr_t* auxv_buf = (elf_addr_t*)read_memory(tc->mm_struct + field_offset(mm_struct, saved_auxv), data_size, "mm_struct saved_auxv");
    if(!auxv_buf){
        fprintf(fp, "fill_auvx_note auxv_buf is NULL \n");
    }
    int i = 0;
    do {
        i += 2;
    }
    while (auxv_buf[i - 2] != AT_NULL);
    data_size = i * sizeof(elf_addr_t);
    void* data = std::malloc(data_size);
    memcpy(data, auxv_buf, data_size);
    FREEBUF(auxv_buf);
    if (debug){
        fprintf(fp,  "\n\nNT_AUXV:\n");
        fprintf(fp, "%s", hexdump(0x1000, (char*)data, data_size).c_str());
    }
    pt_note.auxv = std::make_shared<memelfnote>();
    pt_note.auxv->name = "CORE";
    pt_note.auxv->type = NT_AUXV;
    pt_note.auxv->data = data;
    pt_note.auxv->datasz = data_size;
}

void Arm64::write_pt_note_phdr(size_t note_size) {
    size_t data_size = sizeof(elf_phdr);
    elf_phdr* phdr = (elf_phdr*)std::malloc(data_size);
    BZERO(phdr, data_size);
    phdr->p_type = PT_NOTE;
    phdr->p_offset = get_pt_note_data_start();
    phdr->p_vaddr = 0;
    phdr->p_paddr = 0;
    phdr->p_filesz = note_size;
    phdr->p_memsz = 0;
    phdr->p_flags = 0;
    phdr->p_align = 0;
    fwrite(phdr, data_size, 1, corefile);
    std::free(phdr);
}

void Arm64::write_pt_load_phdr(std::shared_ptr<vma> vma_ptr, size_t& vma_offset) {
    size_t data_size = sizeof(elf_phdr);
    elf_phdr* phdr = (elf_phdr*)std::malloc(data_size);
    BZERO(phdr, data_size);
    phdr->p_type = PT_LOAD;
    phdr->p_offset = vma_offset;
    phdr->p_vaddr = vma_ptr->vm_start;
    phdr->p_paddr = 0;
    phdr->p_memsz = vma_ptr->vm_end - vma_ptr->vm_start;
    phdr->p_filesz = vma_dump_size(vma_ptr);

    if (vma_ptr->vm_flags & VM_READ){
        phdr->p_flags |= PF_R;
    }
    if (vma_ptr->vm_flags & VM_WRITE){
        phdr->p_flags |= PF_W;
    }
    if (vma_ptr->vm_flags & VM_EXEC){
        phdr->p_flags |= PF_X;
    }
    phdr->p_align = page_size;
    fwrite(phdr, data_size, 1, corefile);
    vma_offset += phdr->p_filesz;
    std::free(phdr);
}

int Arm64::notesize(std::shared_ptr<memelfnote> note_ptr){
    int total_size = sizeof(elf_note);
    total_size += roundup(note_ptr->name.size() + 1,4);
    total_size += roundup(note_ptr->datasz,4);
    return total_size;
}

void Arm64::writenote(std::shared_ptr<memelfnote> note_ptr) {
    elf_note note;
    note.n_namesz = note_ptr->name.size() + 1;
    note.n_descsz = note_ptr->datasz;
    note.n_type = note_ptr->type;
    fwrite(&note, sizeof(elf_note), 1, corefile);
    fwrite(note_ptr->name.c_str(), note.n_namesz, 1, corefile);
    dump_align(ftell(corefile),4);
    fwrite((char*)note_ptr->data, note_ptr->datasz, 1, corefile);
    std::free(note_ptr->data);
    dump_align(ftell(corefile),4);
}

void Arm64::write_elf_header(int phnum) {
    size_t data_size = sizeof(elf_hdr);
    BZERO(hdr, data_size);
    snprintf((char *)hdr->e_ident, 5, ELFMAG);
    hdr->e_ident[EI_CLASS] = elf_class;
    hdr->e_ident[EI_DATA] = ELFDATA2LSB;
    hdr->e_ident[EI_VERSION] = EV_CURRENT;
    hdr->e_ident[EI_OSABI] = urv_ptr->ei_osabi;
    hdr->e_type = ET_CORE;
    hdr->e_machine = urv_ptr->e_machine;
    hdr->e_version = EV_CURRENT;
    hdr->e_phoff = data_size;
    hdr->e_flags = urv_ptr->e_flags;
    hdr->e_ehsize = data_size;
    hdr->e_phentsize = sizeof(elf_phdr);
    hdr->e_phnum = phnum;
    if (debug){
        fprintf(fp, "\n\nelf_hdr:\n");
        fprintf(fp, "%s", hexdump(0x1000,(char*)hdr,data_size).c_str());
    }
    fwrite(hdr, data_size, 1, corefile);
}

void* Arm64::parser_prstatus(ulong task_addr,int* data_size) {
    size_t data_len = sizeof(struct elf64_prstatus);
    struct elf64_prstatus* prstatus = (struct elf64_prstatus*)std::malloc(data_len);
    BZERO(prstatus, data_len);
    prstatus->pr_info.si_signo = prstatus->pr_cursig = 6;
    ulong real_parent_addr = read_pointer(task_addr + field_offset(task_struct, real_parent), "real_parent");
    prstatus->pr_ppid = read_int(real_parent_addr + field_offset(task_struct, pid), "real_parent pid");
    prstatus->pr_pid = task_pid_nr_ns(task_addr, read_enum_val("PIDTYPE_PID"));
    prstatus->pr_pgrp = task_pid_nr_ns(task_addr, read_enum_val("PIDTYPE_PGID"));
    prstatus->pr_sid = task_pid_nr_ns(task_addr, read_enum_val("PIDTYPE_SID"));
    prstatus->pr_fpvalid = 1;
    // #define task_pt_regs(p) ((struct pt_regs *)(UL(1) << THREAD_SHIFT + task->stack) - 1)
    // task.stack -> task.stack + 16K = (stack_top) -> stack_top - sizeof(struct pt_regs)
    ulong pt_regs_addr = GET_STACKTOP(task_addr) - machdep->machspec->user_eframe_offset;
    if(!read_struct(pt_regs_addr, &prstatus->pr_reg, sizeof(struct user_pt_regs),"gpr64_get user_pt_regs")){
        fprintf(fp, "get user_pt_regs failed \n");
    }
    *data_size = data_len;
    if (debug){
        fprintf(fp, "pid: %d, task_addr:%#lx, pt_regs_addr:%#lx, struct_size:%#zx stack_top:%#lx user_eframe_offset:%#lx \n", prstatus->pr_pid, task_addr, pt_regs_addr, sizeof(struct pt_regs), GET_STACKTOP(task_addr), machdep->machspec->user_eframe_offset);
        fprintf(fp,  "\n\nNT_PRSTATUS:\n");
        fprintf(fp, "%s", hexdump(0x1000,(char*)prstatus,data_len).c_str());
    }
    return prstatus;
}

void Arm64::parser_prpsinfo() {
    size_t data_size = sizeof(struct elf_prpsinfo);
    struct elf_prpsinfo* prpsinfo = (struct elf_prpsinfo*)std::malloc(data_size);
    BZERO(prpsinfo, data_size);
    ulong state = 0;
    if (field_offset(task_struct, state) != -1){
        state = read_ulong(tc->task + field_offset(task_struct, state), "task_struct state");
    } else {
        state = read_int(tc->task + field_offset(task_struct, __state), "task_struct __state");
    }
    std::string args = swap_ptr->read_start_args(tc->task);
    copy_and_fill_char(prpsinfo->pr_psargs, args.c_str(), args.size());
    ulong real_parent_addr = read_pointer(tc->task + field_offset(task_struct, real_parent), "task_struct real_parent");
    prpsinfo->pr_ppid = read_int(real_parent_addr + field_offset(task_struct, pid), "task_struct real_parent pid");
    prpsinfo->pr_pid = task_pid_nr_ns(tc->task, read_enum_val("PIDTYPE_PID"));
    prpsinfo->pr_pgrp = task_pid_nr_ns(tc->task, read_enum_val("PIDTYPE_PGID"));
    prpsinfo->pr_sid = task_pid_nr_ns(tc->task, read_enum_val("PIDTYPE_SID"));
    uint i = state ? ffs(state) + 1 : 0;
    prpsinfo->pr_state = i;
    prpsinfo->pr_sname = (i > 5) ? '.' : "RSDTZW"[i];
    prpsinfo->pr_zomb = prpsinfo->pr_sname == 'Z';
    int static_prio = read_int(tc->task + field_offset(task_struct, static_prio), "task_struct static_prio");
    prpsinfo->pr_nice = static_prio - 120;
    prpsinfo->pr_flag = read_ulong(tc->task + field_offset(task_struct, flags), "task_struct flags");
    ulong cred_addr = read_pointer(tc->task + field_offset(task_struct, cred), "task_struct cred");
    prpsinfo->pr_uid = read_uint(cred_addr + field_offset(cred, uid), "cred uid");
    prpsinfo->pr_gid = read_uint(cred_addr + field_offset(cred, gid), "cred gid");
    copy_and_fill_char(prpsinfo->pr_fname, tc->comm, strlen(tc->comm));
    if (debug){
        fprintf(fp,  "\n\nNT_PRPSINFO:\n");
        fprintf(fp, "%s", hexdump(0x1000,(char*)prpsinfo,data_size).c_str());
    }
    pt_note.psinfo = std::make_shared<memelfnote>();
    pt_note.psinfo->name = "CORE";
    pt_note.psinfo->type = NT_PRPSINFO;
    pt_note.psinfo->data = prpsinfo;
    pt_note.psinfo->datasz = data_size;
}

void Arm64::parser_siginfo() {
    size_t data_size = sizeof(struct elf_siginfo);
    struct elf_siginfo* sinfo = (struct elf_siginfo*)std::malloc(data_size);
    BZERO(sinfo, data_size);
    sinfo->si_signo = 6;
    if (debug){
        fprintf(fp,  "\n\nNT_SIGINFO:\n");
        fprintf(fp, "%s", hexdump(0x1000,(char*)sinfo,data_size).c_str());
    }
    pt_note.signote = std::make_shared<memelfnote>();
    pt_note.signote->name = "CORE";
    pt_note.signote->type = NT_SIGINFO;
    pt_note.signote->data = sinfo;
    pt_note.signote->datasz = data_size;
}

int Arm64::get_phdr_start() {
    return hdr->e_phoff;
}

int Arm64::get_pt_note_data_start() {
    return hdr->e_ehsize + (hdr->e_phnum * hdr->e_phentsize);
}
#pragma GCC diagnostic pop
