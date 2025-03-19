// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include "arm.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

Arm::Arm(std::shared_ptr<Swapinfo> swap) : Core(swap){
    elf_class = ELFCLASS32;
    field_init(task_struct,thread_info);
    field_init(thread_info,vfpstate);
    field_init(thread_info,fpstate);
    field_init(vfp_state,hard);
    field_init(vfp_hard_struct,fpregs);
    field_init(vfp_hard_struct,fpscr);
    hdr = (elf_hdr*)std::malloc(sizeof(elf_hdr));
}

Arm::~Arm(){
    std::free(hdr);
}

void* Arm::parser_nt_arm_vfp(ulong task_addr) {
    size_t data_len = sizeof(struct user_vfp);
    struct user_vfp* vfp = (struct user_vfp*)std::malloc(data_len);
    BZERO(vfp, data_len);
    ulong fpregs_addr = task_addr + field_offset(task_struct, thread_info)
            + field_offset(thread_info, vfpstate)
            + field_offset(vfp_state, hard)
            + field_offset(vfp_hard_struct, fpregs);
    if(!read_struct(fpregs_addr, &vfp->fpregs, field_size(vfp_hard_struct, fpregs),"parser_nt_arm_vfp fpregs")){
        fprintf(fp, "get fpregs failed \n");
    }
    ulong fpscr_addr = task_addr + field_offset(task_struct, thread_info)
            + field_offset(thread_info, vfpstate)
            + field_offset(vfp_state, hard)
            + field_offset(vfp_hard_struct, fpscr);
    vfp->fpscr = read_ulong(fpscr_addr,"parser_nt_arm_vfp fpscr");
    if (debug){
        fprintf(fp, "\n\nNT_ARM_VFP:\n");
        fprintf(fp, "%s", hexdump(0x1000,(char*)vfp, data_len).c_str());
    }
    return vfp;
}

void* Arm::parser_nt_prfpreg(ulong task_addr) {
    size_t data_len = sizeof(struct user_fp);
    struct user_fp* ufp = (struct user_fp*)std::malloc(data_len);
    BZERO(ufp, data_len);
    ulong fpstate_addr = task_addr + field_offset(task_struct, thread_info) + field_offset(thread_info, fpstate);
    if(!read_struct(fpstate_addr, ufp, sizeof(*ufp),"parser_nt_prfpreg fpstate")){
        fprintf(fp, "get fpstate failed \n");
    }
    if (debug){
        fprintf(fp,  "\n\nNT_PRFPREG:\n");
        fprintf(fp, "%s", hexdump(0x1000,(char*)fp, data_len).c_str());
    }
    return ufp;
}

void* Arm::parser_nt_arm_tls(ulong task_addr) {
    return nullptr;
}

void* Arm::parser_nt_arm_hw_break(ulong task_addr) {
    return nullptr;
}

void* Arm::parser_nt_arm_hw_watch(ulong task_addr) {
    return nullptr;
}

void* Arm::parser_nt_arm_system_call(ulong task_addr) {
    return nullptr;
}

void* Arm::parser_nt_arm_sve(ulong task_addr) {
    return nullptr;
}

void* Arm::parser_nt_arm_pac_mask(ulong task_addr) {
    return nullptr;
}

void* Arm::parser_nt_arm_pac_enabled_keys(ulong task_addr) {
    return nullptr;
}

void* Arm::parser_nt_arm_paca_keys(ulong task_addr) {
    return nullptr;
}

void* Arm::parser_nt_arm_pacg_keys(ulong task_addr) {
    return nullptr;
}

void* Arm::parser_nt_arm_tagged_addr_ctrl(ulong task_addr) {
    return nullptr;
}

void Arm::parser_auvx(){
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

void Arm::write_pt_note_phdr(size_t note_size) {
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

void Arm::write_pt_load_phdr(std::shared_ptr<vma> vma_ptr, size_t& vma_offset) {
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

int Arm::notesize(std::shared_ptr<memelfnote> note_ptr){
    int total_size = sizeof(elf_note);
    total_size += roundup(note_ptr->name.size() + 1,4);
    total_size += roundup(note_ptr->datasz,4);
    return total_size;
}

void Arm::writenote(std::shared_ptr<memelfnote> note_ptr) {
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

void Arm::write_elf_header(int phnum) {
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

void* Arm::parser_prstatus(ulong task_addr,int* data_size) {
    size_t data_len = sizeof(struct elf32_prstatus);
    struct elf32_prstatus* prstatus = (struct elf32_prstatus*)std::malloc(data_len);
    BZERO(prstatus, data_len);
    prstatus->pr_info.si_signo = prstatus->pr_cursig = 6;
    ulong real_parent_addr = read_pointer(task_addr + field_offset(task_struct, real_parent), "real_parent");
    prstatus->pr_ppid = read_int(real_parent_addr + field_offset(task_struct, pid), "real_parent pid");
    prstatus->pr_pid = task_pid_nr_ns(task_addr, read_enum_val("PIDTYPE_PID"));
    prstatus->pr_pgrp = task_pid_nr_ns(task_addr, read_enum_val("PIDTYPE_PGID"));
    prstatus->pr_sid = task_pid_nr_ns(task_addr, read_enum_val("PIDTYPE_SID"));
    prstatus->pr_fpvalid = 1;
    // #define task_pt_regs(p) ((struct pt_regs *)(THREAD_SIZE - 8 + task->stack) - 1)
    ulong pt_regs_addr = GET_STACKTOP(task_addr) - 8 - sizeof(struct arm32_pt_regs);
    if(!read_struct(pt_regs_addr, &prstatus->pr_reg, sizeof(struct arm32_pt_regs),"gpr64_get user_pt_regs")){
        fprintf(fp, "get pt_regs failed \n");
    }
    *data_size = data_len;
    if (debug){
        fprintf(fp, "pid: %d, task_addr:%#lx, pt_regs_addr:%#lx, struct_size:%#zx stack_top:%#lx \n", prstatus->pr_pid, task_addr, pt_regs_addr, sizeof(struct arm32_pt_regs), GET_STACKTOP(task_addr));
        fprintf(fp,  "\n\nNT_PRSTATUS:\n");
        fprintf(fp, "%s", hexdump(0x1000, (char*)prstatus, data_len).c_str());
    }
    return prstatus;
}

void Arm::parser_prpsinfo() {
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
        fprintf(fp, "%s", hexdump(0x1000, (char*)prpsinfo, data_size).c_str());
    }
    pt_note.psinfo = std::make_shared<memelfnote>();
    pt_note.psinfo->name = "CORE";
    pt_note.psinfo->type = NT_PRPSINFO;
    pt_note.psinfo->data = prpsinfo;
    pt_note.psinfo->datasz = data_size;
}

void Arm::parser_siginfo() {
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

int Arm::get_phdr_start() {
    return hdr->e_phoff;
}

int Arm::get_pt_note_data_start() {
    return hdr->e_ehsize + (hdr->e_phnum * hdr->e_phentsize);
}

#pragma GCC diagnostic pop
