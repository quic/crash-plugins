// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include "compat.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

Compat::Compat(std::shared_ptr<Swapinfo> swap) : Core(swap){
    field_init(task_struct, thread);
    field_init(thread_struct, uw);

    elf_class = ELFCLASS32;
    hdr = (elf_compat_hdr*)std::malloc(sizeof(elf_compat_hdr));
}

Compat::~Compat(){
    std::free(hdr);
}

void* Compat::parser_nt_arm_vfp(ulong task_addr) {
    size_t data_len = sizeof(struct user_fpsimd_state);
    struct user_fpsimd_state* uregs = (struct user_fpsimd_state*)std::malloc(data_len);
    BZERO(uregs, data_len);
    ulong fpsimd_state_addr = task_addr + field_offset(task_struct, thread) + field_offset(thread_struct, uw) + sizeof(unsigned long) /*tp_value*/ + sizeof(unsigned long) /*tp2_value*/;
    if(!read_struct(fpsimd_state_addr, uregs, sizeof(struct user_fpsimd_state),"parser_nt_arm_vfp uregs")){
        fprintf(fp, "compat_vfp_get failed \n");
    }

    compat_ulong_t fpscr = (uregs->fpsr & VFP_FPSCR_STAT_MASK) | (uregs->fpcr & VFP_FPSCR_CTRL_MASK);

    // task -R thread task_addr -x
    data_len = sizeof(struct compat_user_fpsimd_state); // VFP_STATE_SIZE
    struct compat_user_fpsimd_state* to = (struct compat_user_fpsimd_state*)std::malloc(data_len);
    BZERO(to, data_len);
    memcpy(to->vregs, uregs->vregs, sizeof(__ull) * 16);
    to->fpsr = fpscr;
    std::free(uregs);
    if (debug){
        fprintf(fp,  "\n\nNT_ARM_VFP: task_addr%#lx: \n", task_addr);
        fprintf(fp, "%s", hexdump(0x1000,(char*)to, data_len).c_str());
    }
    return to;
}

void* Compat::parser_nt_prfpreg(ulong task_addr) {
    return nullptr;
}

void* Compat::parser_nt_arm_tls(ulong task_addr) {
    return nullptr;
}

void* Compat::parser_nt_arm_hw_break(ulong task_addr) {
    return nullptr;
}

void* Compat::parser_nt_arm_hw_watch(ulong task_addr) {
    return nullptr;
}

void* Compat::parser_nt_arm_system_call(ulong task_addr) {
    return nullptr;
}

void* Compat::parser_nt_arm_sve(ulong task_addr) {
    return nullptr;
}

// check user_aarch32_view
void* Compat::parser_nt_arm_pac_mask(ulong task_addr) {
    return nullptr;
}

void* Compat::parser_nt_arm_pac_enabled_keys(ulong task_addr) {
    return nullptr;
}

void* Compat::parser_nt_arm_paca_keys(ulong task_addr) {
    return nullptr;
}

void* Compat::parser_nt_arm_pacg_keys(ulong task_addr) {
    return nullptr;
}

void* Compat::parser_nt_arm_tagged_addr_ctrl(ulong task_addr) {
    return nullptr;
}

void Compat::parser_auvx(){
    size_t data_size = field_size(mm_struct, saved_auxv);
    elf_compat_addr_t* auxv_buf = (elf_compat_addr_t*)read_memory(tc->mm_struct + field_offset(mm_struct, saved_auxv), data_size, "mm_struct saved_auxv");
    if(!auxv_buf){
        fprintf(fp, "fill_auvx_note auxv_buf is NULL \n");
    }
    int i = 0;
    do {
        i += 2;
    }
    while (auxv_buf[i - 2] != AT_NULL);
    data_size = i * sizeof(elf_compat_addr_t);
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

void Compat::write_pt_note_phdr(size_t note_size) {
    size_t data_size = sizeof(elf_compat_phdr);
    elf_compat_phdr* phdr = (elf_compat_phdr*)std::malloc(data_size);
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

void Compat::write_pt_load_phdr(std::shared_ptr<vma> vma_ptr, size_t& vma_offset) {
    size_t data_size = sizeof(elf_compat_phdr);
    elf_compat_phdr* phdr = (elf_compat_phdr*)std::malloc(data_size);
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

int Compat::notesize(std::shared_ptr<memelfnote> note_ptr){
    int total_size = sizeof(elf_compat_note);
    total_size += roundup(note_ptr->name.size() + 1,4);
    total_size += roundup(note_ptr->datasz,4);
    return total_size;
}

void Compat::writenote(std::shared_ptr<memelfnote> note_ptr) {
    elf_compat_note note;
    note.n_namesz = note_ptr->name.size() + 1;
    note.n_descsz = note_ptr->datasz;
    note.n_type = note_ptr->type;
    fwrite(&note, sizeof(elf_compat_note), 1, corefile);
    fwrite(note_ptr->name.c_str(), note.n_namesz, 1, corefile);
    dump_align(ftell(corefile),4);
    fwrite((char*)note_ptr->data, note_ptr->datasz, 1, corefile);
    std::free(note_ptr->data);
    dump_align(ftell(corefile),4);
}

void Compat::write_elf_header(int phnum) {
    size_t data_size = sizeof(elf_compat_hdr);
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
    hdr->e_phentsize = sizeof(elf_compat_phdr);
    hdr->e_phnum = phnum;
    if (debug){
        fprintf(fp, "\n\nelf_compat_hdr:\n");
        fprintf(fp, "%s", hexdump(0x1000,(char*)hdr,data_size).c_str());
    }
    fwrite(hdr, data_size, 1, corefile);
}

void* Compat::parser_prstatus(ulong task_addr,int* data_size) {
    size_t data_len = sizeof(struct compat_elf_prstatus);
    struct compat_elf_prstatus* prstatus = (struct compat_elf_prstatus*)std::malloc(data_len);
    BZERO(prstatus, data_len);
    prstatus->common.pr_info.si_signo = prstatus->common.pr_cursig = 6;
    ulong real_parent_addr = read_pointer(task_addr + field_offset(task_struct, real_parent), "real_parent");
    prstatus->common.pr_ppid = read_int(real_parent_addr + field_offset(task_struct, pid), "real_parent pid");
    prstatus->common.pr_pid = task_pid_nr_ns(task_addr, read_enum_val("PIDTYPE_PID"));
    prstatus->common.pr_pgrp = task_pid_nr_ns(task_addr, read_enum_val("PIDTYPE_PGID"));
    prstatus->common.pr_sid = task_pid_nr_ns(task_addr, read_enum_val("PIDTYPE_SID"));
    prstatus->pr_fpvalid = 1;
    // #define task_pt_regs(p) ((struct pt_regs *)(UL(1) << THREAD_SHIFT + task->stack) - 1)
    // task.stack -> task.stack + 16K = (stack_top) -> stack_top - sizeof(struct pt_regs)
    ulong pt_regs_addr = GET_STACKTOP(task_addr) - machdep->machspec->user_eframe_offset;
    struct pt_regs pt_regs_t;
    BZERO(&pt_regs_t, sizeof(struct pt_regs));
    if(!read_struct(pt_regs_addr, &pt_regs_t, sizeof(struct pt_regs), "compat_get_user_reg")){
        fprintf(fp, "get compat_get_user_reg failed \n");
    }
    // compat_get_user_reg() in ptrace.c  uint <-> ulong
    for(int i = 0; i < 18; i++){
        if(i == 15){
            prstatus->pr_reg.regs[i] = pt_regs_t.pc;
        } else if(i == 16){
            prstatus->pr_reg.regs[i] = (pt_regs_t.pstate & ~PSR_AA32_DIT_BIT) | ((pt_regs_t.pstate & PSR_AA32_DIT_BIT) ? COMPAT_PSR_DIT_BIT : 0);
        } else if(i == 17){
            prstatus->pr_reg.regs[i] = pt_regs_t.orig_x0; // orig_x0
        } else {
            prstatus->pr_reg.regs[i] = pt_regs_t.regs[i];
        }
    }
    *data_size = data_len;
    if(debug){
        fprintf(fp, "pid: %d, task_addr:%#lx, pt_regs_addr:%#lx, struct_size:%#zx stack_top:%#lx user_eframe_offset:%#lx \n",prstatus->common.pr_pid, task_addr, pt_regs_addr, sizeof(struct pt_regs), GET_STACKTOP(task_addr), machdep->machspec->user_eframe_offset);
        fprintf(fp,  "\n\nNT_PRSTATUS:\n");
        fprintf(fp, "%s", hexdump(0x1000,(char*)prstatus, data_len).c_str());
    }
    return prstatus;
}

void Compat::parser_prpsinfo() {
    size_t data_size = sizeof(struct compat_elf_prpsinfo);
    struct compat_elf_prpsinfo* prpsinfo = (struct compat_elf_prpsinfo*)std::malloc(data_size);
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
    prpsinfo->pr_flag = read_uint(tc->task + field_offset(task_struct, flags), "task_struct flags");
    ulong cred_addr = read_pointer(tc->task + field_offset(task_struct, cred), "task_struct cred");
    prpsinfo->pr_uid = read_ushort(cred_addr + field_offset(cred, uid), "cred uid");
    prpsinfo->pr_gid = read_ushort(cred_addr + field_offset(cred, gid), "cred gid");
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

void Compat::parser_siginfo() {
    size_t data_size = sizeof(struct compat_elf_siginfo);
    struct compat_elf_siginfo* sinfo = (struct compat_elf_siginfo*)std::malloc(data_size);
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

int Compat::get_phdr_start() {
    return hdr->e_phoff;
}

int Compat::get_pt_note_data_start() {
    return hdr->e_ehsize + (hdr->e_phnum * hdr->e_phentsize);
}
#pragma GCC diagnostic pop
