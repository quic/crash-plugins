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

#include "core.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

void Core::cmd_main(void) {}

Core::Core(std::shared_ptr<Swapinfo> swap) : swap_ptr(swap){
    field_init(thread_info, flags);
    field_init(user_regset_view,name);
    field_init(user_regset_view,regsets);
    field_init(user_regset_view,n);
    field_init(user_regset_view,e_flags);
    field_init(user_regset_view,e_machine);
    field_init(user_regset_view,ei_osabi);
    struct_init(user_regset_view);
    field_init(user_regset,n);
    struct_init(user_regset);

    field_init(task_struct, state);
    field_init(task_struct, __state);
    field_init(task_struct, real_parent);
    field_init(task_struct, pid);
    field_init(task_struct, static_prio);
    field_init(task_struct, flags);
    field_init(task_struct, cred);
    field_init(task_struct, thread_pid);
    field_init(task_struct, signal);
    field_init(task_struct, thread_node);
    field_init(task_struct, thread_info);
    field_init(mm_struct, saved_auxv);
    field_init(mm_struct, mm_count);
    field_init(mm_struct, start_code);
    field_init(mm_struct, end_code);
    field_init(mm_struct, start_data);
    field_init(mm_struct, end_data);
    field_init(mm_struct, start_brk);
    field_init(mm_struct, brk);
    field_init(mm_struct, start_stack);
    field_init(mm_struct, env_start);
    field_init(mm_struct, env_end);
    field_init(mm_struct, flags);
    field_init(cred, uid);
    field_init(cred, gid);
    field_init(vm_area_struct, vm_mm);
    field_init(vm_area_struct, vm_start);
    field_init(vm_area_struct, vm_end);
    field_init(vm_area_struct, vm_pgoff);
    field_init(vm_area_struct, anon_name);
    field_init(vm_area_struct, anon_vma);
    field_init(vm_area_struct, vm_flags);
    field_init(vm_area_struct, vm_file);
    field_init(vm_area_struct, detached);
    field_init(file, f_vfsmnt);
    field_init(file, f_dentry);
    field_init(signal_struct, pids);
    field_init(signal_struct, thread_head);
    field_init(pid, level);
    field_init(pid, numbers);
    struct_init(upid);
    field_init(upid, ns);
    field_init(upid, nr);
    field_init(pid_namespace, level);
    field_init(anon_vma_name, name);
    field_init(inode, i_flags);
    field_init(address_space, host);
    field_init(file, f_mapping);
    field_init(file, f_inode);
    field_init(inode, i_nlink);

    if (BITS64()){
        if (field_offset(thread_info, flags) != -1){
            thread_info_flags = ULONG(tt->thread_info + field_offset(thread_info, flags)); // fill_thread_info should be called at first
            if(thread_info_flags & (1 << 22)){
                is_compat = true;
            }
        }
        user_view_var_name = is_compat ? "user_aarch32_view" : "user_aarch64_view";
    }else{
        user_view_var_name = "user_arm_view";
    }
    parser_user_regset_view();
}

Core::~Core(){
    swap_ptr.reset();
}

void Core::parser_core_dump(void) {
    tc = pid_to_context(core_pid);
    if (core_path.empty()){
        char buffer[PATH_MAX];
        if (getcwd(buffer, sizeof(buffer)) != nullptr) {
            core_path = buffer;
        }
    }
    char filename[32];
    snprintf(filename, sizeof(filename), "core.%ld.%s", tc->pid, tc->comm);
    core_path += "/" + std::string(filename);
    if(debug){
        fprintf(fp, "core_path:%s\n", core_path.c_str());
    }
    corefile = fopen(core_path.c_str(), "wb");
    if (!corefile) {
        fprintf(fp, "Can't open %s\n", core_path.c_str());
        return;
    }
    parser_mm_struct(core_pid);
    parser_vma_list(tc->task);
    parser_prpsinfo();
    parser_siginfo();
    parser_nt_file();
    parser_auvx();
    parser_thread_core_info();
    write_core_file();
}

void Core::write_core_file(void) {
    size_t total_note_size = 0;
    total_note_size += notesize(pt_note.auxv);
    total_note_size += notesize(pt_note.psinfo);
    total_note_size += notesize(pt_note.signote);
    total_note_size += notesize(pt_note.files);
    for(auto& thread_ptr: pt_note.thread_list){
        for(auto& note_ptr: thread_ptr->note_list){
            if (note_ptr->data) {
                total_note_size += notesize(note_ptr);
            }
        }
    }
    // ===========================================
    //  Writing ELF header information
    // ===========================================
    int offset = 0;
    if (fseek(corefile, 0, SEEK_SET) != 0) {
        fclose(corefile);
        return;
    }
    int segs = vma_list.size() + 1; // for PT_NOTE
    int e_phnum = segs > PN_XNUM ? PN_XNUM : segs;
    write_elf_header(e_phnum);
    //  ===========================================
    //  Writing program header information
    //  ===========================================
    offset = get_phdr_start();
    if (fseek(corefile, offset, SEEK_SET) != 0) {
        fclose(corefile);
        return;
    }
    write_pt_note_phdr(total_note_size);
    size_t vma_offset = get_pt_note_data_start() + total_note_size;
    vma_offset = roundup(vma_offset, page_size);
    for (auto& vma : vma_list) {
        write_pt_load_phdr(vma, vma_offset);
    }
    if(debug){
        fprintf(fp, "segs:%d vma_size:%zd \n", segs, vma_list.size());
        fprintf(fp, "pt_note start: %d\n",get_pt_note_data_start());
        fprintf(fp, "total_note_size: %zu\n",total_note_size);
        fprintf(fp, "vma_offset: %zu\n",vma_offset);
    }
    //  ===========================================
    //  Writing PT NOTE data
    //  ===========================================
    offset = get_pt_note_data_start();
    if (fseek(corefile, offset, SEEK_SET) != 0) {
        fclose(corefile);
        return;
    }
    for (size_t i = 0; i < pt_note.thread_list.size(); i++){
        const auto& thread_ptr = pt_note.thread_list[i];
        writenote(thread_ptr->prstatus_ptr);
        if (i == 0){
            writenote(pt_note.psinfo);
            writenote(pt_note.signote);
            writenote(pt_note.auxv);
            writenote(pt_note.files);
        }
        for(const auto& note_ptr: thread_ptr->note_list){
            if (note_ptr != thread_ptr->prstatus_ptr && note_ptr->data){
                writenote(note_ptr);
            }
        }
    }
    pt_note.auxv.reset();
    pt_note.psinfo.reset();
    pt_note.signote.reset();
    pt_note.files.reset();
    pt_note.thread_list.clear();
    //  ===========================================
    //  Writing PT LOAD data
    //  ===========================================
    vma_offset = get_pt_note_data_start() + total_note_size;
    offset = roundup(vma_offset, page_size);
    if(debug){
        fprintf(fp, "align to page vma_offset: %zx , offset: %x \n",vma_offset, offset);
    }
    if (fseek(corefile, offset, SEEK_SET) != 0) {
        fclose(corefile);
        return;
    }
    char page_data[page_size];
    for (const auto& vma : vma_list) {
        for(ulong addr = vma->vm_start; addr < vma->vm_start + vma_dump_size(vma); addr += page_size){
            char* buf_page = swap_ptr->do_swap_page(tc->task,addr);
            if(buf_page == nullptr){
                BZERO(page_data, page_size);
                buf_page = page_data;
            }
            fwrite(buf_page, sizeof(char), page_size, corefile);
        }
    }
    fclose(corefile);
    core_path.clear();
    return;
}

ulong Core::vma_dump_size(std::shared_ptr<vma> vma_ptr) {
    auto filter = [&](int type) -> bool {
        return mm.flags & (1UL << type);
    };

    uint S_DAX = (get_config_val("CONFIG_HUGETLB_PAGE") == "y") ? (1 << 13) : 0;

    auto is_dax = [S_DAX](uint i_flags) -> bool {
        return i_flags & S_DAX;
    };

    ulong whole = vma_ptr->vm_end - vma_ptr->vm_start;

    if (csymbol_exists("gate_vma") && csymbol_value("gate_vma") == vma_ptr->addr) {
        return whole;
    }

    if (vma_ptr->vm_flags & VM_DONTDUMP) {
        return 0;
    }

    if (vma_ptr->file_inode != 0) {
        uint i_flags = read_uint(vma_ptr->file_inode + field_offset(inode, i_flags), "inode i_flags");

        if (is_dax(i_flags)) {
            if ((vma_ptr->vm_flags & VM_SHARED) && filter(MMF_DUMP_DAX_SHARED)) {
                return whole;
            }
            if (!(vma_ptr->vm_flags & VM_SHARED) && filter(MMF_DUMP_DAX_PRIVATE)) {
                return whole;
            }
            return 0;
        }
    }

    if (get_config_val("CONFIG_HUGETLB_PAGE") == "y" && !!(vma_ptr->vm_flags & VM_HUGETLB)) {
        if ((vma_ptr->vm_flags & VM_SHARED) && filter(MMF_DUMP_HUGETLB_SHARED)) {
            return whole;
        }
        if (!(vma_ptr->vm_flags & VM_SHARED) && filter(MMF_DUMP_HUGETLB_PRIVATE)) {
            return whole;
        }
        return 0;
    }

    if (vma_ptr->vm_flags & VM_IO) {
        return 0;
    }

    if (vma_ptr->vm_flags & VM_SHARED) {
        if (vma_ptr->i_nlink == 0 ? filter(MMF_DUMP_ANON_SHARED) : filter(MMF_DUMP_MAPPED_SHARED)) {
            return whole;
        }
        return 0;
    }

    if(((!(get_config_val("CONFIG_MMU") == "y")) || vma_ptr->anon_vma) && filter(MMF_DUMP_ANON_PRIVATE)){
        return whole;
    }

    if (!is_kvaddr(vma_ptr->vm_file)) {
        return 0;
    }

    if (filter(MMF_DUMP_MAPPED_PRIVATE)) {
        return whole;
    }

    return 0;
}

bool Core::parser_mm_struct(int pid) {
    void *buf = read_struct(tc->mm_struct,"mm_struct");
    if (!buf) return false;
    mm.mm_count = ULONG(buf + field_offset(mm_struct,mm_count));
    mm.start_code = ULONG(buf + field_offset(mm_struct,start_code));
    mm.end_code = ULONG(buf + field_offset(mm_struct,end_code));
    mm.start_data = ULONG(buf + field_offset(mm_struct,start_data));
    mm.end_data = ULONG(buf + field_offset(mm_struct,end_data));
    mm.start_brk = ULONG(buf + field_offset(mm_struct,start_brk));
    mm.brk = ULONG(buf + field_offset(mm_struct,brk));
    mm.start_stack = ULONG(buf + field_offset(mm_struct,start_stack));
    mm.arg_start = ULONG(buf + field_offset(mm_struct,arg_start));
    mm.arg_end = ULONG(buf + field_offset(mm_struct,arg_end));
    mm.env_start = ULONG(buf + field_offset(mm_struct,env_start));
    mm.env_end = ULONG(buf + field_offset(mm_struct,env_end));
    mm.flags = ULONG(buf + field_offset(mm_struct,flags));
    FREEBUF(buf);
    return true;
}

bool Core::parser_user_regset_view(void) {
    ulong addr = csymbol_value(user_view_var_name);
    if(!addr){
        fprintf(fp, "Can't found %s\n",user_view_var_name.c_str());
        return false;
    }
    void *buf = read_struct(addr,"user_regset_view");
    if (!buf) return false;
    urv_ptr = std::make_shared<user_regset_view>();
    ulong name_addr = ULONG(buf + field_offset(user_regset_view,name));
    if (!is_kvaddr(name_addr)) return false;
    urv_ptr->name = read_cstring(name_addr, 32, "user_regset_view name");
    urv_ptr->n = UINT(buf + field_offset(user_regset_view,n));
    urv_ptr->e_flags = UINT(buf + field_offset(user_regset_view,e_flags));
    urv_ptr->e_machine = USHORT(buf + field_offset(user_regset_view,e_machine));
    urv_ptr->ei_osabi = UCHAR(buf + field_offset(user_regset_view,ei_osabi));
    if (debug){
        fprintf(fp, "[%s]:%lx, name:%s cnt:%d e_flags:%d e_machine:%d ei_osabi:%d\n",
            user_view_var_name.c_str(), addr, urv_ptr->name.c_str(), urv_ptr->n,urv_ptr->e_flags, urv_ptr->e_machine, urv_ptr->ei_osabi);
    }
    ulong regset_array_addr = ULONG(buf + field_offset(user_regset_view,regsets));
    FREEBUF(buf);
    for (size_t i = 0; i < urv_ptr->n; i++){
        ulong regsets_addr = regset_array_addr + i * struct_size(user_regset) + field_offset(user_regset,n);
        if (!is_kvaddr(regsets_addr)) continue;
        std::shared_ptr<user_regset> regset_ptr = std::make_shared<user_regset>();
        if(!read_struct(regsets_addr,regset_ptr.get(),sizeof(user_regset),"user_regset")){
            continue;
        }
        if (debug){
            fprintf(fp, "user_regset:%lx, core_note_type:%d cnt:%d size:%d\n",
                regsets_addr,regset_ptr->core_note_type,regset_ptr->n,regset_ptr->size);
        }
        urv_ptr->regsets.push_back(regset_ptr);
    }
    return true;
}

std::string Core::vma_flags_to_str(unsigned long flags) {
    std::string str(4, '-');
    if (flags & VM_READ) str[0] = 'r';
    if (flags & VM_WRITE) str[1] = 'w';
    if (flags & VM_EXEC) str[2] = 'x';
    if (flags & VM_SHARED) str[3] = 's';
    else str[3] = 'p';
    return str;
}

void Core::print_proc_mapping(){
    tc = pid_to_context(core_pid);
    parser_vma_list(tc->task);
    for (auto &vma_ptr : vma_list){
        std::ostringstream oss;
        oss << std::left << "VMA:" << std::hex << vma_ptr->addr << " ["
            << std::hex << vma_ptr->vm_start
            << "-"
            << std::hex << vma_ptr->vm_end << "] "
            << vma_flags_to_str(vma_ptr->vm_flags) << " "
            << std::right << std::hex << std::setw(8) << std::setfill('0') << vma_ptr->vm_pgoff << " "
            << vma_ptr->name;
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

void Core::parser_vma_list(ulong task_addr){
    char buf[BUFSIZE];
    int ANON_BUFSIZE = 1024;
    for (auto &vma_addr : for_each_vma(task_addr)){
        void *vma_buf = read_struct(vma_addr, "vm_area_struct");
        if (!vma_buf) {
            fprintf(fp, "Failed to read vm_area_struct at address %lx\n", vma_addr);
            continue;
        }
        ulong vm_mm = ULONG(vma_buf + field_offset(vm_area_struct, vm_mm));
        if (!is_kvaddr(vm_mm) || tc->mm_struct != vm_mm){
            fprintf(fp, "skip vma %lx, reason vma.vm_mm != task.mm\n", vma_addr);
            FREEBUF(vma_buf);
            continue;
        }
        if (field_offset(vm_area_struct, detached) != -1){
            bool detached = BOOL(vma_buf + field_offset(vm_area_struct, detached));
            if (detached){
                fprintf(fp, "skip vma %lx, reason detached\n", vma_addr);
                FREEBUF(vma_buf);
                continue;
            }
        }
        std::shared_ptr<vma> vma_ptr = std::make_shared<vma>();
        vma_ptr->addr = vma_addr;
        vma_ptr->vm_start = ULONG(vma_buf + field_offset(vm_area_struct, vm_start));
        vma_ptr->vm_end = ULONG(vma_buf + field_offset(vm_area_struct, vm_end));
        vma_ptr->vm_pgoff = ULONG(vma_buf + field_offset(vm_area_struct, vm_pgoff));
        vma_ptr->anon_name = ULONG(vma_buf + field_offset(vm_area_struct, anon_name));
        vma_ptr->anon_vma = ULONG(vma_buf + field_offset(vm_area_struct, anon_vma));
        vma_ptr->vm_mm = vm_mm;
        vma_ptr->vm_flags = ULONG(vma_buf + field_offset(vm_area_struct, vm_flags));
        vma_ptr->vm_file = ULONG(vma_buf + field_offset(vm_area_struct, vm_file));
        if(is_kvaddr(vma_ptr->vm_file)){
            ulong f_mapping = read_pointer(vma_ptr->vm_file + field_offset(file, f_mapping), "file f_mapping");
            vma_ptr->file_inode = read_pointer(f_mapping + field_offset(address_space, host), "address_space host");
            ulong f_inode = read_pointer(vma_ptr->vm_file + field_offset(file, f_inode), "file f_inode");
            vma_ptr->i_nlink = read_uint(f_inode + field_offset(inode, i_nlink), "inode i_nlink");
        }else{
            vma_ptr->file_inode = 0;
            vma_ptr->i_nlink = 0;
        }
        FREEBUF(vma_buf);
        if (is_kvaddr(vma_ptr->vm_file)){ //is file vma
            if (field_offset(file, f_vfsmnt) != -1) {
                get_pathname(file_to_dentry(vma_ptr->vm_file), buf, BUFSIZE, 1, file_to_vfsmnt(vma_ptr->vm_file));
            } else {
                get_pathname(file_to_dentry(vma_ptr->vm_file), buf, BUFSIZE, 1, 0);
            }
            vma_ptr->name = buf;
        }else if (vma_ptr->anon_name) { //read anon name
            if (is_kvaddr(vma_ptr->anon_name)){
                if (field_offset(anon_vma_name, name) != -1) {
                    read_cstring(vma_ptr->anon_name + field_offset(anon_vma_name, name),ANON_BUFSIZE,"anon_name");
                }else{
                    read_cstring(vma_ptr->anon_name,ANON_BUFSIZE,"anon_name");
                }
            }else if (is_uvaddr(vma_ptr->anon_name,tc) && swap_ptr.get() != nullptr){
#if defined(__LP64__)
                vma_ptr->anon_name &= (USERSPACE_TOP - 1);
#endif
                char* name_buf = swap_ptr->uread_memory(tc->task,vma_ptr->anon_name, ANON_BUFSIZE, "anon_name");
                if (name_buf != nullptr){
                    vma_ptr->name = name_buf;
                    std::free(name_buf);
                }
            }
        } else {
            if (vma_ptr->vm_end > mm.start_brk && vma_ptr->vm_start < mm.brk){
                vma_ptr->name = "[heap]";
            }
            if (vma_ptr->vm_end >= mm.start_stack && vma_ptr->vm_start <=  mm.start_stack){
                vma_ptr->name = "[stack]";
            }
        }
        vma_ptr->name += '\0';
        vma_list.push_back(vma_ptr);
    }
}

void Core::parser_thread_core_info() {
    int offset = field_offset(task_struct, thread_node);
    ulong signal_addr = read_pointer(tc->task + field_offset(task_struct, signal), "task_struct signal");
    ulong list_head = signal_addr + field_offset(signal_struct, thread_head);
    for(const auto& thread_addr: for_each_list(list_head, offset)){
        std::shared_ptr<elf_thread_info> thread_ptr = std::make_shared<elf_thread_info>();
        thread_ptr->task_addr = thread_addr;
        for(const auto& regset_ptr: urv_ptr->regsets){
            std::shared_ptr<memelfnote> note_ptr = std::make_shared<memelfnote>();
            if(debug) {
                fprintf(fp, "parser_thread_core_info core_note_type: %x \n", regset_ptr->core_note_type);
            }
            switch (regset_ptr->core_note_type)
            {
            case NT_PRSTATUS:
                note_ptr->name = "CORE";
                note_ptr->type = NT_PRSTATUS;
                note_ptr->data = parser_prstatus(thread_addr,&note_ptr->datasz);
                thread_ptr->prstatus_ptr = note_ptr;
                break;
            case NT_PRFPREG:
                note_ptr->name = "LINUX";
                note_ptr->type = NT_PRFPREG;
                note_ptr->data = parser_nt_prfpreg(thread_addr);
                note_ptr->datasz = regset_ptr->n * regset_ptr->size;
                break;
            case NT_ARM_VFP:
                note_ptr->name = "CORE";
                note_ptr->type = NT_ARM_VFP;
                note_ptr->data = parser_nt_arm_vfp(thread_addr);
                note_ptr->datasz = regset_ptr->n * regset_ptr->size;
                break;
            case NT_ARM_TLS:
                note_ptr->name = "CORE";
                note_ptr->type = NT_ARM_TLS;
                note_ptr->data = parser_nt_arm_tls(thread_addr);
                note_ptr->datasz = regset_ptr->n * regset_ptr->size;
                break;
            case NT_ARM_HW_BREAK:
                note_ptr->name = "CORE";
                note_ptr->type = NT_ARM_HW_BREAK;
                note_ptr->data = parser_nt_arm_hw_break(thread_addr);
                note_ptr->datasz = regset_ptr->n * regset_ptr->size;
                break;
            case NT_ARM_HW_WATCH:
                note_ptr->name = "CORE";
                note_ptr->type = NT_ARM_HW_WATCH;
                note_ptr->data = parser_nt_arm_hw_watch(thread_addr);
                note_ptr->datasz = regset_ptr->n * regset_ptr->size;
                break;
            case NT_ARM_SYSTEM_CALL:
                note_ptr->name = "CORE";
                note_ptr->type = NT_ARM_SYSTEM_CALL;
                note_ptr->data = parser_nt_arm_system_call(thread_addr);
                note_ptr->datasz = regset_ptr->n * regset_ptr->size;
                break;
            case NT_ARM_SVE:
                note_ptr->name = "CORE";
                note_ptr->type = NT_ARM_SVE;
                note_ptr->data = parser_nt_arm_sve(thread_addr);
                note_ptr->datasz = regset_ptr->n * regset_ptr->size;
                break;
            case NT_ARM_PAC_MASK:
                note_ptr->name = "CORE";
                note_ptr->type = NT_ARM_PAC_MASK;
                note_ptr->data = parser_nt_arm_pac_mask(thread_addr);
                note_ptr->datasz = regset_ptr->n * regset_ptr->size;
                break;
            case NT_ARM_PAC_ENABLED_KEYS:
                note_ptr->name = "CORE";
                note_ptr->type = NT_ARM_PAC_ENABLED_KEYS;
                note_ptr->data = parser_nt_arm_pac_enabled_keys(thread_addr);
                note_ptr->datasz = regset_ptr->n * regset_ptr->size;
                break;
            case NT_ARM_PACA_KEYS:
                note_ptr->name = "CORE";
                note_ptr->type = NT_ARM_PACA_KEYS;
                note_ptr->data = parser_nt_arm_paca_keys(thread_addr);
                note_ptr->datasz = regset_ptr->n * regset_ptr->size;
                break;
            case NT_ARM_PACG_KEYS:
                note_ptr->name = "CORE";
                note_ptr->type = NT_ARM_PACG_KEYS;
                note_ptr->data = parser_nt_arm_pacg_keys(thread_addr);
                note_ptr->datasz = regset_ptr->n * regset_ptr->size;
                break;
            case NT_ARM_TAGGED_ADDR_CTRL:
                note_ptr->name = "CORE";
                note_ptr->type = NT_ARM_TAGGED_ADDR_CTRL;
                note_ptr->data = parser_nt_arm_tagged_addr_ctrl(thread_addr);
                note_ptr->datasz = regset_ptr->n * regset_ptr->size;
                break;
            default:
                break;
            }
            thread_ptr->note_list.push_back(note_ptr);
        }
        pt_note.thread_list.push_back(thread_ptr);
    }
}

void Core::parser_nt_file() {
    std::vector<char> data_buf;
    size_t files_count = 0;
    int size_data = BITS64() ? (is_compat ? 4 : sizeof(long)) : sizeof(long);

    size_t total_vma_size = 0;
    size_t total_filename_size = 0;
    for (const auto& vma : vma_list) {
        if (!is_kvaddr(vma->vm_file)) {
            continue;
        }
        total_vma_size += 3 * size_data;
        total_filename_size += vma->name.size();
        files_count++;
    }
    data_buf.reserve(2 * size_data + total_vma_size + total_filename_size);

    data_buf.insert(data_buf.end(), reinterpret_cast<const char*>(&files_count), reinterpret_cast<const char*>(&files_count) + size_data);
    data_buf.insert(data_buf.end(), reinterpret_cast<const char*>(&page_size), reinterpret_cast<const char*>(&page_size) + size_data);

    for (const auto& vma : vma_list) {
        if (!is_kvaddr(vma->vm_file)) {
            continue;
        }
        data_buf.insert(data_buf.end(), reinterpret_cast<const char*>(&vma->vm_start), reinterpret_cast<const char*>(&vma->vm_start) + size_data);
        data_buf.insert(data_buf.end(), reinterpret_cast<const char*>(&vma->vm_end), reinterpret_cast<const char*>(&vma->vm_end) + size_data);
        data_buf.insert(data_buf.end(), reinterpret_cast<const char*>(&vma->vm_pgoff), reinterpret_cast<const char*>(&vma->vm_pgoff) + size_data);
    }

    for (const auto& vma : vma_list) {
        if (!is_kvaddr(vma->vm_file)) {
            continue;
        }
        data_buf.insert(data_buf.end(), vma->name.begin(), vma->name.end());
    }

    if (debug) {
        fprintf(fp, "\n\nNT_FILE:\n");
        fprintf(fp, "%s", hexdump(0x1000, data_buf.data(), data_buf.size()).c_str());
    }

    pt_note.files = std::make_shared<memelfnote>();
    pt_note.files->name = "CORE";
    pt_note.files->type = NT_FILE;
    pt_note.files->data = std::malloc(data_buf.size());
    memcpy(pt_note.files->data, data_buf.data(), data_buf.size());
    pt_note.files->datasz = data_buf.size();
}

void Core::dump_align(std::streampos position, std::streamsize align) {
    if (align <= 0 || (align & (align - 1))) {
        return;
    }
    std::streamsize mod = position & (align - 1);
    if (mod > 0) {
        std::streamsize padding_size = align - mod;
        std::vector<char> padding(padding_size, 0);
        if (fwrite(padding.data(), 1, padding_size, corefile) != padding_size) {
            fprintf(fp, "Error writing padding to core file\n");
        }
    }
}

int Core::task_pid_nr_ns(ulong task_addr, long type, ulong ns_addr){
    if(!ns_addr){
        ns_addr = ns_of_pid(read_pointer(task_addr + field_offset(task_struct, thread_pid), "task_struct thread_pid"));
    }
    if (pid_alive(task_addr)){
        return pid_nr_ns(task_pid_ptr(task_addr, type), ns_addr);
    }
    return 0;
}

int Core::pid_nr_ns(ulong pids_addr, ulong pid_ns_addr) {
    if (!is_kvaddr(pids_addr)) {
        return 0;
    }

    uint ns_level = read_uint(pid_ns_addr + field_offset(pid_namespace, level), "pid_namespace level");
    uint pid_level = read_uint(pids_addr + field_offset(pid, level), "pid level");

    if (ns_level > pid_level) {
        return 0;
    }

    ulong upid_addr = pids_addr + field_offset(pid, numbers) + struct_size(upid) * ns_level;
    ulong ns_addr = read_pointer(upid_addr + field_offset(upid, ns), "upid ns");

    if (ns_addr == pid_ns_addr) {
        return read_int(upid_addr + field_offset(upid, nr), "upid nr");
    }

    return 0;
}

int Core::pid_alive(ulong task_addr) {
    ulong thread_pid_addr = read_pointer(task_addr + field_offset(task_struct, thread_pid), "task_struct thread_pid");
    return thread_pid_addr > 0;
}

ulong Core::ns_of_pid(ulong thread_pid_addr) {
    if (!is_kvaddr(thread_pid_addr)) {
        return 0;
    }

    uint level = read_uint(thread_pid_addr + field_offset(pid, level), "task_pid_nr_ns pid level");
    ulong upid_addr = thread_pid_addr + field_offset(pid, numbers) + struct_size(upid) * level;
    return read_pointer(upid_addr + field_offset(upid, ns), "task_pid_nr_ns upid ns");
}

ulong Core::task_pid_ptr(ulong task_addr, long type) {
    if (type == read_enum_val("PIDTYPE_PID")) {
        return read_pointer(task_addr + field_offset(task_struct, thread_pid), "task_struct thread_pid");
    } else {
        ulong signal_addr = read_pointer(task_addr + field_offset(task_struct, signal), "task_struct signal");
        return read_pointer(signal_addr + field_offset(signal_struct, pids) + type * sizeof(void*), "signal_struct pids");
    }
}
#pragma GCC diagnostic pop
