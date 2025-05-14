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
#include <chrono>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

int Core::cmd_flags = 0;
std::string Core::symbols_path;

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
    field_init(file, f_path);
    field_init(file, f_mapping);
    field_init(file, f_inode);
    field_init(path, dentry);
    field_init(path, mnt);
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
    std::string core_path;
    char buffer[PATH_MAX];
    if (getcwd(buffer, sizeof(buffer))) {
        core_path = buffer;
    }
    char filename[32];
    snprintf(filename, sizeof(filename), "core.%ld.%s", tc->pid, tc->comm);
    std::string full_core_path = core_path + "/" + std::string(filename);
    corefile = fopen(full_core_path.c_str(), "wb");
    if (!corefile) {
        fprintf(fp, "Can't open %s\n", full_core_path.c_str());
        return;
    }
    parser_mm_struct(core_pid);
    parser_vma_list(tc->task);
    parser_prpsinfo();
    parser_siginfo();
    parser_nt_file();
    parser_auvx();
    parser_exec_name(auxv_list[AT_EXECFN]);
    parser_thread_core_info();
    write_core_file();
    fprintf(fp, "\ncore_path:%s \n", full_core_path.c_str());
    core_path.clear();
    Core::symbols_path.clear();
}

void Core::parser_exec_name(ulong addr){
    if (IS_UVADDR(addr, tc)){
        exe_name = swap_ptr->uread_cstring(tc->task, addr, 64, "exec name");
    }else{
        exe_name = tc->comm;
    }
}

bool Core::find_lib_path(const std::string& target_path, const std::string& search_base, std::string& result_path) {
    std::string clean_target = target_path;
    if (!clean_target.empty() && clean_target[0] == '/') {
        clean_target.erase(0, 1);
    }
    const std::string normalized_target = std::filesystem::path(clean_target).lexically_normal().generic_string();
    const std::filesystem::path direct_path = std::filesystem::path(search_base) / clean_target;
    if (std::filesystem::exists(direct_path)) {
        result_path = direct_path.generic_string();
        return true;
    }

    std::string target_filename = std::filesystem::path(clean_target).filename().generic_string();
    target_filename.erase(std::remove(target_filename.begin(), target_filename.end(), '\0'), target_filename.end());
    std::string first_filename_match;
    try {
        for (const auto& entry : std::filesystem::recursive_directory_iterator(search_base)) {
            if (!entry.is_regular_file()) continue;

            const std::string current_filename = entry.path().filename().generic_string();
            if (current_filename != target_filename) continue;

            if (first_filename_match.empty()) {
                first_filename_match = entry.path().generic_string();
            }
            const std::string relative_path = entry.path()
                .lexically_relative(search_base)
                .lexically_normal()
                .generic_string();
            const size_t pos = relative_path.find(normalized_target);
            if (pos != std::string::npos) {
                const bool valid_prefix = (pos == 0) || (relative_path[pos-1] == '/');
                const bool valid_suffix = (pos + normalized_target.size() == relative_path.size());

                if (valid_prefix && valid_suffix) {
                    result_path = entry.path().generic_string();
                    return true;
                }
            }
        }
    } catch (const std::exception& e) {
        fprintf(fp, "exception msg:%s \n", e.what());
    }

    if (!first_filename_match.empty()) {
        result_path = first_filename_match;
        fprintf(fp, "only match the file name:%s \n", result_path.c_str());
        return true;
    }
    return false;
}

bool Core::write_pt_note(void) {
    size_t note_data_start = get_pt_note_data_start();
    if (fseek(corefile, note_data_start, SEEK_SET) != 0) {
        fclose(corefile);
        return false;
    }
    for (size_t i = 0; i < thread_list.size(); i++){
        const auto& thread_ptr = thread_list[i];
        writenote(thread_ptr->prstatus_ptr);
        if (i == 0){
            if(psinfo != nullptr){
                writenote(psinfo);
                psinfo.reset();
            }
            if(signote != nullptr){
                writenote(signote);
                signote.reset();
            }
            if(auxv != nullptr){
                if (BITS64() && !is_compat){
                    Elf64_Auxv_t* elf_auxv = (Elf64_Auxv_t*)auxv->data;
                    for (const auto& auxv : auxv_list) {
                        elf_auxv->type = auxv.first;
                        elf_auxv->val = auxv.second;
                        elf_auxv++;
                    }
                    elf_auxv->type = 0;
                    elf_auxv->val = 0;
                }else{
                    Elf32_Auxv_t* elf_auxv = (Elf32_Auxv_t*)auxv->data;
                    for (const auto& auxv : auxv_list) {
                        elf_auxv->type = auxv.first;
                        elf_auxv->val = auxv.second;
                        elf_auxv++;
                    }
                    elf_auxv->type = 0;
                    elf_auxv->val = 0;
                }
                writenote(auxv);
                auxv.reset();
            }
            if(files != nullptr){
                writenote(files);
                files.reset();
            }
        }
        for(const auto& note_ptr: thread_ptr->note_list){
            if (note_ptr != thread_ptr->prstatus_ptr && note_ptr->data){
                writenote(note_ptr);
            }
        }
    }
    thread_list.clear();
    return true;
}

bool Core::write_pt_load(std::shared_ptr<vma> vma_ptr, size_t phdr_pos, size_t& data_pos) {
    size_t p_flags = 0;
    if (vma_ptr->vm_flags & VM_READ){
        p_flags |= PF_R;
    }
    if (vma_ptr->vm_flags & VM_WRITE){
        p_flags |= PF_W;
    }
    if (vma_ptr->vm_flags & VM_EXEC){
        p_flags |= PF_X;
    }
    size_t p_memsz = vma_ptr->vm_end - vma_ptr->vm_start;
    size_t p_filesz = 0;
    if(!vma_dump_size(vma_ptr)){
        p_filesz = p_memsz;
    }
    if (fseek(corefile, phdr_pos, SEEK_SET) != 0) {
        fclose(corefile);
        return false;
    }
    write_phdr(PT_LOAD,data_pos,vma_ptr->vm_start,p_filesz,p_memsz,p_flags,page_size);

    if (vma_dump_size(vma_ptr)) {
        return true;
    }
    if(debug){
        fprintf(fp, "phdr_start: %zu data_start: %zu\n",phdr_pos, data_pos);
    }
    if (fseek(corefile, data_pos, SEEK_SET) != 0) {
        fclose(corefile);
        return false;
    }
    bool replace = false;
    if (Core::cmd_flags & CORE_REPLACE_HEAD){
        /*
        In function svr4_relocate_main_executable,
        the program header in the core file is compared with the program header of the main executable to
        get the runtime address of the dynamic segment.
        */
        if ((vma_ptr->name.find(exe_name) != std::string::npos || vma_ptr->name == exe_name) &&
            (vma_ptr->vm_start <= auxv_list[AT_PHDR] && vma_ptr->vm_end > auxv_list[AT_PHDR])){
                size_t replace_size = replace_phdr_load(vma_ptr);
                if(replace_size > 0){
                    data_pos += replace_size;
                    replace = true;
                }
        }
    }
    if (Core::cmd_flags & CORE_FAKE_LINKMAP){
        /*
        replace all symbol info to core base on l_addr
        */
        for (auto& [vma_name, symbol] : lib_map) {
            if (!symbol) continue;
            if(get_phdr_vma(symbol->vma_load_list) == vma_ptr){
                size_t memsz = vma_ptr->vm_end - vma_ptr->vm_start;
                size_t pgoff = vma_ptr->vm_pgoff << 12;
                fwrite(reinterpret_cast<char*>(symbol->map_addr) + pgoff, memsz, 1, corefile);
                fprintf(fp, "overwrite %s:[size:0x%zx off:%#lx] to core:[%#lx - %#lx] \n",
                    vma_name.c_str(), memsz,vma_ptr->vm_pgoff << 12, vma_ptr->vm_start, vma_ptr->vm_end);
                data_pos += memsz;
                replace = true;
            }
        }
    }
    if(replace == false){
        char page_data[page_size];
        for(ulong addr = vma_ptr->vm_start; addr < vma_ptr->vm_end; addr += page_size){
            if(!swap_ptr->uread_buffer(tc->task, addr, page_data, page_size, "read page for core")){
                BZERO(page_data, page_size);
            }
            fwrite(page_data, page_size, 1, corefile);
            data_pos += page_size;
        }
    }
    return true;
}

size_t Core::replace_phdr_load(std::shared_ptr<vma> vma_ptr){
    std::shared_ptr<symbol_info> lib_ptr = lib_map[vma_ptr->name];
    if(!lib_ptr){
        return -1;
    }
    size_t map_size = 0;
    void *map = map_elf_file(lib_ptr->lib_path, map_size);
    if (map == nullptr){
        return -1;
    }
    size_t memsz = vma_ptr->vm_end - vma_ptr->vm_start;
    size_t pgoff = vma_ptr->vm_pgoff << 12;
    fwrite(reinterpret_cast<char*>(map) + pgoff, memsz, 1, corefile);
    if (munmap(map, map_size) == -1) {
        fprintf(fp, "munmap PHDR failed \n");
    }
    fprintf(fp, "overwrite PHDR %s:[size:0x%zx off:%#lx] to core:[%#lx - %#lx] \n",
            vma_ptr->name.c_str(), memsz, vma_ptr->vm_pgoff << 12, vma_ptr->vm_start, vma_ptr->vm_end);
    return memsz;
}
void Core::write_core_file(void) {
    size_t pt_note_size = 0;
    pt_note_size += notesize(auxv);
    pt_note_size += notesize(psinfo);
    pt_note_size += notesize(signote);
    pt_note_size += notesize(files);
    for(auto& thread_ptr: thread_list){
        for(auto& note_ptr: thread_ptr->note_list){
            if (note_ptr->data) {
                pt_note_size += notesize(note_ptr);
            }
        }
    }
    int segs = vma_list.size() + 1; // for PT_NOTE
    if (Core::cmd_flags & CORE_FAKE_LINKMAP){
        segs += lib_map.size() ? 1 : 0; // for Fake
    }
    int e_phnum = segs > PN_XNUM ? PN_XNUM : segs;
    // ===========================================
    //  Writing ELF header
    // ===========================================
    size_t hdr_size = 0;
    hdr_ptr = fill_elf_header(ET_CORE, e_phnum, hdr_size);
    if (fseek(corefile, 0, SEEK_SET) != 0) {
        fclose(corefile);
        std::free(hdr_ptr);
        return;
    }
    fwrite(hdr_ptr, hdr_size, 1, corefile);

    //  ===========================================
    //  Writing PT_NOTE
    //  ===========================================
    size_t phdr_pos = get_phdr_start();
    if (fseek(corefile, phdr_pos, SEEK_SET) != 0) {
        fclose(corefile);
        std::free(hdr_ptr);
        return;
    }
    if (Core::cmd_flags & CORE_FAKE_LINKMAP){
        if(lib_map.size()){ //update before write fake vma
            size_t hdr_size = (BITS64() && !is_compat) ? sizeof(Elf64_Ehdr) : sizeof(Elf32_Ehdr);
            auxv_list[AT_PHDR] = FAKE_AUXV_PHDR + hdr_size;
            auxv_list[AT_EXECFN] = 0;
        }
    }
    write_phdr(PT_NOTE, get_pt_note_data_start(), 0, pt_note_size, 0, 0, 0);
    if (!write_pt_note()){
        fclose(corefile);
        std::free(hdr_ptr);
        return;
    }

    //  ===========================================
    //  Writing Fake LOAD
    //  ===========================================
    size_t load_data_pos = roundup((get_pt_note_data_start() + pt_note_size), page_size);
    if (Core::cmd_flags & CORE_FAKE_LINKMAP){
        if(lib_map.size()){
            phdr_pos += get_phdr_size(); // header note
            write_fake_data(load_data_pos, phdr_pos);
        }
    }

    //  ===========================================
    //  Writing PT LOAD
    //  ===========================================
    // auto start = std::chrono::high_resolution_clock::now();
    size_t vma_count = vma_list.size();
    for (const auto& vma_ptr : vma_list) {
        phdr_pos += get_phdr_size();
        if (!write_pt_load(vma_ptr,phdr_pos,load_data_pos)){
            continue;
        }
        std::cout << "Written page to core file. Remaining VMA count: " << --vma_count << std::endl;
    }
    // auto end = std::chrono::high_resolution_clock::now();
    // std::chrono::duration<double> elapsed = end - start;
    // fprintf(fp, "time: %.6f s\n",elapsed.count());
    free_lib_map();
    fclose(corefile);
    std::free(hdr_ptr);
    return;
}

int Core::vma_dump_size(std::shared_ptr<vma> vma_ptr) {
    int filter_flags = FILTER_SANITIZER_SHADOW_VMA | FILTER_NON_READ_VMA;
    if (filter_flags & FILTER_SPECIAL_VMA) {
        if (vma_ptr->name.find("binder") != std::string::npos || vma_ptr->name.find("mali0") != std::string::npos){
            return 1;
        }
    }
    if (filter_flags & FILTER_FILE_VMA) {
        if (!vma_ptr->anon_vma && vma_ptr->vm_file){
            return 1;
        }
    }
    if (filter_flags & FILTER_SHARED_VMA) {
        if (vma_ptr->vm_flags & (VM_SHARED | VM_MAYSHARE)){
            return 1;
        }
    }
    if (filter_flags &  FILTER_SANITIZER_SHADOW_VMA) {
        if (vma_ptr->name.find("shadow") != std::string::npos || vma_ptr->name.find("hwasan") != std::string::npos){
            return 1;
        }
    }
    if (filter_flags & FILTER_NON_READ_VMA) {
        if (!(vma_ptr->vm_flags & VM_READ)
                && !(vma_ptr->vm_flags & VM_WRITE)
                && !(vma_ptr->vm_flags & VM_EXEC)){ // RX .text
                    return 1;
        }
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
            << std::right << std::setw(16) << std::setfill('0') << vma_ptr->vm_flags << " "
            << std::right << std::hex << std::setw(8) << std::setfill('0') << vma_ptr->vm_pgoff << " "
            << vma_ptr->name;
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

void Core::parser_vma_list(ulong task_addr){
    if(vma_list.size()){
        vma_list.clear();
    }
    char buf[BUFSIZE];
    int ANON_BUFSIZE = 1024;
    char *file_buf = nullptr;
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
        FREEBUF(vma_buf);
        if (is_kvaddr(vma_ptr->vm_file)){ //file vma
            file_buf = fill_file_cache(vma_ptr->vm_file);
            ulong dentry = ULONG(file_buf + field_offset(file, f_path) + field_offset(path, dentry));
            if(is_kvaddr(dentry)){
                if (field_offset(file, f_path) != -1 && field_offset(path, dentry) != -1 && field_offset(path, mnt) != -1) {
                    ulong vfsmnt = ULONG(file_buf + field_offset(file, f_path) + field_offset(path, mnt));
                    get_pathname(dentry, buf, BUFSIZE, 1, vfsmnt);
                } else {
                    get_pathname(dentry, buf, BUFSIZE, 1, 0);
                }
                vma_ptr->name = buf;
            }
        }else if (vma_ptr->anon_name) { //anon vma
            if (is_kvaddr(vma_ptr->anon_name)){ // // kernel 5.15 in kernelspace
                if (field_offset(anon_vma_name, name) != -1) {
                    vma_ptr->name = "[anon:" + read_cstring(vma_ptr->anon_name + field_offset(anon_vma_name, name),ANON_BUFSIZE,"anon_name") + "]";
                }else{
                    vma_ptr->name = "[anon:" + read_cstring(vma_ptr->anon_name,ANON_BUFSIZE,"anon_name") + "]";
                }
            }else if (is_uvaddr(vma_ptr->anon_name,tc) && swap_ptr.get() != nullptr){ // kernel 5.4 in userspace
#if defined(ARM64)
                vma_ptr->anon_name &= (USERSPACE_TOP - 1);
#endif
                vma_ptr->name = "[anon:" + swap_ptr->uread_cstring(tc->task,vma_ptr->anon_name, ANON_BUFSIZE, "anon_name") + "]";
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
                fprintf(fp, "core_note_type: %x \n", regset_ptr->core_note_type);
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
        thread_list.push_back(thread_ptr);
    }
}

void Core::parser_auvx(){
    size_t auxv_size = field_size(mm_struct, saved_auxv);
    size_t data_size = BITS64() && !is_compat ? sizeof(Elf64_Auxv_t) : sizeof(Elf32_Auxv_t);
    int auxv_cnt = auxv_size / data_size;
    void* auxv_buf = read_memory(tc->mm_struct + field_offset(mm_struct, saved_auxv), auxv_size, "mm_struct saved_auxv");
    if(!auxv_buf){
        fprintf(fp, "fill_auvx_note auxv_buf is NULL \n");
        return;
    }
    if(auxv_list.size()){
        auxv_list.clear();
    }
    if (BITS64() && !is_compat){
        Elf64_Auxv_t* elf_auxv = (Elf64_Auxv_t*)auxv_buf;
        for (size_t i = 0; i < auxv_cnt; i++){
            if (elf_auxv->type == 0){
               continue;
            }
            auxv_list[elf_auxv->type] = elf_auxv->val;
            elf_auxv++;
        }
    }else{
        Elf32_Auxv_t* elf_auxv = (Elf32_Auxv_t*)auxv_buf;
        for (size_t i = 0; i < auxv_cnt; i++){
            if (elf_auxv->type == 0){
               continue;
            }
            auxv_list[elf_auxv->type] = elf_auxv->val;
            elf_auxv++;
        }
    }
    auxv = std::make_shared<memelfnote>();
    auxv->name = "CORE";
    auxv->type = NT_AUXV;
    auxv->data = std::malloc(auxv_size);
    memcpy(auxv->data, auxv_buf, auxv_size);
    FREEBUF(auxv_buf);
    auxv->datasz = auxv_size;
    if (debug){
        fprintf(fp,  "\n\nNT_AUXV:\n");
        fprintf(fp, "%s", hexdump(0x1000, (char*)auxv->data, auxv_size).c_str());
    }
}

void Core::parser_nt_file() {
    std::unique_ptr<std::vector<char>> data_ptr = std::make_unique<std::vector<char>>();
    size_t files_count = 0;
    int size_data = BITS64() ? (is_compat ? 4 : sizeof(long)) : sizeof(long);
    size_t total_vma_size = 0;
    size_t total_filename_size = 0;

    free_lib_map();
    for (const auto& vma : vma_list) {
        if (!is_kvaddr(vma->vm_file)) {
            continue;
        }
        total_vma_size += 3 * size_data;
        total_filename_size += vma->name.size();
        files_count++;

        if (!Core::symbols_path.empty()){
            std::string filepath;
            if(!find_lib_path(vma->name, Core::symbols_path, filepath)){
                continue;
            }
            std::shared_ptr<symbol_info> lib_ptr;
            if (lib_map.find(vma->name) != lib_map.end()) { //exists
                lib_ptr = lib_map[vma->name];
            } else {
                lib_ptr = std::make_shared<symbol_info>();
                lib_ptr->lib_path = filepath;
                // get the elf symbol info, including mmap_addr, phdr, pt_dynamic
                if(!read_elf_file(lib_ptr)){
                    continue;
                }
                lib_map[vma->name] = lib_ptr;
            }
            lib_ptr->vma_load_list.push_back(vma);
            vma->symbol_ptr = lib_ptr;
        }
    }
    if(debug){
        for (const auto& pair : lib_map) {
            fprintf(fp, "%s \n", pair.second->lib_path.c_str());
            for (const auto& vma : pair.second->vma_load_list) {
                fprintf(fp, "   [%#lx ~ %#lx] \n", vma->vm_start, vma->vm_end);
            }
        }
    }
    data_ptr->reserve(2 * size_data + total_vma_size + total_filename_size);
    data_ptr->insert(data_ptr->end(), reinterpret_cast<const char*>(&files_count), reinterpret_cast<const char*>(&files_count) + size_data);
    data_ptr->insert(data_ptr->end(), reinterpret_cast<const char*>(&page_size), reinterpret_cast<const char*>(&page_size) + size_data);
    for (const auto& vma : vma_list) {
        if (!is_kvaddr(vma->vm_file)) {
            continue;
        }
        data_ptr->insert(data_ptr->end(), reinterpret_cast<const char*>(&vma->vm_start), reinterpret_cast<const char*>(&vma->vm_start) + size_data);
        data_ptr->insert(data_ptr->end(), reinterpret_cast<const char*>(&vma->vm_end), reinterpret_cast<const char*>(&vma->vm_end) + size_data);
        data_ptr->insert(data_ptr->end(), reinterpret_cast<const char*>(&vma->vm_pgoff), reinterpret_cast<const char*>(&vma->vm_pgoff) + size_data);
    }
    for (const auto& vma : vma_list) {
        if (!is_kvaddr(vma->vm_file)) {
            continue;
        }
        data_ptr->insert(data_ptr->end(), vma->name.begin(), vma->name.end());
    }
    if (debug) {
        fprintf(fp, "\n\nNT_FILE:\n");
        fprintf(fp, "%s\n\n", hexdump(0x1000, data_ptr->data(), data_ptr->size()).c_str());
    }
    files = std::make_shared<memelfnote>();
    files->name = "CORE";
    files->type = NT_FILE;
    files->data = std::malloc(data_ptr->size());
    memcpy(files->data, data_ptr->data(), data_ptr->size());
    files->datasz = data_ptr->size();
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

void Core::write_phdr(size_t p_type, size_t p_offset, size_t p_vaddr, size_t p_filesz, size_t p_memsz, size_t p_flags, size_t p_align) {
    size_t data_size = BITS64() && !is_compat ? sizeof(Elf64_Phdr) : sizeof(Elf32_Phdr);
    std::unique_ptr<char[]> phdr(new char[data_size]);
    BZERO(phdr.get(), data_size);

    auto set_phdr = [&](auto* elf_phdr) {
        elf_phdr->p_type = p_type;
        elf_phdr->p_offset = p_offset;
        elf_phdr->p_vaddr = p_vaddr;
        elf_phdr->p_paddr = 0;
        elf_phdr->p_filesz = p_filesz;
        elf_phdr->p_memsz = p_memsz;
        elf_phdr->p_flags = p_flags;
        elf_phdr->p_align = p_align;
        fwrite(elf_phdr, data_size, 1, corefile);
    };

    if (BITS64() && !is_compat) {
        Elf64_Phdr* elf_phdr = reinterpret_cast<Elf64_Phdr*>(phdr.get());
        set_phdr(elf_phdr);
    } else {
        Elf32_Phdr* elf_phdr = reinterpret_cast<Elf32_Phdr*>(phdr.get());
        set_phdr(elf_phdr);
    }
}

int Core::notesize(std::shared_ptr<memelfnote> note_ptr){
    size_t total_size = BITS64() && !is_compat ? sizeof(Elf64_Nhdr) : sizeof(Elf32_Nhdr);
    total_size += roundup(note_ptr->name.size() + 1,4);
    total_size += roundup(note_ptr->datasz,4);
    return total_size;
}

void Core::writenote(std::shared_ptr<memelfnote> note_ptr) {
    size_t data_size = BITS64() && !is_compat ? sizeof(Elf64_Nhdr) : sizeof(Elf32_Nhdr);
    std::unique_ptr<char[]> note(new char[data_size]);
    BZERO(note.get(), data_size);

    auto write_note = [&](auto* elf_note) {
        elf_note->n_namesz = note_ptr->name.size() + 1;
        elf_note->n_descsz = note_ptr->datasz;
        elf_note->n_type = note_ptr->type;

        fwrite(elf_note, sizeof(*elf_note), 1, corefile);
        fwrite(note_ptr->name.c_str(), elf_note->n_namesz, 1, corefile);
        dump_align(ftell(corefile), 4);
        fwrite(reinterpret_cast<const char*>(note_ptr->data), note_ptr->datasz, 1, corefile);
        std::free(note_ptr->data);
        dump_align(ftell(corefile), 4);
    };

    if (BITS64() && !is_compat) {
        write_note(reinterpret_cast<Elf64_Nhdr*>(note.get()));
    } else {
        write_note(reinterpret_cast<Elf32_Nhdr*>(note.get()));
    }
}

void* Core::fill_elf_header(int type, int phnum, size_t& hdr_size) {
    hdr_size = BITS64() && !is_compat ? sizeof(Elf64_Ehdr) : sizeof(Elf32_Ehdr);
    size_t phdr_size = BITS64() && !is_compat ? sizeof(Elf64_Phdr) : sizeof(Elf32_Phdr);
    void* hdr = std::malloc(hdr_size);
    BZERO(hdr, hdr_size);
    auto set_elf_header = [&](auto* elf_hdr) {
        snprintf((char *)elf_hdr->e_ident, 5, ELFMAG);
        elf_hdr->e_ident[EI_CLASS] = elf_class;
        elf_hdr->e_ident[EI_DATA] = ELFDATA2LSB;
        elf_hdr->e_ident[EI_VERSION] = EV_CURRENT;
        elf_hdr->e_ident[EI_OSABI] = urv_ptr->ei_osabi;
        elf_hdr->e_type = type;
        elf_hdr->e_machine = urv_ptr->e_machine;
        elf_hdr->e_version = EV_CURRENT;
        elf_hdr->e_phoff = hdr_size;
        elf_hdr->e_flags = urv_ptr->e_flags;
        elf_hdr->e_ehsize = hdr_size;
        elf_hdr->e_phentsize = phdr_size;
        elf_hdr->e_phnum = phnum;
        if (debug) {
            fprintf(fp, "\n\nelf_hdr:\n");
            fprintf(fp, "%s", hexdump(0, (char*)elf_hdr, hdr_size).c_str());
        }
    };
    if (BITS64() && !is_compat) {
        Elf64_Ehdr* elf_hdr = reinterpret_cast<Elf64_Ehdr*>(hdr);
        set_elf_header(elf_hdr);
    } else {
        Elf32_Ehdr* elf_hdr = reinterpret_cast<Elf32_Ehdr*>(hdr);
        set_elf_header(elf_hdr);
    }
    return hdr;
}

int Core::get_phdr_start() {
    return (BITS64() && !is_compat) ?
           reinterpret_cast<Elf64_Ehdr*>(hdr_ptr)->e_phoff :
           reinterpret_cast<Elf32_Ehdr*>(hdr_ptr)->e_phoff;
}

int Core::get_pt_note_data_start() {
    return (BITS64() && !is_compat) ?
           reinterpret_cast<Elf64_Ehdr*>(hdr_ptr)->e_ehsize + (reinterpret_cast<Elf64_Ehdr*>(hdr_ptr)->e_phnum * reinterpret_cast<Elf64_Ehdr*>(hdr_ptr)->e_phentsize) :
           reinterpret_cast<Elf32_Ehdr*>(hdr_ptr)->e_ehsize + (reinterpret_cast<Elf32_Ehdr*>(hdr_ptr)->e_phnum * reinterpret_cast<Elf32_Ehdr*>(hdr_ptr)->e_phentsize);
}

int Core::get_phdr_size() {
    return (BITS64() && !is_compat) ?
           reinterpret_cast<Elf64_Ehdr*>(hdr_ptr)->e_phentsize :
           reinterpret_cast<Elf32_Ehdr*>(hdr_ptr)->e_phentsize;
}

std::shared_ptr<vma> Core::get_phdr_vma(std::vector<std::shared_ptr<vma>> vma_list){
    std::vector<std::shared_ptr<vma>> tmps_vma;
    if(vma_list.size() == 0){
        return nullptr;
    }
    // std::sort(vma_list.begin(), vma_list.end(),[&](const std::shared_ptr<vma>& a, const std::shared_ptr<vma>& b){
    //     return a->vm_start > b->vm_start;
    // });
    for (const auto& vma_ptr : vma_list) {
        if (vma_ptr->vm_flags & VM_EXEC){ // R .text
            if (tmps_vma.empty()) {
                return vma_ptr;
            }
            for (const auto& ptr : tmps_vma){
                ulong cloc_vaddr = vma_ptr->vm_start - (vma_ptr->vm_pgoff << 12) + (ptr->vm_pgoff << 12);
                if(ptr->vm_start > cloc_vaddr){
                    continue;
                }
                if(ptr->vm_start <= cloc_vaddr){
                    return ptr;
                }
            }
        } else {
            tmps_vma.push_back(vma_ptr);
        }
    }
    return vma_list[0];
}

void* Core::map_elf_file(std::string filepath, size_t& len){
    int fd = open(filepath.c_str(), O_RDONLY);
    if (fd < 0) {
        return nullptr;
    }
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return nullptr;
    }
    void* map = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        fprintf(fp, "mmap failed \n");
        close(fd);
        return nullptr;
    }
    len = st.st_size;
    close(fd);
    return map;
}

bool Core::check_elf_file(void* map){
    auto check_header  = [&](auto* elf_hdr) {
        if (memcmp(elf_hdr->e_ident, ELFMAG, SELFMAG) != 0) {
            fprintf(fp, "Not an ELF file\n");
            return false;
        }
        if (elf_hdr->e_type != ET_DYN) {
            fprintf(fp, "Not a shared object (ET_DYN) file\n");
            return false;
        }
        return true;
    };
    if (BITS64() && !is_compat) {
        Elf64_Ehdr* elf_hdr = reinterpret_cast<Elf64_Ehdr*>(map);
        return check_header(elf_hdr);
    } else {
        Elf32_Ehdr* elf_hdr = reinterpret_cast<Elf32_Ehdr*>(map);
        return check_header(elf_hdr);
    }
}

bool Core::read_elf_file(std::shared_ptr<symbol_info> lib_ptr){
    size_t map_size = 0;
    void* map = map_elf_file(lib_ptr->lib_path, map_size);
    if (map == nullptr) {
        return false;
    }
    if (!check_elf_file(map)) {
        munmap(map, map_size);
        return false;
    }
    auto process_phdrs = [&](auto* elf_hdr, auto* phdr_table) {
        for (size_t i = 0; i < elf_hdr->e_phnum; ++i) {
            auto& phdr = phdr_table[i];
            if (phdr.p_type == PT_DYNAMIC) {
                lib_ptr->dynamic_offset = phdr.p_offset;
                lib_ptr->dynamic_vaddr = phdr.p_vaddr;
            }
            if (phdr.p_type == PT_PHDR) {
                lib_ptr->phdr_offset = phdr.p_offset;
                lib_ptr->phdr_vaddr = phdr.p_vaddr;
            }
        }
    };
    if (BITS64() && !is_compat) {
        Elf64_Ehdr* elf_hdr = reinterpret_cast<Elf64_Ehdr*>(map);
        Elf64_Phdr* phdr_table = reinterpret_cast<Elf64_Phdr*>(reinterpret_cast<char*>(map) + elf_hdr->e_phoff);
        process_phdrs(elf_hdr, phdr_table);
    } else {
        Elf32_Ehdr* elf_hdr = reinterpret_cast<Elf32_Ehdr*>(map);
        Elf32_Phdr* phdr_table = reinterpret_cast<Elf32_Phdr*>(reinterpret_cast<char*>(map) + elf_hdr->e_phoff);
        process_phdrs(elf_hdr, phdr_table);
    }
    lib_ptr->map_addr = map;
    lib_ptr->map_size = map_size;
    return true;
}

void Core::free_lib_map() {
    for (auto& [key, symbol] : lib_map) {
        if (!symbol) continue;
        if (symbol->map_addr != nullptr && symbol->map_size > 0) {
            if (munmap(symbol->map_addr, symbol->map_size) == -1) {
                fprintf(fp, "munmap failed \n");
            }
            symbol->map_addr = nullptr;
            symbol->map_size = 0;
        }
        symbol->vma_load_list.clear();
    }
    lib_map.clear();
}

/*
   ---->+-----------------+<-----               [FAKE_AUXV_PHDR]
     ^  |     ET_DYN      |
     |  +-----------------+<----- PT_PHDR
 page|  |     PT_PHDR     |
     |  +-----------------+
     v  |    PT_DYNAMIC   |
   ---->+-----------------+<----- PT_DYNAMIC    [FAKE_AUXV_PHDR + page]
     ^  |    dynamic_t    |
     |  +-----------------+<----- dynamic_t.value
 page|  |    r_debug_t    |
     v  |                 |
   ---->+-----------------+<----- debug_t.map   [FAKE_AUXV_PHDR + page + page]
        |                 |
        |    link_map     |
        |                 |
        |                 |
        +-----------------+<-----               [FAKE_AUXV_PHDR + page + page + linkmap_size]
        |                 |
        |    strtab       |
        |                 |
        +-----------------+
*/
void Core::write_fake_data(size_t &data_pos, size_t phdr_pos){
    if (fseek(corefile, data_pos, SEEK_SET) != 0) {
        fclose(corefile);
        return;
    }
    size_t fake_header_offset = data_pos;
    size_t hdr_size = 0;
    void* hdr = fill_elf_header(ET_DYN, 2, hdr_size);
    fwrite(hdr, hdr_size, 1, corefile);
    if (debug) {
        fprintf(fp, "\n\nfake elf_hdr:\n");
        fprintf(fp, "%s", hexdump(0, (char*)hdr, hdr_size).c_str());
    }
    std::free(hdr);
    /*
       we can see the comment as below in GDB.
       at_phdr is real address in memory. pt_phdr is what pheader says it is.
	   Relocation offset is the difference between the two.
       sect_addr = sect_addr + (at_phdr - pt_phdr);
    */
    write_phdr(PT_PHDR, hdr_size, hdr_size, 0, page_size, PF_R, 0x8);
    write_phdr(PT_DYNAMIC, page_size, page_size, page_size, page_size, PF_R | PF_W,0x8);
    dump_align(ftell(corefile), page_size);

    data_pos += page_size;

    dynamic_t dyn;
    BZERO(&dyn, sizeof(dynamic_t));
    dyn.type = DT_DEBUG;
    dyn.value = FAKE_AUXV_PHDR + page_size /* first page */ + sizeof(dynamic_t);
    if (debug) {
        fprintf(fp, "\n\nfake DYNAMINC:\n");
        fprintf(fp, "%s", hexdump(0, (char*)&dyn, sizeof(dynamic_t)).c_str());
    }
    fwrite(&dyn, sizeof(dynamic_t), 1, corefile);
    r_debug_t r_debug;
    BZERO(&r_debug, sizeof(r_debug_t));
    r_debug.version = 1;
    r_debug.map = FAKE_AUXV_PHDR + page_size /* first page */ + page_size /* second page */;
    if (debug) {
        fprintf(fp, "\n\nfake DT_DEBUG:\n");
        fprintf(fp, "%s", hexdump(0, (char*)&r_debug, sizeof(r_debug_t)).c_str());
    }
    fwrite(&r_debug, sizeof(r_debug_t), 1, corefile);
    dump_align(ftell(corefile), page_size);

    data_pos += page_size;

    size_t cur_linkmap_vaddr = r_debug.map;
    // size_t linkmap_size = roundup(sizeof(linkmap_t) * (lib_map.size() + 1/* FAKECORE */), page_size);
    size_t linkmap_size = sizeof(linkmap_t) * (lib_map.size() + 1/* FAKECORE */);
    std::unique_ptr<char[]> linkmap_buf(new char[linkmap_size]);
    BZERO(linkmap_buf.get(), linkmap_size);

    data_pos += linkmap_size;

    size_t cur_strtab_vaddr = r_debug.map + linkmap_size;
    std::string name = "[FAKECORE]";
    name += '\0';
    std::stringstream strtab;
    strtab << name;

    linkmap_t* linkmap = (linkmap_t*)linkmap_buf.get();
    linkmap->addr = FAKE_AUXV_PHDR;
    linkmap->name = cur_strtab_vaddr;
    linkmap->ld = 0x0;
    linkmap->next = cur_linkmap_vaddr + sizeof(linkmap_t);
    linkmap->prev = 0x0;
    cur_strtab_vaddr += name.length();
    for (const auto& pair : lib_map) {
        std::shared_ptr<symbol_info> lib_ptr = pair.second;
        if(lib_ptr == nullptr){
            continue;
        }
        std::shared_ptr<vma> base_vma_ptr = get_phdr_vma(lib_ptr->vma_load_list);
        if(base_vma_ptr == nullptr){
            continue;
        }
        linkmap++;
        // the base addr of library
        linkmap->addr = base_vma_ptr->vm_start;
        if (lib_ptr->phdr_offset != lib_ptr->phdr_vaddr){
            linkmap->addr += (lib_ptr->phdr_offset - lib_ptr->phdr_vaddr);
        }
        // the addr of dynamic
        linkmap->ld = linkmap->addr + lib_ptr->dynamic_vaddr;
        if (debug){
            fprintf(fp, "linkmap->addr:%#lx linkmap->ld:%#lx %s\n", linkmap->addr,linkmap->ld,base_vma_ptr->name.c_str());
        }
        linkmap->name = cur_strtab_vaddr;
        linkmap->prev = cur_linkmap_vaddr;
        cur_linkmap_vaddr = cur_linkmap_vaddr + sizeof(linkmap_t);
        linkmap->next = cur_linkmap_vaddr + sizeof(linkmap_t);

        strtab << base_vma_ptr->name;
        cur_strtab_vaddr += base_vma_ptr->name.length();
    }
    linkmap->next = 0;
    // strtab_len = roundup(strtab.str().size(), page_size);
    data_pos += strtab.str().size();
    if(debug){
        fprintf(fp, "\n\nLINKMAP:\n");
        fprintf(fp, "%s", hexdump(FAKE_AUXV_PHDR + 2 * page_size, (char*)linkmap_buf.get(), linkmap_size).c_str());

        fprintf(fp, "\n\nSTRTAB:\n");
        fprintf(fp, "%s", hexdump(FAKE_AUXV_PHDR + 2 * page_size + linkmap_size, (char*)strtab.str().c_str(), strtab.str().size()).c_str());
    }
    fwrite(linkmap_buf.get(), linkmap_size, 1, corefile);
    fwrite(strtab.str().c_str(), strtab.str().size(), 1, corefile);

    dump_align(ftell(corefile), page_size);
    //  ===========================================
    //  Writing Fake LOAD Header
    //  ===========================================
    /*
        roundup(linkmap_size + strtab, page_size),
    */
    size_t p_filesz = (page_size                 /* FAKE_PHDR */
                    + page_size                  /* FAKE_DYNAMIC */
                    + linkmap_size               /* FAKE_LINK_MAP */
                    + strtab.str().size());      /* FAKE_STRTAB */
    if (fseek(corefile, phdr_pos, SEEK_SET) != 0) {
        fclose(corefile);
        return;
    }
    write_phdr(PT_LOAD, fake_header_offset, FAKE_AUXV_PHDR, p_filesz, p_filesz, PF_R | PF_W, page_size);
}

void Core::print_linkmap(){
#if defined(ARM)
#define Elf(type) Elf32_##type
#elif defined(ARM64)
#define Elf(type) Elf64_##type
#endif
    if (BITS64() && is_compat) {
        /*
         * If you want to enable compatibility, you need to add the following code:
         * Every struct should use 32-bit(uint32_t and Elf32_type), including all parameters passed in swapinfo.
         */
        fprintf(fp, "We do not support compat for the linkmap feature\n");
        return;
    }
    tc = pid_to_context(core_pid);
    if (!tc) {
        fprintf(fp, "pid_to_context failed\n");
        return;
    }
    parser_auvx();
    std::free(auxv->data);
    auxv.reset();
    ulong at_phdr = auxv_list[AT_PHDR];
    ulong at_phnum = auxv_list[AT_PHNUM];
    ulong at_phent = auxv_list[AT_PHENT];
    ulong at_entry = auxv_list[AT_ENTRY];
    parser_exec_name(auxv_list[AT_EXECFN]);
    std::string exec_file_path;
    if(!find_lib_path(exe_name, Core::symbols_path, exec_file_path)){
        fprintf(fp, "can't find %s\n",exe_name.c_str());
        return;
    }
    int fd = open(exec_file_path.c_str(), O_RDONLY);
    if (fd == -1) {
        return;
    }
    struct stat st;
    if (fstat(fd, &st) == -1) {
        close(fd);
        return;
    }
    void* exec_map = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (exec_map == MAP_FAILED) {
        close(fd);
        return;
    }
    Elf(Ehdr)* ehdr = reinterpret_cast<Elf(Ehdr)*>(exec_map);
    Elf(Phdr)* phdr = reinterpret_cast<Elf(Phdr)*>((static_cast<char*>(exec_map) + ehdr->e_phoff));
    char* core_phdr = static_cast<char*>(std::malloc(at_phnum * at_phent));
    if (!core_phdr) {
        munmap(exec_map, st.st_size);
        close(fd);
        return;
    }
    if (!swap_ptr->uread_buffer(tc->task, at_phdr, core_phdr, at_phnum * at_phent, "read page for core phdr")) {
        std::free(core_phdr);
        munmap(exec_map, st.st_size);
        close(fd);
        return;
    }
    ulong exec_pt_Load_x_vaddr = ehdr->e_entry;
    ulong exec_dynamic_vaddr = 0;
    Elf(Dyn)* dyn = nullptr;
    bool flags = true;
    for (int i = 0; i < at_phnum; ++i) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            dyn = reinterpret_cast<Elf(Dyn)*>((static_cast<char*>(exec_map) + phdr[i].p_offset));
            exec_dynamic_vaddr = phdr[i].p_vaddr;
        }
        // see the svr4_exec_displacement in GDB.
        if (memcmp(&phdr[i], &core_phdr[i * sizeof(Elf(Phdr))], sizeof(Elf(Phdr))) != 0) {
            if(flags){
                fprintf(fp, "the phdr is not correct in coredump, core phnum:%ld, exec phnum:%d \n", at_phnum, ehdr->e_phnum);
                flags = false;
            }
        }
    }
    ulong linkmap_addr = 0;
    ulong exec_displacement = at_entry - exec_pt_Load_x_vaddr;
    // fprintf(fp, "at_entry: %#lx exec_pt_Load_x_vaddr:%#lx exec_dynamic_vaddr:%#lx exec_displacement:%#lx \n", at_entry, exec_pt_Load_x_vaddr, exec_dynamic_vaddr, exec_displacement);
    if (dyn) {
        for (int count = 0;; ++count) {
            if (dyn[count].d_tag == DT_NULL) {
                break;
            }
            if (dyn[count].d_tag == DT_DEBUG) {
                ulong dyn_ptr = exec_displacement + exec_dynamic_vaddr + count * sizeof(Elf(Dyn)) + sizeof(void*) /* 8 & 4*/;
                linkmap_addr = swap_ptr->uread_ulong(tc->task, dyn_ptr, "read page for dyn");
                // fprintf(fp, "dyn_ptr: %#lx, base:%#lx\n", dyn_ptr, linkmap_addr);
            }
        }
    }

    if (!is_uvaddr(linkmap_addr, tc)) {
        fprintf(fp, "linkmap addr not uvaddr:%#lx\n", linkmap_addr);
        std::free(core_phdr);
        munmap(exec_map, st.st_size);
        close(fd);
        return;
    }

    linkmap_addr += sizeof(void*);
    linkmap_addr = swap_ptr->uread_ulong(tc->task, linkmap_addr, "read page for fisrt linkmap");
    // fprintf(fp, "the fisrt linkmap: %#lx\n", linkmap_addr);

    char* lp = static_cast<char*>(std::malloc(sizeof(linkmap_t)));
    if (!lp) {
        fprintf(fp, "linkmap: read fail\n");
        free(core_phdr);
        munmap(exec_map, st.st_size);
        close(fd);
        return;
    }

    if (!swap_ptr->uread_buffer(tc->task, linkmap_addr, lp, sizeof(linkmap_t), "read page for linkmap")) {
        fprintf(fp, "linkmap: read fail\n");
        std::free(lp);
        std::free(core_phdr);
        munmap(exec_map, st.st_size);
        close(fd);
        return;
    }

    linkmap_t* linkmap = reinterpret_cast<linkmap_t*>(lp);
    std::ostringstream oss;
    oss << std::left
        << std::setw(20)  << "addr"
        << std::setw(20) << "ld"
        << std::setw(20) << "next"
        << std::setw(20) << "prev"
        << std::setw(20) << "name" << "\n";
    oss << std::hex;
    oss << std::setw(20) << linkmap->addr
        << std::setw(20) << linkmap->ld
        << std::setw(20) << linkmap->next
        << std::setw(20) << linkmap->prev
        << std::setw(20) << swap_ptr->uread_cstring(tc->task, linkmap->name, 128, "linkmap name")
        << "\n";

    while (linkmap->next) {
        ulong linkmap_next = linkmap->next;
        if (!is_uvaddr(linkmap_next, tc)) {
            fprintf(fp, "linkmap addr not uvaddr:%#lx\n", linkmap_next);
            break;
        }

        BZERO(lp, sizeof(linkmap_t));
        if (!swap_ptr->uread_buffer(tc->task, linkmap_next, lp, sizeof(linkmap_t), "read page for linkmap next")) {
            fprintf(fp, "linkmap: read fail\n");
            break;
        }

        linkmap = reinterpret_cast<linkmap_t*>(lp);
        oss << std::setw(20) << linkmap->addr
            << std::setw(20) << linkmap->ld
            << std::setw(20) << linkmap->next
            << std::setw(20) << linkmap->prev
            << std::setw(20) << swap_ptr->uread_cstring(tc->task, linkmap->name, 128, "linkmap name")
            << "\n";
    }
    std::free(lp);
    fprintf(fp, "%s", oss.str().c_str());

    std::free(core_phdr);
    munmap(exec_map, st.st_size);
    close(fd);
}
#pragma GCC diagnostic pop
 