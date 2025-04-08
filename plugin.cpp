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

#include "plugin.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

PaserPlugin::PaserPlugin(){
    // std::cout << "PaserPlugin" << std::endl;
    field_init(task_struct, active_mm);
    field_init(task_struct, mm);
    field_init(task_struct, tasks);
    struct_init(task_struct);

    field_init(mm_struct, pgd);
    field_init(mm_struct, arg_start);
    field_init(mm_struct, arg_end);
    if (THIS_KERNEL_VERSION < LINUX(6,1,0)){
        field_init(mm_struct, mmap);
    }else{
        field_init(mm_struct, mm_mt);
    }
    struct_init(mm_struct);

    field_init(maple_tree,ma_root);

    field_init(vm_area_struct,vm_start);
    field_init(vm_area_struct,vm_end);
    field_init(vm_area_struct,vm_flags);
    field_init(vm_area_struct, vm_next);
    struct_init(vm_area_struct);

    field_init(page, _mapcount);
    field_init(page, freelist);
    field_init(page, units);
    field_init(page, index);
    field_init(page, private);
    struct_init(page);

    field_init(list_head, prev);
    field_init(list_head, next);
    struct_init(list_head);
    if (BITS64()){
        std::string config = get_config_val("CONFIG_ARM64_VA_BITS");
        int va_bits = std::stoi(config);
        vaddr_mask = (static_cast<uint64_t>(1) << va_bits) - 1;
    }else{
        vaddr_mask = (static_cast<uint64_t>(1) << 32) - 1;
    }
    //print_table();
}

bool PaserPlugin::isNumber(const std::string& str) {
    regex_t decimal, hex;
    bool result = false;
    if (regcomp(&decimal, "^-?\\d+$", REG_EXTENDED)) {
        fprintf(fp, "Could not compile decimal regex\n");
        return false;
    }
    if (regcomp(&hex, "^0[xX][0-9a-fA-F]+$", REG_EXTENDED)) {
        fprintf(fp, "Could not compile hex regex \n");
        regfree(&decimal);
        return false;
    }
    if (!regexec(&decimal, str.c_str(), 0, NULL, 0) || !regexec(&hex, str.c_str(), 0, NULL, 0)) {
        result = true;
    }
    regfree(&decimal);
    regfree(&hex);
    return result;
}

std::string PaserPlugin::csize(size_t size){
    std::ostringstream oss;
    if (size < KB) {
        oss << size << "B";
    } else if (size < MB) {
        double sizeInKB = static_cast<double>(size) / KB;
        if (sizeInKB == static_cast<size_t>(sizeInKB)) {
            oss << static_cast<size_t>(sizeInKB) << "KB";
        } else {
            oss << std::fixed << std::setprecision(2) << sizeInKB << "KB";
        }
    } else if (size < GB) {
        double sizeInMB = static_cast<double>(size) / MB;
        if (sizeInMB == static_cast<size_t>(sizeInMB)) {
            oss << static_cast<size_t>(sizeInMB) << "MB";
        } else {
            oss << std::fixed << std::setprecision(2) << sizeInMB << "MB";
        }
    } else {
        double sizeInGB = static_cast<double>(size) / GB;
        if (sizeInGB == static_cast<size_t>(sizeInGB)) {
            oss << static_cast<size_t>(sizeInGB) << "GB";
        } else {
            oss << std::fixed << std::setprecision(2) << sizeInGB << "GB";
        }
    }
    return oss.str();
}

std::string PaserPlugin::csize(size_t size, int unit, int precision){
    std::ostringstream oss;
    if (unit == KB) {
        oss << std::fixed << std::setprecision(precision) << (size / KB) << " KB";
    } else if (unit == MB) {
        oss << std::fixed << std::setprecision(precision) << (size / MB) << " MB";
    } else if (unit == GB) {
        oss << std::fixed << std::setprecision(precision) << (size / GB) << " GB";
    } else {
        oss << size << "B";
    }
    return oss.str();
}

void PaserPlugin::initialize(void){
    cmd_help = new char*[help_str_list.size()+1];
    for (size_t i = 0; i < help_str_list.size(); ++i) {
        cmd_help[i] = TO_CONST_STRING(help_str_list[i].c_str());
    }
    cmd_help[help_str_list.size()] = nullptr;
}

void PaserPlugin::type_init(const std::string& type){
    std::string name = type;
    typetable[name] = std::make_unique<Typeinfo>(type);
}

void PaserPlugin::type_init(const std::string& type,const std::string& field){
    std::string name = type + "@" + field;
    typetable[name] = std::make_unique<Typeinfo>(type,field);
}

int PaserPlugin::type_offset(const std::string& type,const std::string& field){
    std::string name = type + "@" + field;
    auto it = typetable.find(name);
    if (it != typetable.end()) {
        return it->second->offset();
    } else {
        fprintf(fp, "Error: Typeinfo not found for %s\n",name.c_str());
        return -1;
    }
}

int PaserPlugin::type_size(const std::string& type,const std::string& field){
    std::string name = type + "@" + field;
    auto it = typetable.find(name);
    if (it != typetable.end()) {
        return it->second->size();
    } else {
        fprintf(fp, "Error: Typeinfo not found for %s\n",name.c_str());
        return -1;
    }
}

int PaserPlugin::type_size(const std::string& type){
    std::string name = type;
    auto it = typetable.find(name);
    if (it != typetable.end()) {
        return it->second->size();
    } else {
        fprintf(fp, "Error: Typeinfo not found for %s\n",name.c_str());
        return -1;
    }
}

void PaserPlugin::print_backtrace(){
    void *buffer[100];
    int nptrs = backtrace(buffer, 100);
    char **strings = backtrace_symbols(buffer, nptrs);
    if (strings == NULL) {
        fprintf(fp, "backtrace_symbols");
    }
    for (int i = 0; i < nptrs; i++) {
        fprintf(fp, "%s\n", strings[i]);
    }
    free(strings);
}

void PaserPlugin::print_table(){
    char buf[BUFSIZE];
    for (const auto& pair : typetable) {
        sprintf(buf, "%s", pair.first.c_str());
        fprintf(fp, "%s",mkstring(buf, 45, LJUST, buf));
        sprintf(buf, ": offset:%d", pair.second.get()->m_offset);
        fprintf(fp, "%s",mkstring(buf, 15, LJUST, buf));
        fprintf(fp, " size:%d\n",pair.second.get()->m_size);
    }
}

std::vector<ulong> PaserPlugin::for_each_radix(ulong root_rnode){
    std::vector<ulong> res;
    size_t entry_num = do_radix_tree(root_rnode, RADIX_TREE_COUNT, NULL);
    struct list_pair *entry_list = (struct list_pair *)GETBUF((entry_num + 1) * sizeof(struct list_pair));
    entry_list[0].index = entry_num;
    do_radix_tree(root_rnode, RADIX_TREE_GATHER, entry_list);
    for (size_t i = 0; i < entry_num; ++i){
        ulong addr = (ulong)entry_list[i].value;
        if (!is_kvaddr(addr))continue;
        res.push_back(addr);
    }
    return res;
}

std::vector<ulong> PaserPlugin::for_each_mptree(ulong maptree_addr){
    std::vector<ulong> res;
    size_t entry_num = do_maple_tree(maptree_addr, MAPLE_TREE_COUNT, NULL);
    struct list_pair *entry_list = (struct list_pair *)GETBUF(entry_num * sizeof(struct list_pair));
    do_maple_tree(maptree_addr, MAPLE_TREE_GATHER, entry_list);
    for (size_t i = 0; i < entry_num; ++i){
        ulong addr = (ulong)entry_list[i].value;
        if (!is_kvaddr(addr))continue;
        res.push_back(addr);
    }
    return res;
}

std::vector<ulong> PaserPlugin::for_each_xarray(ulong xarray_addr){
    std::vector<ulong> res;
    if (!is_kvaddr(xarray_addr))return res;
    size_t entry_num = do_xarray(xarray_addr, XARRAY_COUNT, NULL);
    struct list_pair *entry_list = (struct list_pair *)GETBUF((entry_num + 1) * sizeof(struct list_pair));
    entry_list[0].index = entry_num;
    do_xarray(xarray_addr, XARRAY_GATHER, entry_list);
    for (size_t i = 0; i < entry_num; ++i){
        ulong addr = (ulong)entry_list[i].value;
        if (!is_kvaddr(addr))continue;
        res.push_back(addr);
    }
    return res;
}

std::vector<ulong> PaserPlugin::for_each_rbtree(ulong rb_root,int offset){
    std::vector<ulong> res;
    if (!is_kvaddr(rb_root))return res;
    ulong *treeList;
    struct tree_data td;
    int cnt = 0;
    BZERO(&td, sizeof(struct tree_data));
    // td.flags |= VERBOSE | TREE_POSITION_DISPLAY | TREE_LINEAR_ORDER;
    td.flags |= TREE_NODE_POINTER;
    td.start = rb_root;
    td.node_member_offset = offset;
    hq_open();
    cnt = do_rbtree(&td);
    if(cnt==0)return res;
    treeList = (ulong *)GETBUF(cnt * sizeof(void *));
    retrieve_list(treeList, cnt);
    for (int i = 0; i < cnt; ++i) {
        if (!is_kvaddr(treeList[i]))continue;
        // LOGI("node addr:%lx\n",treeList[i]);
        treeList[i] -= td.node_member_offset;
        res.push_back(treeList[i]);
    }
    FREEBUF(treeList);
    hq_close();
    return res;
}

std::vector<ulong> PaserPlugin::for_each_list(ulong list_head,int offset){
    std::vector<ulong> res;
    fprintf(fp, "for_each_list \n");
    if (!is_kvaddr(list_head))return res;
    void *buf = read_struct(list_head,"list_head");
    if(buf == nullptr) return res;
    ulong next = ULONG(buf + field_offset(list_head,next));
    ulong prev = ULONG(buf + field_offset(list_head,prev));
    FREEBUF(buf);
    if (!next || (next == list_head)) {
        return res;
    }
    struct list_data ld;
    BZERO(&ld, sizeof(struct list_data));
    ld.flags |= LIST_ALLOCATE;
    readmem(list_head, KVADDR, &ld.start,sizeof(ulong), TO_CONST_STRING("for_each_list list_head"), FAULT_ON_ERROR);
    ld.end = list_head;
    // ld.member_offset = offset;
    ld.list_head_offset = offset;
    if (empty_list(ld.start)) return res;
    int cnt = do_list(&ld);
    if(cnt==0)return res;
    for (int i = 0; i < cnt; ++i) {
        ulong node_addr = ld.list_ptr[i];
        if (!is_kvaddr(node_addr))continue;
        res.push_back(node_addr);
    }
    FREEBUF(ld.list_ptr);
    return res;
}

std::vector<ulong> PaserPlugin::for_each_hlist(ulong hlist_head,int offset){
    std::vector<ulong> res;
    ulong first = read_pointer(hlist_head,"hlist_head");
    if (!is_kvaddr(first))return res;
    struct list_data ld;
    BZERO(&ld, sizeof(struct list_data));
    ld.flags |= LIST_ALLOCATE;
    ld.start = first;
    // ld.member_offset = offset;
    ld.list_head_offset = offset;
    if (empty_list(ld.start)) return res;
    int cnt = do_list(&ld);
    if(cnt==0)return res;
    for (int i = 0; i < cnt; ++i) {
        ulong node_addr = ld.list_ptr[i];
        if (!is_kvaddr(node_addr))continue;
        res.push_back(node_addr);
    }
    FREEBUF(ld.list_ptr);
    return res;
}

std::vector<ulong> PaserPlugin::for_each_process(){
    std::vector<ulong> res_list;
    ulong init_task = csymbol_value("init_task");
    int offset = field_offset(task_struct,tasks);
    ulong list_head_addr = init_task + offset;
    // fprintf(fp, "list_head_addr:%lx \n",list_head_addr);
    std::vector<ulong> task_list = for_each_list(list_head_addr,offset);
    for (const auto& task_addr : task_list) {
        if(task_addr == init_task)continue;
        ulong mm_struct = read_pointer(task_addr + field_offset(task_struct,mm), "task_struct_mm");
        if (mm_struct == 0)continue;
        if(!task_exists(task_addr))continue;
        if(std::find(res_list.begin(), res_list.end(), task_addr) != res_list.end())continue;
        res_list.push_back(task_addr);
    }
    return res_list;
}

std::vector<ulong> PaserPlugin::for_each_threads(){
    std::vector<ulong> task_list;
    struct task_context* tc = FIRST_CONTEXT();
    task_list.push_back(tc->task);
    for (size_t i = 0; i < RUNNING_TASKS(); i++, tc++){
        task_list.push_back(tc->task);
    }
    return task_list;
}

std::vector<ulong> PaserPlugin::for_each_vma(ulong& task_addr){
    std::vector<ulong> vma_list;
    ulong mm_addr = read_pointer(task_addr + field_offset(task_struct,mm), "task_struct_mm");
    if (!is_kvaddr(mm_addr))return vma_list;
    if (THIS_KERNEL_VERSION < LINUX(6,1,0)){
        ulong vma_addr = read_pointer(mm_addr + field_offset(mm_struct,mmap), "mm_struct_mmap");
        while (is_kvaddr(vma_addr)){
            vma_list.push_back(vma_addr);
            vma_addr = read_pointer(vma_addr + field_offset(vm_area_struct,vm_next), "vm_area_struct_next");
        }
    } else {
        ulong mm_mt_addr = mm_addr + field_offset(mm_struct,mm_mt);
        vma_list = for_each_mptree(mm_mt_addr);
    }
    return vma_list;
}

ulonglong PaserPlugin::read_structure_field(ulong addr,const std::string& type,const std::string& field,bool virt){
    int offset = type_offset(type,field);
    int size = type_size(type,field);
    std::string note = type + "_" + field;
    addr += offset;
    ulonglong result = 0;
    void *buf = (void *)GETBUF(size);
    if (!readmem(addr, (virt ? KVADDR : PHYSADDR), buf, size, TO_CONST_STRING(note.c_str()), RETURN_ON_ERROR|QUIET)) {
        fprintf(fp, "Can't read %s at %lx\n",TO_CONST_STRING(note.c_str()), addr);
        FREEBUF(buf);
        return 0;
    }
    switch(size){
        case 1:
            result = UCHAR(buf);
            break;
        case 2:
            result = USHORT(buf);
            break;
        case 4:
            result = UINT(buf);
            break;
        case 8:
            result = ULONGLONG(buf);
            break;
        default:
            result = ULONG(buf);
    }
    FREEBUF(buf);
    return result;
}

std::string PaserPlugin::read_cstring(ulong addr,int len, const std::string& note,bool virt){
    char res[len];
    if (!readmem(addr, (virt ? KVADDR : PHYSADDR), res, len, TO_CONST_STRING(note.c_str()), RETURN_ON_ERROR|QUIET)) {
        fprintf(fp, "Can't read %s at %lx\n",TO_CONST_STRING(note.c_str()), addr);
        return nullptr;
    }
    return std::string(res);
}

bool PaserPlugin::read_bool(ulong addr,const std::string& note,bool virt){
    void *buf = read_memory(addr,sizeof(bool),note,virt);
    if(buf == nullptr){
        return false;
    }
    bool res = BOOL(buf);
    FREEBUF(buf);
    return res;
}

int PaserPlugin::read_int(ulong addr,const std::string& note,bool virt){
    void *buf = read_memory(addr,sizeof(int),note,virt);
    if(buf == nullptr){
        return 0;
    }
    int res = INT(buf);
    FREEBUF(buf);
    return res;
}

uint PaserPlugin::read_uint(ulong addr,const std::string& note,bool virt){
    void *buf = read_memory(addr,sizeof(uint),note,virt);
    if(buf == nullptr){
        return 0;
    }
    uint res = UINT(buf);
    FREEBUF(buf);
    return res;
}

long PaserPlugin::read_long(ulong addr,const std::string& note,bool virt){
    void *buf = read_memory(addr,sizeof(long),note,virt);
    if(buf == nullptr){
        return 0;
    }
    long res = LONG(buf);
    FREEBUF(buf);
    return res;
}

ulong PaserPlugin::read_ulong(ulong addr,const std::string& note,bool virt){
    void *buf = read_memory(addr,sizeof(ulong),note,virt);
    if(buf == nullptr){
        return 0;
    }
    ulong res = ULONG(buf);
    FREEBUF(buf);
    return res;
}

ulonglong PaserPlugin::read_ulonglong(ulong addr,const std::string& note,bool virt){
    void *buf = read_memory(addr,sizeof(ulonglong),note,virt);
    if(buf == nullptr){
        return 0;
    }
    ulonglong res = ULONGLONG(buf);
    FREEBUF(buf);
    return res;
}

ushort PaserPlugin::read_ushort(ulong addr,const std::string& note,bool virt){
    void *buf = read_memory(addr,sizeof(ushort),note,virt);
    if(buf == nullptr){
        return 0;
    }
    ushort res = USHORT(buf);
    FREEBUF(buf);
    return res;
}

short PaserPlugin::read_short(ulong addr,const std::string& note,bool virt){
    void *buf = read_memory(addr,sizeof(short),note,virt);
    if(buf == nullptr){
        return 0;
    }
    short res = SHORT(buf);
    FREEBUF(buf);
    return res;
}

void* PaserPlugin::read_memory(ulong addr,int len, const std::string& note, bool virt){
    void* buf = (void *)GETBUF(len);
    if (!readmem(addr, (virt ? KVADDR : PHYSADDR), buf, len, TO_CONST_STRING(note.c_str()), RETURN_ON_ERROR|QUIET)) {
        fprintf(fp, "Can't read %s at %lx\n",TO_CONST_STRING(note.c_str()), addr);
        FREEBUF(buf);
        return nullptr;
    }
    return buf;
}

void* PaserPlugin::read_struct(ulong addr,const std::string& type,bool virt){
    int size = type_size(type);
    void* buf = (void *)GETBUF(size);
    if (!readmem(addr, (virt ? KVADDR : PHYSADDR), buf, size, TO_CONST_STRING(type.c_str()), RETURN_ON_ERROR|QUIET)) {
        fprintf(fp, "Can't read %s at %lx\n",TO_CONST_STRING(type.c_str()),addr);
        FREEBUF(buf);
        return nullptr;
    }
    return buf;
}

bool PaserPlugin::read_struct(ulong addr,void* buf, int len, const std::string& note,bool virt){
    if (!readmem(addr, (virt ? KVADDR : PHYSADDR), buf, len, TO_CONST_STRING(note.c_str()), RETURN_ON_ERROR|QUIET)) {
        fprintf(fp, "Can't read %s at %lx\n",TO_CONST_STRING(note.c_str()),addr);
        return false;
    }
    return true;
}

ulong PaserPlugin::read_pointer(ulong addr, const std::string& note,bool virt){
    void *buf = read_memory(addr,sizeof(void *),note,virt);
    if(buf == nullptr){
        return 0;
    }
    ulong res = (ulong)VOID_PTR(buf);
    FREEBUF(buf);
    return res;
}

unsigned char PaserPlugin::read_byte(ulong addr, const std::string& note,bool virt){
    unsigned char val;
    if (!readmem(addr, (virt ? KVADDR : PHYSADDR), &val, 1, TO_CONST_STRING(note.c_str()), RETURN_ON_ERROR|QUIET)) {
        fprintf(fp, "Can't read %s at %lx\n",TO_CONST_STRING(note.c_str()), addr);
        return -1;
    }
    return val;
}

int PaserPlugin::csymbol_exists(const std::string& note){
    return symbol_exists(TO_CONST_STRING(note.c_str()));
}

ulong PaserPlugin::csymbol_value(const std::string& note){
    return symbol_value(TO_CONST_STRING(note.c_str()));
}

bool PaserPlugin::is_kvaddr(ulong addr){
    return IS_KVADDR(addr);
}

bool PaserPlugin::is_uvaddr(ulong addr, struct task_context* tc){
    return IS_UVADDR(addr,tc);
}

int PaserPlugin::page_to_nid(ulong page){
    int i;
    struct node_table *nt;
    physaddr_t paddr = page_to_phy(page);
    if (paddr == 0){
        return -1;
    }
    for (i = 0; i < vt->numnodes; i++){
        nt = &vt->node_table[i];
        physaddr_t end_paddr = nt->start_paddr + ((physaddr_t)nt->size * (physaddr_t)page_size);
        if ((paddr >= nt->start_paddr) && (paddr < end_paddr)){
            return i;
        }
    }
    return -1;
}

ulong PaserPlugin::virt_to_phy(ulong vaddr){
    return VTOP(vaddr);
}

ulong PaserPlugin::phy_to_virt(ulong paddr){
    return PTOV(paddr);
}

ulong PaserPlugin::phy_to_pfn(ulong paddr){
    return BTOP(paddr);
}

physaddr_t PaserPlugin::pfn_to_phy(ulong pfn){
    return PTOB(pfn);
}

ulong PaserPlugin::page_to_pfn(ulong page){
    return phy_to_pfn(page_to_phy(page));
}

ulong PaserPlugin::pfn_to_page(ulong pfn){
    return phy_to_page(pfn_to_phy(pfn));
}

ulong PaserPlugin::phy_to_page(ulong paddr){
    ulong page;
    if(phys_to_page(paddr, &page)){
        return page;
    }
    return 0;
}

physaddr_t PaserPlugin::page_to_phy(ulong page){
    physaddr_t paddr = 0;
    if (is_page_ptr(page, &paddr)){
        return paddr;
    }
    return 0;
}

std::string PaserPlugin::get_config_val(const std::string& conf_name){
    char *config_val;
    if (get_kernel_config(TO_CONST_STRING(conf_name.c_str()),&config_val) != IKCONFIG_N){
        std::string val(config_val);
        return val;
    }else{
        return "n";
    }
}

void PaserPlugin::cfill_pgd(ulonglong pgd, int type, ulong size){
    if (!IS_LAST_PGD_READ(pgd)) {
        readmem(pgd, type, machdep->pgd, size, TO_CONST_STRING("pgd page"), FAULT_ON_ERROR);
        machdep->last_pgd_read = (ulong)(pgd);
    }
}

void PaserPlugin::cfill_pmd(ulonglong pmd, int type, ulong size){
    if (!IS_LAST_PMD_READ(pmd)) {
        readmem(pmd, type, machdep->pmd, size, TO_CONST_STRING("pmd page"), FAULT_ON_ERROR);
        machdep->last_pmd_read = (ulong)(pmd);
    }
}

void PaserPlugin::cfill_ptbl(ulonglong ptbl, int type, ulong size){
    if (!IS_LAST_PTBL_READ(ptbl)) {
        readmem(ptbl, type, machdep->ptbl, size, TO_CONST_STRING("page table"), FAULT_ON_ERROR);
        machdep->last_ptbl_read = (ulong)(ptbl);
    }
}

// maybe we can refer to symbols.c is_binary_stripped
bool PaserPlugin::is_binary_stripped(std::string& filename){
    std::string command = "readelf -s " + filename;
    FILE *pipe = popen(command.c_str(), "r");
    if (!pipe) {
        fprintf(fp, "Failed to run readelf command. \n");
        return false;
    }
    std::string output;
    char buffer[BUFSIZE];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        output += buffer;
    }
    pclose(pipe);
    return output.find("Symbol table '.symtab' contains") == std::string::npos;
}

bool PaserPlugin::add_symbol_file(std::string& filename){
    if(is_elf_file(TO_CONST_STRING(filename.c_str())) && is_binary_stripped(filename)){
        fprintf(fp, "This file is not symbols file \n");
        return false;
    }
    char buf[BUFSIZE];
    sprintf(buf, "add-symbol-file %s", filename.c_str());
    if(!gdb_pass_through(buf, NULL, GNU_RETURN_ON_ERROR)){
        return false;
    }
    return true;
}

void PaserPlugin::verify_userspace_symbol(std::string& symbol_name){
    char buf[BUFSIZE];
    sprintf(buf, "ptype %s", symbol_name.c_str());
    if(!gdb_pass_through(buf, NULL, GNU_RETURN_ON_ERROR)){
        fprintf(fp, "verify_userspace_symbol: %s failed \n", symbol_name.c_str());
    }
}

std::string PaserPlugin::extract_string(const char *input) {
    std::string result;
    const char *ptr = input;
    while (*ptr != '\0') {
        if (!result.empty()) {
            result += ' ';
        }
        result += std::string(ptr);
        ptr += strlen(ptr) + 1;
    }
    return result;
}

int PaserPlugin::is_bigendian(void){
    int i = 0x12345678;
    if (*(char *)&i == 0x12)
        return TRUE;
    else
        return FALSE;
}

long PaserPlugin::read_enum_val(const std::string& enum_name){
     long enum_val = 0;
     enumerator_value(TO_CONST_STRING(enum_name.c_str()), &enum_val);
     return enum_val;
}

char PaserPlugin::get_printable(uint8_t d) {
    return std::isprint(d) ? static_cast<char>(d) : '.';
}

std::string PaserPlugin::print_line(uint64_t addr, const std::vector<uint8_t>& data) {
    std::vector<char> printable;
    std::vector<std::string> data_hex;
    for (uint8_t d : data) {
        printable.push_back(get_printable(d));
        char hex[3];
        snprintf(hex, sizeof(hex), "%02x", d);
        data_hex.push_back(hex);
    }
    while (printable.size() < 16) {
        printable.push_back(' ');
        data_hex.push_back("  ");
    }
    std::ostringstream oss;
    oss << std::setw(8) << std::setfill('0') << std::hex << addr << ": ";
    for (size_t i = 0; i < 16; ++i) {
        if (i % 2 == 0 && i > 0) {
            oss << " ";
        }
        oss << data_hex[i];
    }
    oss << " ";
    for (char c : printable) {
        oss << c;
    }
    oss << "\n";
    return oss.str();
}

std::string PaserPlugin::hexdump(uint64_t addr, const char* buf, size_t length, bool little_endian) {
    std::ostringstream sio;
    std::vector<uint8_t> data_list;
    if (little_endian) {
        data_list.assign(reinterpret_cast<const uint8_t*>(buf), reinterpret_cast<const uint8_t*>(buf) + length);
    } else {
        std::vector<size_t> places;
        for (size_t i = 0; i < length / 4; ++i) {
            places.push_back((i + 1) * 4 - 1);
            places.push_back((i + 1) * 4 - 2);
            places.push_back((i + 1) * 4 - 3);
            places.push_back(i * 4);
        }
        for (const auto& i : places) {
            data_list.push_back(static_cast<uint8_t>(buf[i]));
        }
    }
    uint64_t address = addr;
    std::vector<uint8_t> bb;
    size_t n = 0;
    for (uint8_t i : data_list) {
        bb.push_back(i);
        if (n == 15) {
            sio << print_line(address, bb);
            bb.clear();
            n = 0;
            address += 16;
        } else {
            ++n;
        }
    }
    if (!bb.empty()) {
        sio << print_line(address, bb);
    }
    return sio.str();
}

#if defined(ARM)
ulong* PaserPlugin::pmd_page_addr(ulong pmd){
    ulong ptr;
    if (machdep->flags & PGTABLE_V2) {
        ptr = PAGEBASE(pmd);
    } else {
        ptr = pmd & ~(PTRS_PER_PTE * sizeof(void *) - 1);
        ptr += PTRS_PER_PTE * sizeof(void *);
    }
    return (ulong *)ptr;
}

ulong PaserPlugin::get_arm_pte(ulong task_addr, ulong page_vaddr){
    char buf[BUFSIZE];
    int verbose = 0;
    ulong *pgd;
    ulong *page_dir;
    ulong *page_middle;
    ulong *page_table;
    ulong pgd_pte;
    ulong pmd_pte;
    ulong pte;
    struct task_context *tc = task_to_context(task_addr);
    #define PGDIR_SIZE() (4 * PAGESIZE())
    #define PGDIR_OFFSET(X) (((ulong)(X)) & (PGDIR_SIZE() - 1))
    /*
     * Before idmap_pgd was introduced with upstream commit 2c8951ab0c
     * (ARM: idmap: use idmap_pgd when setting up mm for reboot), the
     * panic task pgd was overwritten by soft reboot code, so we can't do
     * any vtop translations.
     */
    if (!(machdep->flags & IDMAP_PGD) && tc->task == tt->panic_task){
        fprintf(fp,  TO_CONST_STRING("panic task pgd is trashed by soft reboot code\n"));
    }
    if (is_kernel_thread(tc->task) && IS_KVADDR(page_vaddr)) {
        ulong active_mm = read_structure_field(tc->task,"task_struct","active_mm");
        if (!active_mm){
            fprintf(fp,  TO_CONST_STRING("no active_mm for this kernel thread\n"));
        }
        pgd = ULONG_PTR(read_structure_field(active_mm,"mm_struct","pgd"));
    } else {
        ulong mm = task_mm(tc->task, TRUE);
        if (mm){
            pgd = ULONG_PTR(tt->mm_struct + field_offset(mm_struct, pgd));
        }else{
            pgd = ULONG_PTR(read_structure_field(tc->mm_struct,"mm_struct","pgd"));
        }
    }
    if (verbose){
        fprintf(fp, "PAGE DIRECTORY: %lx\n", (ulong)pgd);
    }
    /*
     * pgd_offset(pgd, vaddr)
     */
    page_dir = pgd + PGD_OFFSET(page_vaddr) * 2;
    /* The unity-mapped region is mapped using 1MB pages,
     * hence 1-level translation if bit 20 is set; if we
     * are 1MB apart physically, we move the page_dir in
     * case bit 20 is set.
     */
    if (((page_vaddr) >> (20)) & 1){
        page_dir = page_dir + 1;
    }
    cfill_pgd(PAGEBASE(pgd), KVADDR, PGDIR_SIZE());
    pgd_pte = ULONG(machdep->pgd + PGDIR_OFFSET(page_dir));
    if (verbose){
        fprintf(fp, "  PGD: %s => %lx\n",mkstring(buf, VADDR_PRLEN, RJUST | LONG_HEX,MKSTR((ulong)page_dir)), pgd_pte);
    }
    if (!pgd_pte){
        return 0;
    }
    /*
     * pmd_offset(pgd, vaddr)
     *
     * Here PMD is folded into a PGD.
     */
    pmd_pte = pgd_pte;
    page_middle = page_dir;
    if (verbose){
        fprintf(fp, "  PMD: %s => %lx\n",mkstring(buf, VADDR_PRLEN, RJUST | LONG_HEX,MKSTR((ulong)page_middle)), pmd_pte);
    }
    /*
     * pte_offset_map(pmd, vaddr)
     */
    page_table = pmd_page_addr(pmd_pte) + PTE_OFFSET(page_vaddr);
    cfill_ptbl(PAGEBASE(page_table), PHYSADDR, PAGESIZE());
    pte = ULONG(machdep->ptbl + PAGEOFFSET(page_table));
    if (verbose) {
        fprintf(fp, "  PTE: %s => %lx\n\n",mkstring(buf, VADDR_PRLEN, RJUST | LONG_HEX,MKSTR((ulong)page_table)), pte);
    }
    return pte;
}
#endif

bool PaserPlugin::load_symbols(std::string& path, std::string name){
    if (is_directory(TO_CONST_STRING(path.c_str()))){
        char * buf = search_directory_tree(TO_CONST_STRING(path.c_str()), TO_CONST_STRING(name.c_str()), 1);
        if (buf){
            std::string retbuf(buf);
            if (is_elf_file(TO_CONST_STRING(retbuf.c_str())) && add_symbol_file(retbuf)){
                // fprintf(fp, "Add symbol:%s succ \n",retbuf.c_str());
                path = retbuf;
                return true;
            }
        }
    }else if (file_exists(TO_CONST_STRING(path.c_str()), NULL) && is_elf_file(TO_CONST_STRING(path.c_str()))){
        if (add_symbol_file(path)){
            // fprintf(fp, "Add symbol:%s succ \n",path.c_str());
            return true;
        }
    }
    return false;
}
#pragma GCC diagnostic pop
