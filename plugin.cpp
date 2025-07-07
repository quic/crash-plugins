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

ParserPlugin::ParserPlugin(){
    field_init(task_struct, active_mm);
    field_init(task_struct, mm);
    field_init(task_struct, tasks);
    struct_init(task_struct);
    field_init(task_struct,files);
    field_init(files_struct,fdt);
    field_init(fdtable,max_fds);
    field_init(fdtable,fd);
    field_init(mm_struct, pgd);
    field_init(mm_struct, arg_start);
    field_init(mm_struct, arg_end);
    field_init(mm_struct, mmap);
    field_init(mm_struct, mm_mt);
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
    field_init(page, page_type);
    field_init(page, _count);
    field_init(page, _refcount);
    field_init(page, mapping);
    struct_init(page);
    field_init(address_space,host);
    field_init(address_space,a_ops);
    field_init(address_space,nrpages);
    field_init(address_space,i_pages);
    field_init(address_space,page_tree);
    struct_init(address_space);
    field_init(inode,i_mapping);
    field_init(list_head, prev);
    field_init(list_head, next);
    struct_init(list_head);
    field_init(driver_private,driver);
    field_init(driver_private,klist_devices);
    field_init(driver_private,knode_bus);
    field_init(device_private,knode_bus);
    field_init(device_private,device);
    field_init(device_private,knode_driver);
    field_init(device_private,knode_class);
    field_init(subsys_private,klist_drivers);
    field_init(subsys_private,klist_devices);
    field_init(subsys_private,bus);
    field_init(subsys_private,subsys);
    field_init(subsys_private,class);
    field_init(klist_node, n_node);
    field_init(klist,k_list);
    field_init(device_driver,p);
    field_init(bus_type,p);
    field_init(class,p);
    field_init(class,name);
    field_init(bus_type,name);
    field_init(kset,kobj);
    field_init(kset,list);
    field_init(kobject, entry);
    field_init(char_device_struct,next);
    field_init(char_device_struct,cdev);
    field_init(char_device_struct,name);
    field_init(miscdevice,list);
    if (BITS64()){
        std::string config = get_config_val("CONFIG_ARM64_VA_BITS");
        int va_bits = std::stoi(config);
        kaddr_mask = GENMASK_ULL((va_bits ? va_bits : 39) - 1, 0);
    }else{
        kaddr_mask = GENMASK_ULL(32 - 1, 0);
    }
    //print_table();
}

bool ParserPlugin::isNumber(const std::string& str) {
    regex_t decimal, hex;
    bool result = false;
    if (regcomp(&decimal, "^-?[0-9]+$", REG_EXTENDED)) {
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

std::string ParserPlugin::csize(uint64_t size){
    std::ostringstream oss;
    if (size < KB) {
        oss << size << "B";
    } else if (size < MB) {
        double sizeInKB = static_cast<double>(size) / KB;
        if (sizeInKB == static_cast<uint64_t>(sizeInKB)) {
            oss << static_cast<uint64_t>(sizeInKB) << "KB";
        } else {
            oss << std::fixed << std::setprecision(2) << sizeInKB << "KB";
        }
    } else if (size < GB) {
        double sizeInMB = static_cast<double>(size) / MB;
        if (sizeInMB == static_cast<uint64_t>(sizeInMB)) {
            oss << static_cast<uint64_t>(sizeInMB) << "MB";
        } else {
            oss << std::fixed << std::setprecision(2) << sizeInMB << "MB";
        }
    } else {
        double sizeInGB = static_cast<double>(size) / GB;
        if (sizeInGB == static_cast<uint64_t>(sizeInGB)) {
            oss << static_cast<uint64_t>(sizeInGB) << "GB";
        } else {
            oss << std::fixed << std::setprecision(2) << sizeInGB << "GB";
        }
    }
    return oss.str();
}

std::string ParserPlugin::csize(uint64_t size, int unit, int precision){
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

struct task_context* ParserPlugin::find_proc(ulong pid){
    for(ulong task_addr: for_each_process()){
        struct task_context *tc = task_to_context(task_addr);
        if (!tc){
            continue;
        }
        if (tc->pid == pid){
            return tc;
        }
    }
    return nullptr;
}

struct task_context* ParserPlugin::find_proc(std::string name){
    for(ulong task_addr: for_each_process()){
        struct task_context *tc = task_to_context(task_addr);
        if (!tc){
            continue;
        }
        std::string comm = tc->comm;
        if (comm == name){
            return tc;
        }
    }
    return nullptr;
}

bool ParserPlugin::page_buddy(ulong page_addr){
    if (THIS_KERNEL_VERSION >= LINUX(4, 19, 0)){
        uint page_type = read_uint(page_addr + field_offset(page,page_type),"page_type");
        return ((page_type & 0xf0000080) == 0xf0000000);
    }else{
        uint mapcount = read_int(page_addr + field_offset(page,_mapcount),"_mapcount");
        return (mapcount == 0xffffff80);
    }
}

int ParserPlugin::page_count(ulong page_addr){
    int count = 0;
    if (THIS_KERNEL_VERSION < LINUX(4, 6, 0)){
        count = read_int(page_addr + field_offset(page,_count),"_count");
    }else{
        count = read_int(page_addr + field_offset(page,_refcount),"_refcount");
    }
    return count;
}

void ParserPlugin::initialize(void){
    cmd_help = new char*[help_str_list.size()+1];
    for (size_t i = 0; i < help_str_list.size(); ++i) {
        cmd_help[i] = TO_CONST_STRING(help_str_list[i].c_str());
    }
    cmd_help[help_str_list.size()] = nullptr;
}

void ParserPlugin::type_init(const std::string& type){
    std::string name = type;
    typetable[name] = std::make_unique<Typeinfo>(type);
}

void ParserPlugin::type_init(const std::string& type,const std::string& field){
    std::string name = type + "@" + field;
    typetable[name] = std::make_unique<Typeinfo>(type,field);
}

int ParserPlugin::type_offset(const std::string& type,const std::string& field){
    std::string name = type + "@" + field;
    auto it = typetable.find(name);
    if (it != typetable.end()) {
        return it->second->offset();
    } else {
        fprintf(fp, "Error: Typeinfo not found for %s\n",name.c_str());
        return -1;
    }
}

int ParserPlugin::type_size(const std::string& type,const std::string& field){
    std::string name = type + "@" + field;
    auto it = typetable.find(name);
    if (it != typetable.end()) {
        return it->second->size();
    } else {
        fprintf(fp, "Error: Typeinfo not found for %s\n",name.c_str());
        return -1;
    }
}

int ParserPlugin::type_size(const std::string& type){
    std::string name = type;
    auto it = typetable.find(name);
    if (it != typetable.end()) {
        return it->second->size();
    } else {
        fprintf(fp, "Error: Typeinfo not found for %s\n",name.c_str());
        return -1;
    }
}

void ParserPlugin::print_backtrace(){
    void *buffer[100];
    int nptrs = backtrace(buffer, 100);
    char **strings = backtrace_symbols(buffer, nptrs);
    if (strings == NULL) {
        fprintf(fp, "backtrace_symbols");
    }
    for (int i = 0; i < nptrs; i++) {
        fprintf(fp, "%s\n", strings[i]);
    }
    std::free(strings);
}

void ParserPlugin::print_table(){
    char buf[BUFSIZE];
    for (const auto& pair : typetable) {
        sprintf(buf, "%s", pair.first.c_str());
        fprintf(fp, "%s",mkstring(buf, 45, LJUST, buf));
        sprintf(buf, ": offset:%d", pair.second.get()->m_offset);
        fprintf(fp, "%s",mkstring(buf, 15, LJUST, buf));
        fprintf(fp, " size:%d\n",pair.second.get()->m_size);
    }
}

std::vector<ulong> ParserPlugin::for_each_pfn(){
    ulong max_pfn;
    ulong min_low_pfn;
    std::vector<ulong> res;
    /* max_pfn */
    if (csymbol_exists("max_pfn")){
        try_get_symbol_data(TO_CONST_STRING("max_pfn"), sizeof(ulong), &max_pfn);
    }
    /* min_low_pfn */
    if (csymbol_exists("min_low_pfn")){
        try_get_symbol_data(TO_CONST_STRING("min_low_pfn"), sizeof(ulong), &min_low_pfn);
    }
    for (size_t pfn = min_low_pfn; pfn < max_pfn; pfn++){
        res.push_back(pfn);
    }
    return res;
}

std::vector<ulong> ParserPlugin::for_each_inode(){
    std::set<ulong> inode_list;
    for (const auto& page : for_each_file_page()) {
        ulong mapping = read_pointer(page + field_offset(page,mapping),"mapping");
        ulong inode = read_pointer(mapping + field_offset(address_space,host),"host");
        if (!is_kvaddr(inode)){
            continue;
        }
        ulong ops = read_pointer(mapping + field_offset(address_space,a_ops),"a_ops");
        if (!is_kvaddr(ops)){
            continue;
        }
        ulong i_mapping = read_pointer(inode + field_offset(inode,i_mapping),"i_mapping");
        if (!is_kvaddr(i_mapping) && mapping != i_mapping){
            continue;
        }
        inode_list.insert(inode);
    }
    std::vector<ulong> res(inode_list.begin(), inode_list.end());
    return res;
}

std::vector<ulong> ParserPlugin::for_each_file_page(){
    std::vector<ulong> res;
    for (const auto& pfn : for_each_pfn()) {
        ulong page = pfn_to_page(pfn);
        if (!is_kvaddr(page)){
            continue;
        }
        if(page_buddy(page) || page_count(page) == 0){
            continue;
        }
        ulong mapping = read_pointer(page + field_offset(page,mapping),"mapping");
        if (!is_kvaddr(mapping)){
            continue;
        }
        if((mapping & 0x1) == 1){ // skip anon page
            continue;
        }
        res.push_back(page);
    }
    return res;
}

std::vector<ulong> ParserPlugin::for_each_anon_page(){
    std::vector<ulong> res;
    for (const auto& pfn : for_each_pfn()) {
        ulong page = pfn_to_page(pfn);
        if (!is_kvaddr(page)){
            continue;
        }
        if(page_buddy(page) || page_count(page) == 0){
            continue;
        }
        ulong mapping = read_pointer(page + field_offset(page,mapping),"mapping");
        if (!is_kvaddr(mapping)){
            continue;
        }
        if((mapping & 0x1) == 0){ // skip file page
            continue;
        }
        res.push_back(page);
    }
    return res;
}

std::vector<ulong> ParserPlugin::for_each_radix(ulong root_rnode){
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

std::vector<ulong> ParserPlugin::for_each_mptree(ulong maptree_addr){
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

std::vector<ulong> ParserPlugin::for_each_xarray(ulong xarray_addr){
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

std::vector<ulong> ParserPlugin::for_each_rbtree(ulong rb_root,int offset){
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
        treeList[i] -= td.node_member_offset;
        res.push_back(treeList[i]);
    }
    FREEBUF(treeList);
    hq_close();
    return res;
}

std::vector<ulong> ParserPlugin::for_each_list(ulong list_head,int offset){
    std::vector<ulong> res;
    if (!is_kvaddr(list_head))return res;
    void *buf = read_struct(list_head,"list_head");
    if(buf == nullptr) return res;
    ulong next = ULONG(buf + field_offset(list_head,next));
    FREEBUF(buf);
    if (!next || (next == list_head)) {
        return res;
    }
    struct list_data ld;
    BZERO(&ld, sizeof(struct list_data));
    ld.flags |= LIST_ALLOCATE;
    /*
    case : invalid list entry: 4000000000000000
    readflag = ld->flags & RETURN_ON_LIST_ERROR ? (RETURN_ON_ERROR|QUIET) : FAULT_ON_ERROR; in tools.c
    Even if the list is incomplete, we should ensure that the existing elements can be used normally.
    */
    // ld.flags |= RETURN_ON_LIST_ERROR;
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

std::vector<ulong> ParserPlugin::for_each_hlist(ulong hlist_head,int offset){
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

std::vector<ulong> ParserPlugin::for_each_process(){
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

std::vector<ulong> ParserPlugin::for_each_threads(){
    std::vector<ulong> task_list;
    struct task_context* tc = FIRST_CONTEXT();
    task_list.push_back(tc->task);
    for (size_t i = 0; i < RUNNING_TASKS(); i++, tc++){
        task_list.push_back(tc->task);
    }
    return task_list;
}

std::vector<ulong> ParserPlugin::for_each_vma(ulong& task_addr){
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

std::vector<ulong> ParserPlugin::for_each_char_device(){
    std::vector<ulong> chardev_list;
    if (!csymbol_exists("chrdevs")){
        return chardev_list;
    }
    size_t len = get_array_length(TO_CONST_STRING("chrdevs"), NULL, 0);
    ulong devs_addr = csymbol_value("chrdevs");
    for (size_t i = 0; i < len; i++){
        ulong chardev_addr = read_pointer(devs_addr + (i * sizeof(void *)),"chardev_addr");
        if (!is_kvaddr(chardev_addr)){
            continue;
        }
        ulong next_dev_addr = chardev_addr;
        while (is_kvaddr(next_dev_addr)){
            chardev_list.push_back(next_dev_addr);
            next_dev_addr = read_pointer(next_dev_addr + field_offset(char_device_struct,next),"next");
        }
    }
    return chardev_list;
}

std::vector<ulong> ParserPlugin::for_each_kobj_map(std::string map_name){
    std::vector<ulong> dev_list;
    if (!csymbol_exists(map_name)){
        return dev_list;
    }
    field_init(kobj_map, probes);
    field_init(probe, data);
    field_init(probe, next);
    size_t len = field_size(kobj_map,probes)/sizeof(void *);
    ulong map_addr = read_pointer(csymbol_value(map_name),"map addr");
    if (!is_kvaddr(map_addr)){
        return dev_list;
    }
    for (size_t i = 0; i < len; i++){
        ulong probe_addr = read_pointer(map_addr + (i * sizeof(void *)),"probe_addr");
        if (!is_kvaddr(probe_addr)){
            continue;
        }
        ulong next_addr = probe_addr;
        while (is_kvaddr(next_addr)){
            ulong data = read_pointer(next_addr + field_offset(probe,data),"data");
            if (is_kvaddr(data)){
                dev_list.push_back(data);
            }
            next_addr = read_pointer(next_addr + field_offset(probe,next),"next");
        }
    }
    return dev_list;
}

std::vector<ulong> ParserPlugin::for_each_cdev(){
    return for_each_kobj_map("cdev_map");
}

std::vector<ulong> ParserPlugin::get_disk_by_bdevmap(){
    return for_each_kobj_map("bdev_map");
}

std::vector<ulong> ParserPlugin::get_disk_by_block_device(){
    std::vector<ulong> dev_list;
    field_init(block_device, bd_disk);
    if (field_offset(block_device, bd_disk) == -1){
        return dev_list;
    }
    for (auto& addr : for_each_block_device()) {
        ulong bd_disk = read_pointer(addr + field_offset(block_device,bd_disk),"bd_disk");
        if (!is_kvaddr(bd_disk)) continue;
        dev_list.push_back(bd_disk);
    }
    return dev_list;
}

std::vector<ulong> ParserPlugin::for_each_disk(){
    std::vector<ulong> dev_list = get_disk_by_bdevmap();
    if (dev_list.size() == 0){
        dev_list = get_disk_by_block_device();
    }
    return dev_list;
}

std::vector<ulong> ParserPlugin::get_block_device_by_bdevs(){
    std::vector<ulong> dev_list;
    if (!csymbol_exists("all_bdevs")){
        return dev_list;
    }
    field_init(block_device, bd_list);
    for (const auto& addr : for_each_list(csymbol_value("all_bdevs"), field_offset(block_device, bd_list))) {
        if (!is_kvaddr(addr)) continue;
        dev_list.push_back(addr);
    }
    return dev_list;
}

std::vector<ulong> ParserPlugin::get_block_device_by_class(){
    std::vector<ulong> dev_list;
    field_init(block_device, bd_device);
    if (field_offset(block_device, bd_device) == -1){
        return dev_list;
    }
    for (const auto& addr : for_each_device_for_class("block")) {
        ulong bd_addr = addr - field_offset(block_device, bd_device);
        if (!is_kvaddr(bd_addr)) continue;
        dev_list.push_back(bd_addr);
    }
    return dev_list;
}

std::vector<ulong> ParserPlugin::get_block_device_by_bdevfs(){
    std::vector<ulong> dev_list;
    if (!csymbol_exists("blockdev_superblock")){
        return dev_list;
    }
    field_init(super_block, s_inodes);
    field_init(inode, i_sb_list);
    field_init(bdev_inode, vfs_inode);
    field_init(bdev_inode, bdev);
    ulong sb_addr = read_pointer(csymbol_value("blockdev_superblock"),"blockdev_superblock");
    ulong list_head = sb_addr + field_offset(super_block, s_inodes);
    for (const auto& addr : for_each_list(list_head, field_offset(inode, i_sb_list))) {
        ulong bd_addr = addr - field_offset(bdev_inode, vfs_inode) + field_offset(bdev_inode, bdev);
        if (!is_kvaddr(bd_addr)) continue;
        dev_list.push_back(bd_addr);
    }
    return dev_list;
}

std::vector<ulong> ParserPlugin::for_each_block_device(){
    std::vector<ulong> dev_list = get_block_device_by_bdevs();
    if (dev_list.size() == 0){
        dev_list = get_block_device_by_class();
    }else if (dev_list.size() == 0){
        dev_list = get_block_device_by_bdevfs();
    }
    return dev_list;
}

std::vector<ulong> ParserPlugin::for_each_misc_device(){
    std::vector<ulong> dev_list;
    if (!csymbol_exists("misc_list")){
        return dev_list;
    }
    for (const auto& addr : for_each_list(csymbol_value("misc_list"), field_offset(miscdevice, list))) {
        if (!is_kvaddr(addr)) continue;
        dev_list.push_back(addr);
    }
    return dev_list;
}

std::vector<ulong> ParserPlugin::for_each_class(){
    std::vector<ulong> class_list;
    if (!csymbol_exists("class_kset")){
        return class_list;
    }
    size_t class_kset_addr = read_pointer(csymbol_value("class_kset"),"class_kset");
    if (!is_kvaddr(class_kset_addr)) {
        return class_list;
    }
    size_t list_head = class_kset_addr + field_offset(kset,list);
    for (const auto& kobject_addr : for_each_list(list_head,field_offset(kobject, entry))) {
        size_t kset_addr = kobject_addr - field_offset(kset,kobj);
        if (!is_kvaddr(kset_addr)) continue;
        size_t subsys_addr = kset_addr - field_offset(subsys_private,subsys);
        if (!is_kvaddr(subsys_addr)) continue;
        size_t class_addr = read_pointer(subsys_addr + field_offset(subsys_private,class),"class");
        if (!is_kvaddr(class_addr)) continue;
        class_list.push_back(class_addr);
    }
    return class_list;
}

std::vector<ulong> ParserPlugin::for_each_bus(){
    std::vector<ulong> bus_list;
    if (!csymbol_exists("bus_kset")){
        return bus_list;
    }
    size_t bus_kset_addr = read_pointer(csymbol_value("bus_kset"),"bus_kset");
    if (!is_kvaddr(bus_kset_addr)) {
        return bus_list;
    }
    size_t list_head = bus_kset_addr + field_offset(kset,list);
    for (const auto& kobject_addr : for_each_list(list_head,field_offset(kobject, entry))) {
        size_t kset_addr = kobject_addr - field_offset(kset,kobj);
        if (!is_kvaddr(kset_addr)) continue;
        size_t subsys_addr = kset_addr - field_offset(subsys_private,subsys);
        if (!is_kvaddr(subsys_addr)) continue;
        size_t bus_addr = read_pointer(subsys_addr + field_offset(subsys_private,bus),"bus_type");
        if (!is_kvaddr(bus_addr)) continue;
        bus_list.push_back(bus_addr);
    }
    return bus_list;
}

ulong ParserPlugin::get_class_subsys_private(std::string class_name){
    if (!csymbol_exists("class_kset")){
        return 0;
    }
    size_t class_kset_addr = read_pointer(csymbol_value("class_kset"),"class_kset");
    if (!is_kvaddr(class_kset_addr)) {
        return 0;
    }
    size_t list_head = class_kset_addr + field_offset(kset,list);
    for (const auto& kobject_addr : for_each_list(list_head,field_offset(kobject, entry))) {
        size_t kset_addr = kobject_addr - field_offset(kset,kobj);
        if (!is_kvaddr(kset_addr)) continue;
        size_t subsys_addr = kset_addr - field_offset(subsys_private,subsys);
        if (!is_kvaddr(subsys_addr)) continue;
        size_t class_addr = read_pointer(subsys_addr + field_offset(subsys_private,class),"class");
        if (!is_kvaddr(class_addr)) continue;
        std::string name;
        size_t name_addr = read_pointer(class_addr + field_offset(class,name),"name addr");
        if (is_kvaddr(name_addr)){
            name = read_cstring(name_addr,64, "class name");
        }
        if (name.empty() || name != class_name){
            continue;
        }
        size_t private_addr = 0;
        if (field_offset(class,p) != -1){
            private_addr = read_pointer(class_addr + field_offset(class,p),"subsys_private");
        }else{
            private_addr = subsys_addr;
        }
        return private_addr;
    }
    return 0;
}

ulong ParserPlugin::get_bus_subsys_private(std::string bus_name){
    if (!csymbol_exists("bus_kset")){
        return 0;
    }
    size_t bus_kset_addr = read_pointer(csymbol_value("bus_kset"),"bus_kset");
    if (!is_kvaddr(bus_kset_addr)) {
        return 0;
    }
    size_t list_head = bus_kset_addr + field_offset(kset,list);
    for (const auto& kobject_addr : for_each_list(list_head,field_offset(kobject, entry))) {
        size_t kset_addr = kobject_addr - field_offset(kset,kobj);
        if (!is_kvaddr(kset_addr)) continue;
        size_t subsys_addr = kset_addr - field_offset(subsys_private,subsys);
        if (!is_kvaddr(subsys_addr)) continue;
        size_t bus_addr = read_pointer(subsys_addr + field_offset(subsys_private,bus),"bus_type");
        if (!is_kvaddr(bus_addr)) continue;
        std::string name;
        size_t name_addr = read_pointer(bus_addr + field_offset(bus_type,name),"name addr");
        if (is_kvaddr(name_addr)){
            name = read_cstring(name_addr,16, "bus name");
        }
        if (name.empty() || name != bus_name){
            continue;
        }
        size_t private_addr = 0;
        if (field_offset(bus_type,p) != -1){
            private_addr = read_pointer(bus_addr + field_offset(bus_type,p),"subsys_private");
        }else{
            private_addr = subsys_addr;
        }
        return private_addr;
    }
    return 0;
}

std::vector<ulong> ParserPlugin::for_each_device_for_class(std::string class_name){
    std::vector<ulong> device_list;
    size_t private_addr = get_class_subsys_private(class_name);
    if (!is_kvaddr(private_addr)){
        return device_list;
    }
    size_t list_head = private_addr + field_offset(subsys_private,klist_devices) + field_offset(klist,k_list);
    for (const auto& node : for_each_list(list_head, field_offset(klist_node, n_node))) {
        if (!is_kvaddr(node)) continue;
        size_t private_addr = node - field_offset(device_private,knode_class);
        if (!is_kvaddr(private_addr)) continue;
        size_t device_addr = read_pointer(private_addr + field_offset(device_private,device),"device_private");
        if (!is_kvaddr(device_addr)) continue;
        device_list.push_back(device_addr);
    }
    return device_list;
}

std::vector<ulong> ParserPlugin::for_each_device_for_bus(std::string bus_name){
    std::vector<ulong> device_list;
    size_t private_addr = get_bus_subsys_private(bus_name);
    if (!is_kvaddr(private_addr)){
        return device_list;
    }
    size_t list_head = private_addr + field_offset(subsys_private,klist_devices) + field_offset(klist,k_list);
    for (const auto& node : for_each_list(list_head, field_offset(klist_node, n_node))) {
        if (!is_kvaddr(node)) continue;
        size_t private_addr = node - field_offset(device_private,knode_bus);
        if (!is_kvaddr(private_addr)) continue;
        size_t device_addr = read_pointer(private_addr + field_offset(device_private,device),"device_private");
        if (!is_kvaddr(device_addr)) continue;
        device_list.push_back(device_addr);
    }
    return device_list;
}

std::vector<ulong> ParserPlugin::for_each_device_for_driver(ulong driver_addr){
    std::vector<ulong> device_list;
    if (!is_kvaddr(driver_addr)){
        return device_list;
    }
    size_t driver_private_addr = read_pointer(driver_addr + field_offset(device_driver,p),"p");
    size_t dev_list_head = driver_private_addr + field_offset(driver_private,klist_devices) + field_offset(klist,k_list);
    for (const auto& kobject_addr : for_each_list(dev_list_head,field_offset(klist_node, n_node))) {
        size_t device_private_addr = kobject_addr - field_offset(device_private,knode_driver);
        if (!is_kvaddr(device_private_addr)) continue;
        size_t device_addr = read_pointer(device_private_addr + field_offset(device_private,device),"device_private");
        if (!is_kvaddr(device_addr)) continue;
        device_list.push_back(device_addr);
    }
    return device_list;
}

std::vector<ulong> ParserPlugin::for_each_driver(std::string bus_name){
    std::vector<ulong> driver_list;
    size_t private_addr = get_bus_subsys_private(bus_name);
    if (!is_kvaddr(private_addr)){
        return driver_list;
    }
    size_t list_head = private_addr + field_offset(subsys_private,klist_drivers) + field_offset(klist,k_list);
    for (const auto& node : for_each_list(list_head,field_offset(klist_node, n_node))) {
        if (!is_kvaddr(node)) continue;
        size_t driver_private_addr = node - field_offset(driver_private,knode_bus);
        if (!is_kvaddr(driver_private_addr)) continue;
        size_t driver_addr = read_pointer(driver_private_addr + field_offset(driver_private,driver),"driver_private");
        if (!is_kvaddr(driver_addr)) continue;
        driver_list.push_back(driver_addr);
    }
    return driver_list;
}

std::vector<ulong> ParserPlugin::for_each_task_files(struct task_context *tc){
    std::vector<ulong> file_table;
    if (!tc){
        return file_table;
    }
    ulong files = read_pointer(tc->task + field_offset(task_struct,files),"files");
    if (!is_kvaddr(files)){
        return file_table;
    }
    ulong fdt = read_pointer(files + field_offset(files_struct,fdt),"fdt");
    if (!is_kvaddr(fdt)){
        return file_table;
    }
    uint max_fds = read_uint(fdt + field_offset(fdtable,max_fds),"max_fds");
    ulong fds = read_pointer(fdt + field_offset(fdtable,fd),"fds");
    if (!is_kvaddr(fds)){
        return file_table;
    }
    file_table.resize(max_fds);
    for (size_t i = 0; i < max_fds; i++){
        ulong file_addr = read_pointer(fds + i * sizeof(struct file *),"fd");
        if (!is_kvaddr(file_addr)){
            file_table[i] = 0;
            continue;
        }
        file_table[i] = file_addr;
    }
    return file_table;
}

ulonglong ParserPlugin::read_structure_field(ulong addr,const std::string& type,const std::string& field,bool virt){
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

std::string ParserPlugin::read_cstring(ulong addr,int len, const std::string& note,bool virt){
    char res[len];
    if (!readmem(addr, (virt ? KVADDR : PHYSADDR), res, len, TO_CONST_STRING(note.c_str()), RETURN_ON_ERROR|QUIET)) {
        fprintf(fp, "Can't read %s at %lx\n",TO_CONST_STRING(note.c_str()), addr);
        return nullptr;
    }
    return std::string(res);
}

bool ParserPlugin::read_bool(ulong addr,const std::string& note,bool virt){
    void *buf = read_memory(addr,sizeof(bool),note,virt);
    if(buf == nullptr){
        return false;
    }
    bool res = BOOL(buf);
    FREEBUF(buf);
    return res;
}

int ParserPlugin::read_int(ulong addr,const std::string& note,bool virt){
    void *buf = read_memory(addr,sizeof(int),note,virt);
    if(buf == nullptr){
        return 0;
    }
    int res = INT(buf);
    FREEBUF(buf);
    return res;
}

uint ParserPlugin::read_uint(ulong addr,const std::string& note,bool virt){
    void *buf = read_memory(addr,sizeof(uint),note,virt);
    if(buf == nullptr){
        return 0;
    }
    uint res = UINT(buf);
    FREEBUF(buf);
    return res;
}

long ParserPlugin::read_long(ulong addr,const std::string& note,bool virt){
    void *buf = read_memory(addr,sizeof(long),note,virt);
    if(buf == nullptr){
        return 0;
    }
    long res = LONG(buf);
    FREEBUF(buf);
    return res;
}

ulong ParserPlugin::read_ulong(ulong addr,const std::string& note,bool virt){
    void *buf = read_memory(addr,sizeof(ulong),note,virt);
    if(buf == nullptr){
        return 0;
    }
    ulong res = ULONG(buf);
    FREEBUF(buf);
    return res;
}

ulonglong ParserPlugin::read_ulonglong(ulong addr,const std::string& note,bool virt){
    void *buf = read_memory(addr,sizeof(ulonglong),note,virt);
    if(buf == nullptr){
        return 0;
    }
    ulonglong res = ULONGLONG(buf);
    FREEBUF(buf);
    return res;
}

ushort ParserPlugin::read_ushort(ulong addr,const std::string& note,bool virt){
    void *buf = read_memory(addr,sizeof(ushort),note,virt);
    if(buf == nullptr){
        return 0;
    }
    ushort res = USHORT(buf);
    FREEBUF(buf);
    return res;
}

short ParserPlugin::read_short(ulong addr,const std::string& note,bool virt){
    void *buf = read_memory(addr,sizeof(short),note,virt);
    if(buf == nullptr){
        return 0;
    }
    short res = SHORT(buf);
    FREEBUF(buf);
    return res;
}

void* ParserPlugin::read_memory(ulong addr,int len, const std::string& note, bool virt){
    void* buf = (void *)GETBUF(len);
    if (!readmem(addr, (virt ? KVADDR : PHYSADDR), buf, len, TO_CONST_STRING(note.c_str()), RETURN_ON_ERROR|QUIET)) {
        fprintf(fp, "Can't read %s at %lx\n",TO_CONST_STRING(note.c_str()), addr);
        FREEBUF(buf);
        return nullptr;
    }
    return buf;
}

void* ParserPlugin::read_struct(ulong addr,const std::string& type,bool virt){
    int size = type_size(type);
    void* buf = (void *)GETBUF(size);
    if (!readmem(addr, (virt ? KVADDR : PHYSADDR), buf, size, TO_CONST_STRING(type.c_str()), RETURN_ON_ERROR|QUIET)) {
        fprintf(fp, "Can't read %s at %lx\n",TO_CONST_STRING(type.c_str()),addr);
        FREEBUF(buf);
        return nullptr;
    }
    return buf;
}

bool ParserPlugin::read_struct(ulong addr,void* buf, int len, const std::string& note,bool virt){
    if (!readmem(addr, (virt ? KVADDR : PHYSADDR), buf, len, TO_CONST_STRING(note.c_str()), RETURN_ON_ERROR|QUIET)) {
        fprintf(fp, "Can't read %s at %lx\n",TO_CONST_STRING(note.c_str()),addr);
        return false;
    }
    return true;
}

ulong ParserPlugin::read_pointer(ulong addr, const std::string& note,bool virt){
    void *buf = read_memory(addr,sizeof(void *),note,virt);
    if(buf == nullptr){
        return 0;
    }
    ulong res = (ulong)VOID_PTR(buf);
    FREEBUF(buf);
    return res;
}

unsigned char ParserPlugin::read_byte(ulong addr, const std::string& note,bool virt){
    unsigned char val;
    if (!readmem(addr, (virt ? KVADDR : PHYSADDR), &val, 1, TO_CONST_STRING(note.c_str()), RETURN_ON_ERROR|QUIET)) {
        fprintf(fp, "Can't read %s at %lx\n",TO_CONST_STRING(note.c_str()), addr);
        return -1;
    }
    return val;
}

int ParserPlugin::csymbol_exists(const std::string& note){
    return symbol_exists(TO_CONST_STRING(note.c_str()));
}

ulong ParserPlugin::csymbol_value(const std::string& note){
    return symbol_value(TO_CONST_STRING(note.c_str()));
}

bool ParserPlugin::is_kvaddr(ulong addr){
    return IS_KVADDR(addr);
}

bool ParserPlugin::is_uvaddr(ulong addr, struct task_context* tc){
    return IS_UVADDR(addr,tc);
}

int ParserPlugin::page_to_nid(ulong page){
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

ulong ParserPlugin::virt_to_phy(ulong vaddr){
    return VTOP(vaddr);
}

ulong ParserPlugin::phy_to_virt(ulong paddr){
    return PTOV(paddr);
}

ulong ParserPlugin::phy_to_pfn(ulong paddr){
    return BTOP(paddr);
}

physaddr_t ParserPlugin::pfn_to_phy(ulong pfn){
    return PTOB(pfn);
}

ulong ParserPlugin::page_to_pfn(ulong page){
    return phy_to_pfn(page_to_phy(page));
}

ulong ParserPlugin::pfn_to_page(ulong pfn){
    return phy_to_page(pfn_to_phy(pfn));
}

ulong ParserPlugin::phy_to_page(ulong paddr){
    ulong page;
    if(phys_to_page(paddr, &page)){
        return page;
    }
    return 0;
}

physaddr_t ParserPlugin::page_to_phy(ulong page){
    physaddr_t paddr = 0;
    if (is_page_ptr(page, &paddr)){
        return paddr;
    }
    return 0;
}

std::string ParserPlugin::get_config_val(const std::string& conf_name){
    char *config_val;
    if (get_kernel_config(TO_CONST_STRING(conf_name.c_str()),&config_val) != IKCONFIG_N){
        std::string val(config_val);
        return val;
    }else{
        return "n";
    }
}

void ParserPlugin::cfill_pgd(ulonglong pgd, int type, ulong size){
    if (!IS_LAST_PGD_READ(pgd)) {
        readmem(pgd, type, machdep->pgd, size, TO_CONST_STRING("pgd page"), FAULT_ON_ERROR);
        machdep->last_pgd_read = (ulong)(pgd);
    }
}

void ParserPlugin::cfill_pmd(ulonglong pmd, int type, ulong size){
    if (!IS_LAST_PMD_READ(pmd)) {
        readmem(pmd, type, machdep->pmd, size, TO_CONST_STRING("pmd page"), FAULT_ON_ERROR);
        machdep->last_pmd_read = (ulong)(pmd);
    }
}

void ParserPlugin::cfill_ptbl(ulonglong ptbl, int type, ulong size){
    if (!IS_LAST_PTBL_READ(ptbl)) {
        readmem(ptbl, type, machdep->ptbl, size, TO_CONST_STRING("page table"), FAULT_ON_ERROR);
        machdep->last_ptbl_read = (ulong)(ptbl);
    }
}

// maybe we can refer to symbols.c is_binary_stripped
bool ParserPlugin::is_binary_stripped(std::string& filename){
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

bool ParserPlugin::add_symbol_file(std::string& filename){
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

void ParserPlugin::verify_userspace_symbol(std::string& symbol_name){
    char buf[BUFSIZE];
    sprintf(buf, "ptype %s", symbol_name.c_str());
    if(!gdb_pass_through(buf, NULL, GNU_RETURN_ON_ERROR)){
        fprintf(fp, "verify_userspace_symbol: %s failed \n", symbol_name.c_str());
    }
}

std::string ParserPlugin::extract_string(const char *input) {
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

int ParserPlugin::is_bigendian(void){
    int i = 0x12345678;
    if (*(char *)&i == 0x12)
        return TRUE;
    else
        return FALSE;
}

std::vector<std::string> ParserPlugin::get_enumerator_list(const std::string &enum_name){
    std::vector<std::string> result;
    char buf[BUFSIZE];
    open_tmpfile();
    if (dump_enumerator_list(TO_CONST_STRING(enum_name.c_str()))){
        rewind(pc->tmpfile);
        while (fgets(buf, BUFSIZE, pc->tmpfile)){
            std::string line = buf;
            size_t pos = line.find('=');
            if (pos == std::string::npos) {
                continue;
            }else{
                std::string name = line.substr(0, pos - 1);
                size_t first = name.find_first_not_of(' ');
                size_t last = name.find_last_not_of(' ');
                if (first == std::string::npos || last == std::string::npos) {
                    continue;
                }
                result.push_back(name.substr(first, (last - first + 1)));
            }
        }
    }
    close_tmpfile();
    return result;
}

long ParserPlugin::read_enum_val(const std::string& enum_name){
     long enum_val = 0;
     enumerator_value(TO_CONST_STRING(enum_name.c_str()), &enum_val);
     return enum_val;
}

std::map<std::string, ulong> ParserPlugin::read_enum_list(const std::string& enum_list_name){
    char cmd_buf[BUFSIZE], ret_buf[BUFSIZE*5];
    FILE *tmp_fp = fmemopen(ret_buf, sizeof(ret_buf), "w");
    sprintf(cmd_buf, "ptype enum %s", enum_list_name.c_str());
    gdb_pass_through(cmd_buf, tmp_fp, GNU_RETURN_ON_ERROR);
    fclose(tmp_fp);
    std::string input(ret_buf);
    std::string content = input.substr(input.find('{') + 1, input.find('}') - input.find('{')-1);

    std::map<std::string, ulong> enum_list;
    std::istringstream ss(content);
    std::string item;
    int currentValue = 0;
    while (std::getline(ss, item, ',')) {
        size_t equalPos = item.find('=');
        std::string key = (equalPos != std::string::npos)?item.substr(0, equalPos):item;
        int value = (equalPos != std::string::npos)?std::stoi(item.substr(equalPos+1)):currentValue++;
        key.erase(0, key.find_first_not_of(" \t\n\r"));
        key.erase(key.find_last_not_of(" \t\n\r") + 1);
        enum_list.insert(std::make_pair(key, value));
    }
    return enum_list;
}

char ParserPlugin::get_printable(uint8_t d) {
    return std::isprint(d) ? static_cast<char>(d) : '.';
}

std::string ParserPlugin::print_line(uint64_t addr, const std::vector<uint8_t>& data) {
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

std::string ParserPlugin::hexdump(uint64_t addr, const char* buf, size_t length, bool little_endian) {
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

std::stringstream ParserPlugin::get_curpath() {
    std::stringstream ss;
    char tmp_buf[PATH_MAX];
    if (getcwd(tmp_buf, sizeof(tmp_buf)) != nullptr) {
        ss << tmp_buf;
    }
    return ss;
}


#if defined(ARM)
ulong* ParserPlugin::pmd_page_addr(ulong pmd){
    ulong ptr;
    if (machdep->flags & PGTABLE_V2) {
        ptr = PAGEBASE(pmd);
    } else {
        ptr = pmd & ~(PTRS_PER_PTE * sizeof(void *) - 1);
        ptr += PTRS_PER_PTE * sizeof(void *);
    }
    return (ulong *)ptr;
}

ulong ParserPlugin::get_arm_pte(ulong task_addr, ulong page_vaddr){
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

bool ParserPlugin::load_symbols(std::string& path, std::string name){
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

void ParserPlugin::uwind_irq_back_trace(int cpu, ulong x30){
#if defined(ARM64)
    ulong *cpus = get_cpumask_buf();
    if (NUM_IN_BITMAP(cpus, cpu)) {
        if (hide_offline_cpu(cpu)) {
            fprintf(fp, "cpu:%d is OFFLINE \n", cpu);
            FREEBUF(cpus);
            return;
        }
    }
    struct bt_info bt_setup, *bt;
    struct stack_hook hook;
    BZERO(&hook, sizeof(struct stack_hook));
    bt = &bt_setup;
    BZERO(bt, sizeof(struct bt_info));
    struct task_context *tc = task_to_context(tt->active_set[cpu]);
    clone_bt_info(&bt_setup, bt, tc);
    bt->hp = &hook;

    char arg_buf[BUFSIZE];
    BZERO(arg_buf, BUFSIZE);
    snprintf(arg_buf, BUFSIZE, "%d", cpu);
    make_cpumask(arg_buf, cpus, RETURN_ON_ERROR /* FAULT_ON_ERROR */, NULL);
    bt->cpumask = cpus;
    hook.esp = x30;
    print_task_header(fp, tc, 0);
    back_trace(bt);
    // dump_bt_info(bt, "back_trace");
    FREEBUF(cpus);
    fprintf(fp, "\n");
#endif
}

void ParserPlugin::uwind_task_back_trace(int pid, ulong x30){
#if defined(ARM64)
    struct task_context *tc = pid_to_context(pid);
    if(!tc){
        fprintf(fp, "No such pid:%d \n", pid);
        return;
    }
    if(strstr(tc->comm, "swapper") != NULL){
        fprintf(fp, "Do not support for swapper process\n");
        return;
    }
    struct bt_info bt_setup, *bt;
    struct stack_hook hook;
    BZERO(&hook, sizeof(struct stack_hook));

    bt = &bt_setup;
    BZERO(bt, sizeof(struct bt_info));
    clone_bt_info(&bt_setup, bt, tc);
    bt->hp = &hook;
    hook.esp = x30;
    back_trace(bt);
    // dump_bt_info(bt, "back_trace");
    fprintf(fp, "\n");
#endif
}
#pragma GCC diagnostic pop
