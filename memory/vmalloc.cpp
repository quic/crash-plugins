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

#include "vmalloc.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Vmalloc)
#endif

void Vmalloc::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    if(area_list.size() == 0){
        parser_vmap_area_list();
    }
    while ((c = getopt(argcnt, args, "arvsf:t:")) != EOF) {
        switch(c) {
            case 'a':
                print_vmap_area_list();
                break;
            case 'r':
                print_vmap_area();
                break;
            case 'v':
                print_vm_struct();
                break;
            case 's':
                print_summary_info();
                break;
            case 'f':
                cppString.assign(optarg);
                print_vm_info_caller(cppString);
                break;
            case 't':
                cppString.assign(optarg);
                print_vm_info_type(cppString);
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

void Vmalloc::init_offset(void) {
    field_init(vmap_area,va_start);
    field_init(vmap_area,va_end);
    field_init(vmap_area,vm);
    field_init(vmap_area,list);
    field_init(vm_struct,next);
    field_init(vm_struct,addr);
    field_init(vm_struct,size);
    field_init(vm_struct,flags);
    field_init(vm_struct,pages);
    field_init(vm_struct,nr_pages);
    field_init(vm_struct,phys_addr);
    field_init(vm_struct,caller);
    struct_init(vmap_area);
    struct_init(vm_struct);
    field_init(vmap_node,pool);
    field_init(vmap_pool,head);
    field_init(vmap_pool,len);
    struct_init(vmap_node);
    struct_init(vmap_pool);
}

void Vmalloc::init_command(void) {
    cmd_name = "vmalloc";
    help_str_list={
        "vmalloc",                            /* command name */
        "dump vmalloc memory information",        /* short description */
        "-a \n"
            "  vmalloc -r\n"
            "  vmalloc -v\n"
            "  vmalloc -s\n"
            "  vmalloc -f <func name>\n"
            "  vmalloc -t <type name>\n"
            "  This command dumps the vmalloc info.",
        "\n",
        "EXAMPLES",
        "  Display vmalloc memory info:",
        "    %s> vmalloc -a",
        "    vmap_area:0xffffff8003015e00 range:[0xffffffc008000000~0xffffffc008005000] size:20.00Kb",
        "       vm_struct:0xffffff8003003a00 size:20.00Kb flags:vmalloc nr_pages:4 addr:0xffffffc008000000 phys_addr:0x0 start_kernel+496",
        "           Page:0xfffffffe000c2a00 PA:0x430a8000",
        "           Page:0xfffffffe000c2a40 PA:0x430a9000",
        "           Page:0xfffffffe000c2a80 PA:0x430aa000",
        "           Page:0xfffffffe000c2ac0 PA:0x430ab000",
        "\n",
        "  Display all vmap_area info:",
        "    %s> vmalloc -r",
        "    Total vm size:443.56Mb",
        "    ==============================================================================================================",
        "    [0]vmap_area:0xffffff8003015e00 range:[0xffffffc008000000~0xffffffc008005000] size:20.00Kb",
        "    [1]vmap_area:0xffffff8003015100 range:[0xffffffc008005000~0xffffffc008007000] size:8.00Kb",
        "    [2]vmap_area:0xffffff8003015180 range:[0xffffffc008008000~0xffffffc00800d000] size:20.00Kb",
        "    [3]vmap_area:0xffffff80030159c0 range:[0xffffffc00800d000~0xffffffc00800f000] size:8.00Kb",
        "\n",
        "  Display all vm_struct info:",
        "    %s> vmalloc -v",
        "    Total vm size:502.01Mb, physical size:109.80Mb",
        "    ==============================================================================================================",
        "    [0]vm_struct:0xffffff8003003a00 size:20.00Kb  flags:vmalloc  nr_pages:4      addr:0xffffffc008000000 phys_addr:0x0            start_kernel+496",
        "    [1]vm_struct:0xffffff8003003c40 size:8.00Kb   flags:vmalloc  nr_pages:1      addr:0xffffffc008005000 phys_addr:0x0            init_IRQ+344",
        "    [2]vm_struct:0xffffff8003003ac0 size:20.00Kb  flags:vmalloc  nr_pages:4      addr:0xffffffc008008000 phys_addr:0x0            start_kernel+496",
        "    [3]vm_struct:0xffffff8003003cc0 size:8.00Kb   flags:vmalloc  nr_pages:1      addr:0xffffffc00800d000 phys_addr:0x0            init_IRQ+344",
        "\n",
        "  Display vmalloc statistical info:",
        "    %s> vmalloc -s",
        "    Summary by caller:",
        "    ========================================================",
        "    [devm_ioremap_wc+112]                        virt_size:121.01Mb   phys_size:0b",
        "    [load_module+4704]                           virt_size:54.26Mb    phys_size:53.09Mb",
        "    [devm_ioremap+112]                           virt_size:46.35Mb    phys_size:0b",
        "",
        "    Summary by type:",
        "    ========================================================",
        "    [ioremap]           virt_size:203.71Mb   phys_size:0b",
        "    [vmap]              virt_size:154.91Mb   phys_size:0b",
        "    [vmalloc]           virt_size:132.02Mb   phys_size:109.80Mb",
        "    [vpages]            virt_size:11.38Mb    phys_size:0b",
        "\n",
        "  Display the allocated pages by function name:",
        "    %s> vmalloc -f load_module",
        "    [1]Page:0xfffffffe00555040 PA:0x55541000",
        "    [2]Page:0xfffffffe00560e00 PA:0x55838000",
        "    [3]Page:0xfffffffe0074d480 PA:0x5d352000",
        "    [4]Page:0xfffffffe0074d4c0 PA:0x5d353000",
        "\n",
        "  Display the allocated pages by type name:",
        "    %s> vmalloc -t vmalloc",
        "    [1]Page:0xfffffffe000c2a00 PA:0x430a8000",
        "    [2]Page:0xfffffffe000c2a40 PA:0x430a9000",
        "    [3]Page:0xfffffffe000c2a80 PA:0x430aa000",
        "    [4]Page:0xfffffffe000c2ac0 PA:0x430ab000",
        "\n",
    };
}

Vmalloc::Vmalloc(){}

void Vmalloc::parser_vmap_nodes(){
    if (!csymbol_exists("vmap_nodes")){
        fprintf(fp, "vmap_nodes doesn't exist in this kernel!\n");
        return;
    }
    ulong nodes_addr = read_pointer(csymbol_value("vmap_nodes"),"vmap_nodes pages");
    if (!is_kvaddr(nodes_addr)) return;
    size_t nr_node = read_int( csymbol_value("nr_vmap_nodes"),"nr_vmap_nodes");
    size_t pool_cnt = field_size(vmap_node,pool)/struct_size(vmap_pool);
    size_t offset = field_offset(vmap_area,list);
    for (size_t i = 0; i < nr_node; i++){
        ulong pools_addr = nodes_addr + i * struct_size(vmap_node) + field_offset(vmap_node,pool);
        for (size_t p = 0; p < pool_cnt; p++){
            ulong pool_addr = pools_addr + p * struct_size(vmap_pool);
            if (!is_kvaddr(pool_addr)) continue;
            ulong len = read_ulong(pool_addr + field_offset(vmap_pool,len),"vmap_pool len");
            if (len == 0){
                continue;
            }
            for (const auto& area_addr : for_each_list(pool_addr,offset)) {
                parser_vmap_area(area_addr);
            }
        }
    }
}

void Vmalloc::parser_vmap_area(ulong addr){
    void *vmap_buf = read_struct(addr,"vmap_area");
    if (!vmap_buf) {
        return;
    }
    std::shared_ptr<vmap_area> area_ptr = std::make_shared<vmap_area>();
    area_ptr->addr = addr;
    area_ptr->va_start = ULONG(vmap_buf + field_offset(vmap_area,va_start));
    area_ptr->va_end = ULONG(vmap_buf + field_offset(vmap_area,va_end));
    area_list.push_back(area_ptr);
    ulong vm_addr = ULONG(vmap_buf + field_offset(vmap_area,vm));
    FREEBUF(vmap_buf);
    while (is_kvaddr(vm_addr)){
        void *vm_buf = read_struct(vm_addr,"vm_struct");
        if (!vm_buf) {
            fprintf(fp, "Failed to read vm_struct structure at address %lx\n", vm_addr);
            continue;
        }
        size_t vm_size = ULONG(vm_buf + field_offset(vm_struct,size));
        size_t nr_pages = UINT(vm_buf + field_offset(vm_struct,nr_pages));
        if (vm_size % page_size != 0 || (vm_size / page_size) != (nr_pages + 1)) {
            FREEBUF(vm_buf);
            break;
        }
        std::shared_ptr<vm_struct> vm_ptr = std::make_shared<vm_struct>();
        vm_ptr->addr = vm_addr;
        vm_ptr->kaddr = ULONG(vm_buf + field_offset(vm_struct,addr));
        vm_ptr->size = vm_size;
        vm_ptr->nr_pages = nr_pages;
        vm_ptr->phys_addr = ULONG(vm_buf + field_offset(vm_struct,phys_addr));
        ulong caller = ULONG(vm_buf + field_offset(vm_struct,caller));
        ulong next = ULONG(vm_buf + field_offset(vm_struct,next));
        ulong pages = ULONG(vm_buf + field_offset(vm_struct,pages));
        ulong flags = ULONG(vm_buf + field_offset(vm_struct,flags));
        FREEBUF(vm_buf);
        if (flags & Vmalloc::VM_IOREMAP){
            vm_ptr->flags.assign("ioremap");
        }else if (flags & Vmalloc::VM_ALLOC){
            vm_ptr->flags.assign("vmalloc");
        }else if (flags & Vmalloc::VM_MAP){
            vm_ptr->flags.assign("vmap");
        }else if (flags & Vmalloc::VM_USERMAP){
            vm_ptr->flags.assign("user");
        }else if (flags & Vmalloc::VM_VPAGES){
            vm_ptr->flags.assign("vpages");
        }else if (flags & Vmalloc::VM_UNLIST){
            vm_ptr->flags.assign("unlist");
        }else{
            vm_ptr->flags.assign("unknow");
        }
        ulong offset;
        struct syment *sp = value_search(caller, &offset);
        if (sp) {
            vm_ptr->caller = sp->name;
            size_t pos = vm_ptr->caller.find('.'); //remove the rest char
            if (pos != std::string::npos) {
                vm_ptr->caller = vm_ptr->caller.substr(0, pos);
            }
            if (offset)
                vm_ptr->caller.append("+").append(std::to_string(offset));
        }
        if (is_kvaddr(pages)) {
            for (int j = 0; j < vm_ptr->nr_pages; ++j) {
                ulong addr = pages + j * sizeof(void *);
                if (!is_kvaddr(addr)) break;
                ulong page_addr = read_pointer(addr,"vm_struct pages");
                if (!is_kvaddr(page_addr)) continue;
                physaddr_t paddr = page_to_phy(page_addr);
                if (paddr <= 0) continue;
                vm_ptr->page_list.push_back(page_addr);
            }
        }
        area_ptr->vm_list.push_back(vm_ptr);
        vm_addr = next;
    }
}

void Vmalloc::parser_vmap_area_list(){
    if (!csymbol_exists("vmap_area_list")){
        parser_vmap_nodes();
    }else{
        ulong area_list_addr = csymbol_value("vmap_area_list");
        if (!is_kvaddr(area_list_addr)) {
            fprintf(fp, "vmap_area_list address is invalid!\n");
            return;
        }
        int offset = field_offset(vmap_area,list);
        for (const auto& area_addr : for_each_list(area_list_addr,offset)) {
            parser_vmap_area(area_addr);
        }
    }
}

void Vmalloc::print_vmap_area_list(){
    size_t index = 0;
    std::ostringstream oss;
    for(auto area: area_list){
        oss << "[" << std::setw(4) << std::setfill('0') << std::dec << std::right << index << "]"
            << "vmap_area:" << std::hex << area->addr << " "
            << "range:[" << std::hex << area->va_start << "~" << std::hex << area->va_end << "]" << " "
            << "size:" << csize((area->va_end - area->va_start)) << "\n";

        for (auto vm : area->vm_list){
            oss << "   vm_struct:" << std::hex << vm->addr << " "
                << "size:" << csize(vm->size) << " "
                << "flags:" << std::dec << vm->flags.c_str() << " "
                << "nr_pages:" << std::dec << vm->nr_pages << " "
                << "addr:" << std::hex << vm->kaddr << " "
                << "phys_addr:" << std::hex << vm->phys_addr << " "
                << vm->caller << "\n";

            size_t cnt = 1;
            for (auto page_addr : vm->page_list){
                physaddr_t paddr = page_to_phy(page_addr);
                oss << "       [" << std::setw(4) << std::setfill('0') << std::dec << std::right << cnt << "]"
                    << "Page:" << std::hex << page_addr << " "
                    << "PA:" << paddr << "\n";
                cnt++;
            }
        }
        index++;
        oss << "\n";
    }
    fprintf(fp, "%s", oss.str().c_str());
}

void Vmalloc::print_vmap_area(){
    ulong total_size = 0;
    for(auto area: area_list){
        total_size += (area->va_end - area->va_start);
    }
    fprintf(fp, "Total vm size:%s\n",csize(total_size).c_str());
    fprintf(fp, "==============================================================================================================\n");
    std::ostringstream oss;
    for(size_t i=0; i < area_list.size(); i++){
        oss << "[" << std::setw(4) << std::setfill('0') << std::dec << std::right << i << "]"
            << "vmap_area:" << std::hex << area_list[i]->addr << " "
            << "range:[" << std::hex << area_list[i]->va_start << "~" << std::hex << area_list[i]->va_end << "]" << " "
            << "size:" << csize((area_list[i]->va_end - area_list[i]->va_start))
            << "\n";
    }
    fprintf(fp, "%s \n", oss.str().c_str());
}

void Vmalloc::print_vm_struct(){
    ulong total_size = 0;
    ulong total_pages = 0;
    for(auto area: area_list){
        for (auto vm : area->vm_list){
            total_size += vm->size;
            total_pages += vm->nr_pages;
        }
    }
    fprintf(fp, "Total vm size:%s, ",csize(total_size).c_str());
    fprintf(fp, "physical size:%s\n",csize(total_pages*page_size).c_str());
    fprintf(fp, "==============================================================================================================\n");
    int index = 0;
    std::ostringstream oss;
    for(auto area: area_list){
        for (auto vm : area->vm_list){
            oss << "[" << std::setw(4) << std::setfill('0') << std::dec << std::right << index << "]"
                << "vm_struct:" << std::hex << vm->addr << " "
                << "size:" << std::left << std::setw(8) << std::setfill(' ') << csize(vm->size) << " "
                << "flags:" << std::setw(8) << vm->flags << " "
                << "nr_pages:" << std::dec << std::setw(4) << vm->nr_pages << " "
                << "kaddr:" << std::hex << vm->kaddr << " "
                << "phys_addr:" << std::hex << vm->phys_addr
                << "\n";
            index += 1;
        }
    }
    fprintf(fp, "%s \n", oss.str().c_str());
}

void Vmalloc::print_summary_caller(){
    std::unordered_map<std::string, std::vector<std::shared_ptr<vm_struct>>> caller_map;
    for(auto area: area_list){
        for (auto vm : area->vm_list){
            auto it = caller_map.find(vm->caller);
            if (it != caller_map.end()) {
                it->second.push_back(vm);
            }else{
                caller_map[vm->caller] = std::vector<std::shared_ptr<vm_struct>>{vm};
            }
        }
    }
    std::vector<vmalloc_info> callers;
    for(const auto& pair: caller_map){
        vmalloc_info info;
        info.func = pair.first;
        ulong total_size = 0;
        ulong total_cnt = 0;
        for(auto vm: pair.second){
            total_size += vm->size;
            total_cnt += vm->nr_pages;
        }
        info.virt_size = total_size;
        info.page_cnt = total_cnt;
        callers.push_back(info);
    }
    std::sort(callers.begin(), callers.end(),[&](vmalloc_info a, vmalloc_info b){
        return a.virt_size > b.virt_size;
    });
    size_t max_len = 0;
    for (const auto& info : callers) {
        max_len = std::max(max_len,info.func.size());
    }
    std::ostringstream oss;
    oss << std::left << std::setw(max_len + 2) << "Func Name" << " "
            << std::left << std::setw(15) << "virt" << " "
            << std::left << std::setw(15) << "phys"
            << "\n";
    for(const auto& info: callers){
        oss << std::left << std::setw(max_len + 2) << info.func << " "
            << std::left << std::setw(15) << csize(info.virt_size) << " "
            << std::left << std::setw(15) << csize(info.page_cnt*page_size)
            << "\n";
    }
    fprintf(fp, "%s \n", oss.str().c_str());

}

void Vmalloc::print_summary_type(){
    std::unordered_map<std::string, std::vector<std::shared_ptr<vm_struct>>> type_maps;
    for(auto area: area_list){
        for (auto vm : area->vm_list){
            auto it = type_maps.find(vm->flags);
            if (it != type_maps.end()) {
                it->second.push_back(vm);
            }else{
                type_maps[vm->flags] = std::vector<std::shared_ptr<vm_struct>>{vm};
            }
        }
    }
    std::vector<vmalloc_info> types;
    for(const auto& pair: type_maps){
        vmalloc_info info;
        info.func = pair.first;
        ulong total_size = 0;
        ulong total_cnt = 0;
        for(auto vm: pair.second){
            total_size += vm->size;
            total_cnt += vm->nr_pages;
        }
        info.virt_size = total_size;
        info.page_cnt = total_cnt;
        types.push_back(info);
    }
    std::sort(types.begin(), types.end(),[&](vmalloc_info a, vmalloc_info b){
        return a.virt_size > b.virt_size;
    });
    size_t max_len = 0;
    for (const auto& info : types) {
        max_len = std::max(max_len,info.func.size());
    }
    std::ostringstream oss;
    oss << std::left << std::setw(max_len + 2) << "Type" << " "
            << std::left << std::setw(15) << "virt" << " "
            << std::left << std::setw(15) << "phys"
            << "\n";
    for(const auto& info: types){
        oss << std::left << std::setw(max_len + 2) << info.func << " "
            << std::left << std::setw(15) << csize(info.virt_size) << " "
            << std::left << std::setw(15) << csize(info.page_cnt*page_size)
            << "\n";
    }
    fprintf(fp, "%s \n",oss.str().c_str());
}

void Vmalloc::print_summary_info(){
    fprintf(fp, "Summary by caller:\n");
    fprintf(fp, "========================================================\n");
    print_summary_caller();
    fprintf(fp, "\n\nSummary by type:\n");
    fprintf(fp, "========================================================\n");
    print_summary_type();
}

void Vmalloc::print_vm_info_caller(std::string func){
    std::unordered_map<std::string, std::vector<std::shared_ptr<vm_struct>>> caller_map;
    for(auto area: area_list){
        for (auto vm : area->vm_list){
            auto it = caller_map.find(vm->caller);
            if (it != caller_map.end()) {
                it->second.push_back(vm);
            }else{
                caller_map[vm->caller] = std::vector<std::shared_ptr<vm_struct>>{vm};
            }
        }
    }
    std::ostringstream oss;
    for (const auto& item : caller_map) {
        std::string func_name = item.first;
        std::vector<std::shared_ptr<vm_struct>> vm_list = item.second;
        if (func_name.find(func) != std::string::npos) {
            // fprintf(fp, "%s:\n",func_name.c_str());
            int index = 1;
            for(auto vm: vm_list){
                for (auto page_addr : vm->page_list){
                    physaddr_t paddr = page_to_phy(page_addr);
                    oss << "[" << std::setw(4) << std::setfill('0') << std::dec << std::right << index << "]"
                        << "Page:" << std::left << std::hex << page_addr << " "
                        << "PA:" << paddr
                        << "\n";
                    index += 1;
                }
            }
        }
    }
    fprintf(fp, "%s \n", oss.str().c_str());
}

void Vmalloc::print_vm_info_type(std::string type){
    std::unordered_map<std::string, std::vector<std::shared_ptr<vm_struct>>> type_maps;
    for(auto area: area_list){
        for (auto vm : area->vm_list){
            auto it = type_maps.find(vm->flags);
            if (it != type_maps.end()) {
                it->second.push_back(vm);
            }else{
                type_maps[vm->flags] = std::vector<std::shared_ptr<vm_struct>>{vm};
            }
        }
    }
    std::ostringstream oss;
    for (const auto& item : type_maps) {
        std::string type_name = item.first;
        std::vector<std::shared_ptr<vm_struct>> vm_list = item.second;
        if (type_name.find(type) != std::string::npos) {
            // fprintf(fp, "%s:\n",type_name.c_str());
            int index = 1;
            for(auto vm: vm_list){
                for (auto page_addr : vm->page_list){
                    physaddr_t paddr = page_to_phy(page_addr);
                    oss << "[" << std::setw(4) << std::setfill('0') << std::dec << std::right << index << "]"
                        << "Page:" << std::left << std::hex << page_addr << " "
                        << "PA:" << paddr
                        << "\n";
                    index += 1;
                }
            }
        }
    }
    fprintf(fp, "%s \n",oss.str().c_str());
}

#pragma GCC diagnostic pop
