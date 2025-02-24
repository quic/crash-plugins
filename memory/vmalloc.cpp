// Copyright (c) 2024-2025 Qualcomm Innovation Center, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Clear

#include "vmalloc.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Vmalloc)
#endif

void Vmalloc::cmd_main(void) {
    int c;
    int flags;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
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

Vmalloc::Vmalloc(){
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
    initialize();
    parser_vmap_area_list();
}

void Vmalloc::parser_vmap_area_list(){
    if (!csymbol_exists("vmap_area_list")){
        LOGE("vmap_area_list doesn't exist in this kernel!\n");
        return;
    }
    ulong area_list_addr = csymbol_value("vmap_area_list");
    if (!area_list_addr) return;
    int offset = field_offset(vmap_area,list);
    std::vector<ulong> vmap_list = for_each_list(area_list_addr,offset);
    for (const auto& area_addr : vmap_list) {
        void *buf = read_struct(area_addr,"vmap_area");
        if(buf == nullptr) continue;
        std::shared_ptr<vmap_area> area_ptr = std::make_shared<vmap_area>();
        area_ptr->addr = area_addr;
        area_ptr->va_start = ULONG(buf + field_offset(vmap_area,va_start));
        area_ptr->va_end = ULONG(buf + field_offset(vmap_area,va_end));
        area_list.push_back(area_ptr);
        ulong vm_addr = ULONG(buf + field_offset(vmap_area,vm));
        FREEBUF(buf);
        while (vm_addr > 0)
        {
            void *buf = read_struct(vm_addr,"vm_struct");
            if(buf == nullptr) continue;
            std::shared_ptr<vm_struct> vm_ptr = std::make_shared<vm_struct>();
            vm_ptr->addr = vm_addr;
            vm_ptr->kaddr = ULONG(buf + field_offset(vm_struct,addr));
            vm_ptr->size = ULONG(buf + field_offset(vm_struct,size));
            vm_ptr->nr_pages = UINT(buf + field_offset(vm_struct,nr_pages));
            vm_ptr->phys_addr = ULONG(buf + field_offset(vm_struct,phys_addr));

            ulong caller = ULONG(buf + field_offset(vm_struct,caller));
            ulong next = ULONG(buf + field_offset(vm_struct,next));
            ulong pages = ULONG(buf + field_offset(vm_struct,pages));
            ulong flags = ULONG(buf + field_offset(vm_struct,flags));
            FREEBUF(buf);
            if (flags & Vmalloc::VM_IOREMAP){
                vm_ptr->flags.append("ioremap");
            }else if (flags & Vmalloc::VM_ALLOC){
                vm_ptr->flags.append("vmalloc");
            }else if (flags & Vmalloc::VM_MAP){
                vm_ptr->flags.append("vmap");
            }else if (flags & Vmalloc::VM_USERMAP){
                vm_ptr->flags.append("user");
            }else if (flags & Vmalloc::VM_VPAGES){
                vm_ptr->flags.append("vpages");
            }else if (flags & Vmalloc::VM_UNLIST){
                vm_ptr->flags.append("unlist");
            }
            struct syment *sp;
            ulong offset;
            if (sp = value_search(caller, &offset)) {
                vm_ptr->caller = sp->name;
                size_t pos = vm_ptr->caller.find('.'); //remove the rest char
                if (pos != std::string::npos) {
                    vm_ptr->caller = vm_ptr->caller.substr(0, pos);
                }
                if (offset)
                    vm_ptr->caller.append("+").append(std::to_string(offset));
            }
            for (int j = 0; j < vm_ptr->nr_pages; ++j) {
                ulong addr = pages + j * sizeof(void *);
                ulong page_addr = read_pointer(addr,"vm_struct pages");
                if (!is_kvaddr(page_addr))continue;
                    continue;
                physaddr_t paddr = page_to_phy(page_addr);
                if (paddr <= 0)
                    continue;
                vm_ptr->page_list.push_back(page_addr);
            }
            area_ptr->vm_list.push_back(vm_ptr);
            vm_addr = next;
        }
    }
}

void Vmalloc::print_vmap_area_list(){
    char buf[BUFSIZE];
    for(auto area: area_list){
        convert_size((area->va_end - area->va_start),buf);
        fprintf(fp, "vmap_area:0x%lx range:[0x%lx~0x%lx] size:%s\n",area->addr,area->va_start,area->va_end,buf);
        for (auto vm : area->vm_list){
            convert_size(vm->size,buf);
            fprintf(fp, "   vm_struct:0x%lx size:%s flags:%s nr_pages:%d addr:0x%lx phys_addr:0x%llx %s\n",
                    vm->addr,buf,vm->flags.c_str(),vm->nr_pages,vm->kaddr,vm->phys_addr,vm->caller.c_str());
            for (auto page_addr : vm->page_list){
                physaddr_t paddr = page_to_phy(page_addr);
                fprintf(fp, "       Page:0x%lx PA:0x%llx\n",page_addr,(ulonglong)paddr);
            }
        }
        fprintf(fp, "\n");
    }
}

void Vmalloc::print_vmap_area(){
    char buf[BUFSIZE];
    ulong total_size = 0;
    for(auto area: area_list){
        total_size += (area->va_end - area->va_start);
    }
    convert_size(total_size,buf);
    fprintf(fp, "Total vm size:%s\n",buf);
    fprintf(fp, "==============================================================================================================\n");
    for(int i=0; i < area_list.size(); i++){
        convert_size((area_list[i]->va_end - area_list[i]->va_start),buf);
        fprintf(fp, "[%d]vmap_area:0x%lx range:[0x%lx~0x%lx] size:%s\n",i,
            area_list[i]->addr,area_list[i]->va_start,area_list[i]->va_end,buf);
    }
}

void Vmalloc::print_vm_struct(){
    char buf[BUFSIZE];
    ulong total_size = 0;
    ulong total_pages = 0;
    for(auto area: area_list){
        for (auto vm : area->vm_list){
            total_size += vm->size;
            total_pages += vm->nr_pages;
        }
    }
    convert_size(total_size,buf);
    fprintf(fp, "Total vm size:%s, ",buf);
    convert_size(total_pages*page_size,buf);
    fprintf(fp, "physical size:%s\n",buf);
    fprintf(fp, "==============================================================================================================\n");
    int index = 0;
    for(auto area: area_list){
        for (auto vm : area->vm_list){
            fprintf(fp, "[%d]vm_struct:0x%lx",index,vm->addr);
            convert_size(vm->size,buf);
            fprintf(fp, " size:%s ",mkstring(buf, 8, LJUST,buf));
            sprintf(buf, "flags:%s",vm->flags.c_str());
            fprintf(fp, "%s ",mkstring(buf, 14, LJUST,buf));
            sprintf(buf, "nr_pages:%d",vm->nr_pages);
            fprintf(fp, "%s ",mkstring(buf, 15, LJUST,buf));
            sprintf(buf, "addr:0x%lx",vm->kaddr);
            fprintf(fp, "%s ",mkstring(buf, 21, LJUST,buf));
            sprintf(buf, "phys_addr:0x%llx",vm->phys_addr);
            fprintf(fp, "%s ",mkstring(buf, 24, LJUST,buf));
            fprintf(fp, "%s\n",vm->caller.c_str());
            index +=1;
        }
    }
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
    char buf[BUFSIZE];
    for(const auto& info: callers){
        sprintf(buf, "[%s]",info.func.c_str());
        fprintf(fp, "%s",mkstring(buf, max_len + 3, LJUST, buf));

        convert_size(info.virt_size,buf);
        fprintf(fp, "virt_size:%s ",mkstring(buf, 10, LJUST,buf));
        convert_size(info.page_cnt*page_size,buf);
        fprintf(fp, "phys_size:%s\n",mkstring(buf, 10, LJUST,buf));
    }
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
    char buf[BUFSIZE];
    for(const auto& info: types){
        sprintf(buf, "[%s]",info.func.c_str());
        fprintf(fp, "%s",mkstring(buf, 20, LJUST, buf));
        convert_size(info.virt_size,buf);
        fprintf(fp, "virt_size:%s ",mkstring(buf, 10, LJUST,buf));
        convert_size(info.page_cnt*page_size,buf);
        fprintf(fp, "phys_size:%s\n",mkstring(buf, 10, LJUST,buf));
    }
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
    for (const auto& item : caller_map) {
        std::string func_name = item.first;
        std::vector<std::shared_ptr<vm_struct>> vm_list = item.second;
        if (func_name.find(func) != std::string::npos) {
            // fprintf(fp, "%s:\n",func_name.c_str());
            int index = 1;
            for(auto vm: vm_list){
                for (auto page_addr : vm->page_list){
                    physaddr_t paddr = page_to_phy(page_addr);
                    fprintf(fp, "[%d]Page:0x%lx PA:0x%llx\n",index,page_addr,(ulonglong)paddr);
                    index += 1;
                }
            }
        }
    }
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
    for (const auto& item : type_maps) {
        std::string type_name = item.first;
        std::vector<std::shared_ptr<vm_struct>> vm_list = item.second;
        if (type_name.find(type) != std::string::npos) {
            // fprintf(fp, "%s:\n",type_name.c_str());
            int index = 1;
            for(auto vm: vm_list){
                for (auto page_addr : vm->page_list){
                    physaddr_t paddr = page_to_phy(page_addr);
                    fprintf(fp, "[%d]Page:0x%lx PA:0x%llx\n",index,page_addr,(ulonglong)paddr);
                    index += 1;
                }
            }
        }
    }
}

#pragma GCC diagnostic pop
