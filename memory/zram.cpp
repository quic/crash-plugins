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

#include "zram.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-arith"

#ifndef BUILD_TARGET_TOGETHER
DEFINE_PLUGIN_COMMAND(Zram)
#endif

void Zram::cmd_main(void) {
    int c;
    std::string cppString;
    if (argcnt < 2) cmd_usage(pc->curcmd, SYNOPSIS);
    if (!is_zram_enable()){
        return;
    }
    if(zram_list.size() == 0){
        parser_zrams();
    }
    while ((c = getopt(argcnt, args, "am:f:p:z:o:d")) != EOF) {
        switch(c) {
            case 'a':
                print_zrams();
                break;
            case 'm':
                cppString.assign(optarg);
                print_mem_pool(cppString);
                break;
            case 'f':
                cppString.assign(optarg);
                print_zram_full_info(cppString);
                break;
            case 'p':
                cppString.assign(optarg);
                print_pages(cppString);
                break;
            case 'z':
                cppString.assign(optarg);
                print_zspages(cppString);
                break;
            case 'o':
                cppString.assign(optarg);
                print_objs(cppString);
                break;
            case 'd':
                debug = true;
                break;
            default:
                argerrs++;
                break;
        }
    }
    if (argerrs)
        cmd_usage(pc->curcmd, SYNOPSIS);
}

Zram::Zram(){
    cmd_name = "zram";
    help_str_list={
        "zram",                            /* command name */
        "dump zram information",        /* short description */
        "-a \n"
            "  zram -m <zram addr>\n"
            "  zram -f <zram addr>\n"
            "  zram -p <zram addr>\n"
            "  zram -z <zram addr>\n"
            "  zram -o <size_class/zspage/page addr>\n"
            "  zram -d\n"
            "  This command dumps the zram info.",
        "\n",
        "EXAMPLES",
        "  Display all zram info:",
        "    %s> zram -a",
        "    ========================================================================",
        "    zram                : ffffff801530dc00",
        "    name                : zram0",
        "    compressor          : lz4 rle",
        "    total_size          : 1.50Gb",
        "    zs_pool             : ffffff805bad4000",
        "    orig_data_size      : 291.87Mb",
        "    compr_data_size     : 88.53Mb",
        "    compress ratio      : 30.33%",
        "    mem_used_max        : 93.48Mb",
        "    mem_used_total      : 93.47Mb",
        "    mem_limit           : 0b",
        "    same_pages          : 6096",
        "    huge_pages          : 1964",
        "    compacted_pages     : 4495",
        "    ========================================================================",
        "\n",
        "  Display the memory pool of specified zram by zram address:",
        "    %s> zram -m ffffff801530dc00",
        "    zs_pool             : ffffff805bad4000",
        "    name                : zram0",
        "    pages_allocated     : 23929",
        "    isolated_pages      : 0",
        "    pages_compacted     : 4495",
        "    =============================================================================================",
        "    index size_class         EMPTY ALMOST_EMPTY ALMOST_FULL  FULL  pages objs  size  OBJ_ALLOCATED OBJ_USED",
        "    0     ffffff805b0b7000   0     0            0            0     1     128   32    0             0",
        "    1     ffffff805b0b7300   0     1            2            7     3     256   48    2560          2368",
        "    2     ffffff805b0b7480   0     1            3            19    1     64    64    1472          1444",
        "    3     ffffff805b0b7f00   0     0            1            22    1     51    80    1173          1168",
        "\n",
        "  Display the full info of specified zram by zram address:",
        "    %s> zram -f ffffff801530dc00",
        "    size_class(ffffff805b0b7300) objs_per_zspage:256 pages_per_zspage:3 size:48",
        "       zspage[0]:ffffff805414f400 freeobj:66 inuse:66 class:1 fullness:1",
        "           page[0]:fffffffe01e2b880 PFN:b8ae2 range:b8ae2000-b8ae3000 offset:0",
        "                   obj[0] b8ae2000-b8ae2030 handle:ffffff8068ea93d0 index:0    alloc",
        "                   obj[1] b8ae2030-b8ae2060 handle:ffffff8068d795e0 index:1    alloc",
        "                   obj[2] b8ae2060-b8ae2090 handle:ffffff8013df55e0 index:2    alloc",
        "\n",
        "  Display all pages of specified zram by zram address:",
        "    %s> zram -p ffffff801530dc00",
        "      Page[0]:fffffffe01e2b880 PFN:b8ae2 range:b8ae2000-b8ae3000 offset:0",
        "      Page[1]:fffffffe01f980c0 PFN:be603 range:be603000-be604000 offset:32",
        "      Page[2]:fffffffe01cf6440 PFN:b3d91 range:b3d91000-b3d92000 offset:16",
        "      Page[3]:fffffffe01e70c40 PFN:b9c31 range:b9c31000-b9c32000 offset:0",
        "\n",
        "  Display all zspage of specified zram by zram address:",
        "    %s> zram -z ffffff801530dc00",
        "      zspage[0]:ffffff805414f400 class:1 fullness:1 pages:3 inuse:66 freeobj:66",
        "      zspage[1]:ffffff8067f162b0 class:1 fullness:2 pages:3 inuse:255 freeobj:101",
        "      zspage[2]:ffffff806578c780 class:1 fullness:2 pages:3 inuse:255 freeobj:235",
        "      zspage[3]:ffffff8068ca4240 class:1 fullness:3 pages:3 inuse:256 freeobj:2147483647",
        "\n",
        "  Display all obj info by zs_class/zspage/page address:",
        "    %s> zram -o ffffff805414f400",
        "      obj[0] b8ae2000-b8ae2030 handle:ffffff8068ea93d0 index:0    alloc",
        "      obj[1] b8ae2030-b8ae2060 handle:ffffff8068d795e0 index:1    alloc",
        "      obj[2] b8ae2060-b8ae2090 handle:ffffff8013df55e0 index:2    alloc",
        "      obj[3] b8ae2090-b8ae20c0 handle:ffffff806b06ccd0 index:3    alloc",
        "      obj[4] b8ae20c0-b8ae20f0 handle:ffffff8068e612e0 index:4    alloc",
        "\n",
        "  Enable debug log:",
        "    %s> zram -d",
        "\n",
    };
    initialize();
}

void Zram::print_mem_pool(std::string zram_addr){
    ulong addr = std::stoul(zram_addr, nullptr, 16);
    if (!is_kvaddr(addr)){
        fprintf(fp, "invaild addr %lx\n",addr);
        return;
    }
    std::shared_ptr<zram> zram_ptr;
    bool is_found = false;
    for (const auto &zram : zram_list){
        if (zram->addr == addr){
            is_found = true;
            zram_ptr = zram;
            break;
        }
    }
    if (is_found == false){
        fprintf(fp, "invaild addr %lx\n",addr);
        return;
    }
    std::shared_ptr<zs_pool> pool_ptr = zram_ptr->mem_pool;
    std::ostringstream oss;
    oss << std::left << std::setw(20) << "zs_pool" << ": "
        << std::hex << pool_ptr->addr;
    fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");

    oss << std::left << std::setw(20) << "name" << ": "
        << pool_ptr->name;
    fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");

    oss << std::left << std::setw(20) << "pages_allocated" << ": "
        << std::dec << pool_ptr->pages_allocated;
    fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");

    oss << std::left << std::setw(20) << "isolated_pages" << ": "
        << std::dec << pool_ptr->isolated_pages;
    fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");

    oss << std::left << std::setw(20) << "pages_compacted" << ": "
        << std::dec << pool_ptr->stats.pages_compacted.counter;
    fprintf(fp, "%s \n",oss.str().c_str());
    oss.str("");
    fprintf(fp, "=============================================================================================\n");
    std::ostringstream oss_hd;
    oss_hd << std::setw(5) << "index" << " "
        << std::left << std::setw(VADDR_PRLEN) << "size_class" << " "
        << std::left << std::setw(5) << "EMPTY" << " "
        << std::left << std::setw(12) << "ALMOST_EMPTY" << " "
        << std::left << std::setw(12) << "ALMOST_FULL" << " "
        << std::left << std::setw(5) << "FULL" << " "
        << std::left << std::setw(12) << "pages/zspage" << " "
        << std::left << std::setw(12) << "objs/zspage" << " "
        << std::left << std::setw(9) << "obj_size" << " "
        << std::left << std::setw(13) << "OBJ_ALLOCATED" << " "
        << "OBJ_USED";
    fprintf(fp, "%s \n",oss_hd.str().c_str());
    std::vector<std::string> class_stat_type = get_enumerator_list("class_stat_type");
    int CLASS_EMPTY = 0;
    int CLASS_ALMOST_EMPTY = 0;
    int CLASS_ALMOST_FULL = 0;
    int CLASS_FULL = 0;
    int OBJ_ALLOCATED = 0;
    int OBJ_USED = 0;
    if (class_stat_type.size() > 0){
        CLASS_EMPTY = read_enum_val("ZS_INUSE_RATIO_0");
        CLASS_ALMOST_EMPTY = read_enum_val("ZS_INUSE_RATIO_10");
        CLASS_ALMOST_FULL = read_enum_val("ZS_INUSE_RATIO_99");
        CLASS_FULL = read_enum_val("ZS_INUSE_RATIO_100");
        OBJ_ALLOCATED = read_enum_val("ZS_OBJS_ALLOCATED");
        OBJ_USED = read_enum_val("ZS_OBJS_INUSE");
    }else{
        CLASS_EMPTY = read_enum_val("CLASS_EMPTY");
        CLASS_ALMOST_EMPTY = read_enum_val("CLASS_ALMOST_EMPTY");
        CLASS_ALMOST_FULL = read_enum_val("CLASS_ALMOST_FULL");
        CLASS_FULL = read_enum_val("CLASS_FULL");
        OBJ_ALLOCATED = read_enum_val("OBJ_ALLOCATED");
        OBJ_USED = read_enum_val("OBJ_USED");
    }
    for (size_t i = 0; i < pool_ptr->class_list.size(); i++){
        std::shared_ptr<size_class> class_ptr = pool_ptr->class_list[i];
        std::ostringstream oss;
        oss << "[" << std::dec << std::setw(5) << std::setfill('0') << i << "] "
            << std::left << std::hex << std::setw(VADDR_PRLEN) << std::setfill(' ') << class_ptr->addr << " "
            << std::left << std::dec << std::setw(5) << class_ptr->stats[CLASS_EMPTY] << " "
            << std::left << std::dec << std::setw(12) << class_ptr->stats[CLASS_ALMOST_EMPTY] << " "
            << std::left << std::dec << std::setw(12) << class_ptr->stats[CLASS_ALMOST_FULL] << " "
            << std::left << std::dec << std::setw(5) << class_ptr->stats[CLASS_FULL] << " "
            << std::left << std::dec << std::setw(12) << class_ptr->pages_per_zspage << " "
            << std::left << std::dec << std::setw(12) << class_ptr->objs_per_zspage << " "
            << std::left << std::dec << std::setw(9) << csize(class_ptr->size) << " "
            << std::left << std::dec << std::setw(13) << class_ptr->stats[OBJ_ALLOCATED] << " "
            << std::left << std::dec << class_ptr->stats[OBJ_USED];
        fprintf(fp, "%s \n",oss.str().c_str());
    }
}

void Zram::print_zspages(std::string zram_addr){
    ulong addr = std::stoul(zram_addr, nullptr, 16);
    if (!is_kvaddr(addr)){
        fprintf(fp, "invaild addr %lx\n",addr);
        return;
    }
    std::shared_ptr<zram> zram_ptr;
    bool is_found = false;
    for (const auto &zram : zram_list){
        if (zram->addr == addr){
            is_found = true;
            zram_ptr = zram;
            break;
        }
    }
    if (is_found == false){
        fprintf(fp, "invaild addr %lx\n",addr);
        return;
    }
    size_t index = 1;
    for (const auto& class_ptr : zram_ptr->mem_pool->class_list) {
        if(class_ptr->zspage_parser == false){
            parser_zpage(class_ptr);
        }
        for (int i = 0; i < group_cnt; i++){
            std::vector<std::shared_ptr<zpage>> zspage_list = class_ptr->fullness_list[i];
            for (size_t z = 0; z < zspage_list.size(); z++){
                std::shared_ptr<zpage> zspage_ptr = zspage_list[z];
                std::ostringstream oss;
                if (THIS_KERNEL_VERSION < LINUX(5, 17, 0)){
                    oss << "zspage[" << std::dec << std::setw(5) << std::setfill('0') << index << "]:"
                        << std::hex << zspage_ptr->addr << " "
                        << "class:" << std::left << std::dec << std::setw(3) << std::setfill(' ') << zspage_ptr->zspage.v0.class_id << " "
                        << "fullness:" << std::dec << zspage_ptr->zspage.v0.fullness << " "
                        << "pages:" << std::dec << class_ptr->pages_per_zspage << " "
                        << "inuse:" << std::left << std::dec << std::setw(5) << zspage_ptr->zspage.inuse << " "
                        << "freeobj:" << std::dec << zspage_ptr->zspage.freeobj;
                    fprintf(fp, "%s \n",oss.str().c_str());
                }else{
                    oss << "zspage[" << std::dec << std::setw(5) << std::setfill('0') << index << "]:"
                        << std::hex << zspage_ptr->addr << " "
                        << "class:" << std::left << std::dec << std::setw(3) << std::setfill(' ') << zspage_ptr->zspage.v5_17.class_id << " "
                        << "fullness:" << std::dec << zspage_ptr->zspage.v5_17.fullness << " "
                        << "pages:" << std::dec << class_ptr->pages_per_zspage << " "
                        << "inuse:" << std::left << std::dec << std::setw(5) << zspage_ptr->zspage.inuse << " "
                        << "freeobj:" << std::dec << zspage_ptr->zspage.freeobj;
                    fprintf(fp, "%s \n",oss.str().c_str());
                }
                index += 1;
            }
        }
    }
}

void Zram::print_pages(std::string zram_addr){
    ulong addr = std::stoul(zram_addr, nullptr, 16);
    if (!is_kvaddr(addr)){
        fprintf(fp, "invaild addr %lx\n",addr);
        return;
    }
    std::shared_ptr<zram> zram_ptr;
    bool is_found = false;
    for (const auto &zram : zram_list){
        if (zram->addr == addr){
            is_found = true;
            zram_ptr = zram;
            break;
        }
    }
    if (is_found == false){
        fprintf(fp, "invaild addr %lx\n",addr);
        return;
    }
    size_t index = 1;
    for (const auto& class_ptr : zram_ptr->mem_pool->class_list) {
        if(class_ptr->zspage_parser == false){
            parser_zpage(class_ptr);
        }
        for (int i = 0; i < group_cnt; i++){
            std::vector<std::shared_ptr<zpage>> zspage_list = class_ptr->fullness_list[i];
            for (size_t z = 0; z < zspage_list.size(); z++){
                std::shared_ptr<zpage> zspage_ptr = zspage_list[z];
                for (size_t p = 0; p < zspage_ptr->page_list.size(); p++){
                    std::shared_ptr<pageinfo> pageinfo = zspage_ptr->page_list[p];
                    physaddr_t page_start = page_to_phy(pageinfo->addr);
                    ulong pfn = page_to_pfn(pageinfo->addr);
                    physaddr_t page_end = page_start + page_size;
                    int offset = read_int(pageinfo->addr + field_offset(page,units),"page units");
                    std::ostringstream oss;
                    oss << "Page[" << std::dec << std::setw(5) << std::setfill('0') << index << "]:"
                        << std::hex << pageinfo->addr << " "
                        << "PFN:" << std::hex << pfn << " "
                        << "range:[" << std::hex << page_start << "-" << std::hex << page_end << "] "
                        << "offset:" << std::dec << offset;
                    fprintf(fp, "%s \n",oss.str().c_str());
                    oss.str("");
                    index += 1;
                }
            }
        }
    }
}

void Zram::print_objs(std::string addr){
    ulong vaddr = std::stoul(addr, nullptr, 16);
    if (!is_kvaddr(vaddr)){
        fprintf(fp, "invaild addr %s, please input the size_class/zspage/page address\n",addr.c_str());
        return;
    }
    int flags = 0;
    std::shared_ptr<size_class> mclass_ptr;
    std::shared_ptr<zpage> mzspage_ptr;
    std::shared_ptr<pageinfo> mpage_ptr;
    for (const auto &zram_ptr : zram_list){
        for (const auto& class_ptr : zram_ptr->mem_pool->class_list) {
            if(class_ptr->zspage_parser == false){
                parser_zpage(class_ptr);
            }
            if(class_ptr->addr == vaddr){
                flags = PRINT_SIZE_CLASS;
                mclass_ptr = class_ptr;
                goto print_obj;
            }
            for (int i = 0; i < group_cnt; i++){
                std::vector<std::shared_ptr<zpage>> zspage_list = class_ptr->fullness_list[i];
                for (size_t z = 0; z < zspage_list.size(); z++){
                    std::shared_ptr<zpage> zspage_ptr = zspage_list[z];
                    if(zspage_ptr->addr == vaddr){
                        flags = PRINT_ZSPAGE;
                        mzspage_ptr = zspage_ptr;
                        goto print_obj;
                    }
                    for (size_t p = 0; p < zspage_ptr->page_list.size(); p++){
                        std::shared_ptr<pageinfo> pageinfo = zspage_ptr->page_list[p];
                        if(pageinfo->addr == vaddr){
                            flags = PRINT_PAGE;
                            mpage_ptr = pageinfo;
                            goto print_obj;
                        }
                    }
                }
            }
        }
    }
print_obj:
    if (flags & PRINT_SIZE_CLASS){
        print_size_class_obj(mclass_ptr);
    }else if(flags & PRINT_ZSPAGE){
        print_zspage_obj(mzspage_ptr);
    }else if(flags & PRINT_PAGE){
        print_page_obj(mpage_ptr);
    }
}

void Zram::print_size_class_obj(std::shared_ptr<size_class> class_ptr){
    for (int i = 0; i < group_cnt; i++){
        std::vector<std::shared_ptr<zpage>> zspage_list = class_ptr->fullness_list[i];
        for (size_t z = 0; z < zspage_list.size(); z++){
            std::shared_ptr<zpage> zspage_ptr = zspage_list[z];
            for (size_t p = 0; p < zspage_ptr->page_list.size(); p++){
                std::shared_ptr<pageinfo> pageinfo = zspage_ptr->page_list[p];
                print_page_obj(pageinfo);
            }
        }
    }
}

void Zram::print_zspage_obj(std::shared_ptr<zpage> zspage_ptr){
    for (size_t p = 0; p < zspage_ptr->page_list.size(); p++){
        std::shared_ptr<pageinfo> pageinfo = zspage_ptr->page_list[p];
        print_page_obj(pageinfo);
    }
}

void Zram::print_page_obj(std::shared_ptr<pageinfo> page_ptr){
    for (const auto &obj_ptr : page_ptr->obj_list){
        std::ostringstream oss;
        if (obj_ptr->is_free == false){ // obj is alloc
            oss << "           obj[" << std::setw(6) << std::setfill('0') << obj_ptr->id << "]"
                << std::hex << obj_ptr->start << "~" << std::hex << obj_ptr->end << " "
                << "handle:" << std::left << std::setw(VADDR_PRLEN) << std::setfill(' ') << std::hex << obj_ptr->handle_addr << " "
                << "index:"  << std::left << std::setw(4) << std::dec << obj_ptr->index << " "
                << "alloc";
            fprintf(fp, "%s \n",oss.str().c_str());
        }else{ // obj is free
            oss << "           obj[" << std::setw(6) << std::setfill('0') << obj_ptr->id << "]"
                << std::hex << obj_ptr->start << "~" << std::hex << obj_ptr->end << " "
                << "handle:" << std::left << std::setw(VADDR_PRLEN) << std::setfill(' ') << std::dec << obj_ptr->handle_addr << " "
                << "next :"   << std::left << std::setw(4) << std::dec << obj_ptr->next << " "
                << "freed";
            fprintf(fp, "%s \n",oss.str().c_str());
        }
    }
}

void Zram::print_zram_full_info(std::string zram_addr){
    ulong addr = std::stoul(zram_addr, nullptr, 16);
    if (!is_kvaddr(addr)){
        fprintf(fp, "invaild addr %lx\n",addr);
        return;
    }
    std::shared_ptr<zram> zram_ptr;
    bool is_found = false;
    for (const auto &zram : zram_list){
        if (zram->addr == addr){
            is_found = true;
            zram_ptr = zram;
            break;
        }
    }
    if (is_found == false){
        fprintf(fp, "invaild addr %lx\n",addr);
        return;
    }
    for (const auto& class_ptr : zram_ptr->mem_pool->class_list) {
        if(class_ptr->zspage_parser == false){
            parser_zpage(class_ptr);
        }
        fprintf(fp, "\nsize_class(%lx) objs_per_zspage:%d pages_per_zspage:%d size:%d\n", class_ptr->addr,
            class_ptr->objs_per_zspage, class_ptr->pages_per_zspage, class_ptr->size);
        for (int i = 0; i < group_cnt; i++){
            std::vector<std::shared_ptr<zpage>> zspage_list = class_ptr->fullness_list[i];
            for (size_t z = 0; z < zspage_list.size(); z++){
                std::shared_ptr<zpage> zspage_ptr = zspage_list[z];
                if (THIS_KERNEL_VERSION < LINUX(5, 17, 0)){
                    fprintf(fp, "   zspage[%zu]:%lx freeobj:%d inuse:%d class:%d fullness:%d\n", z,
                            zspage_ptr->addr,
                            zspage_ptr->zspage.freeobj,
                            zspage_ptr->zspage.inuse,
                            zspage_ptr->zspage.v0.class_id,
                            zspage_ptr->zspage.v0.fullness);
                }else{
                    fprintf(fp, "   zspage[%zu]:%lx freeobj:%d inuse:%d class:%d fullness:%d\n",z,
                            zspage_ptr->addr,
                            zspage_ptr->zspage.freeobj,
                            zspage_ptr->zspage.inuse,
                            zspage_ptr->zspage.v5_17.class_id,
                            zspage_ptr->zspage.v5_17.fullness);
                }
                for (size_t p = 0; p < zspage_ptr->page_list.size(); p++){
                    std::shared_ptr<pageinfo> pageinfo = zspage_ptr->page_list[p];
                    physaddr_t page_start = page_to_phy(pageinfo->addr);
                    ulong pfn = page_to_pfn(pageinfo->addr);
                    physaddr_t page_end = page_start + page_size;
                    int offset = read_int(pageinfo->addr + field_offset(page,units),"page units");
                    fprintf(fp, "       page[%zu]:%lx PFN:%lx range:%llx-%llx offset:%d\n", p, pageinfo->addr,
                        pfn,(ulonglong)page_start,(ulonglong)page_end,offset);
                    print_page_obj(pageinfo);
                }
            }
        }
    }
}

void Zram::print_zrams(){
    if (zram_list.size() == 0){
        fprintf(fp, "Maybe not enable zram \n");
        return;
    }
    fprintf(fp, "========================================================================\n");
    for (const auto& zram_ptr : zram_list) {
        double ratio = (double)zram_ptr->stats.compr_data_size / (double)(zram_ptr->stats.pages_stored * page_size);
        std::ostringstream oss;
        oss << std::left << std::setw(20) << "zram"             << ": " << std::hex << zram_ptr->addr << "\n"
            << std::left << std::setw(20) << "name"             << ": " << zram_ptr->disk_name << "\n"
            << std::left << std::setw(20) << "compressor"       << ": " << (zram_ptr->compressor.empty() ? zram_ptr->zcomp_name : zram_ptr->compressor) << "\n"
            << std::left << std::setw(20) << "total_size"       << ": " << csize(zram_ptr->disksize) << "\n"
            << std::left << std::setw(20) << "zs_pool"          << ": " << std::hex << zram_ptr->mem_pool->addr << "\n"
            << std::left << std::setw(20) << "orig_data_size"   << ": " << csize(zram_ptr->stats.pages_stored * page_size) << "\n"
            << std::left << std::setw(20) << "compr_data_size"  << ": " << csize(zram_ptr->stats.compr_data_size) << "\n"
            << std::left << std::setw(20) << "compress ratio"   << ": " << std::fixed << std::setprecision(2) << ratio * 100 << "%" << "\n"
            << std::left << std::setw(20) << "mem_used_max"     << ": " << csize(zram_ptr->stats.max_used_pages * page_size) << "\n"
            << std::left << std::setw(20) << "mem_used_total"   << ": " << csize(zram_ptr->mem_pool->pages_allocated * page_size) << "\n"
            << std::left << std::setw(20) << "mem_limit"        << ": " << csize(zram_ptr->limit_pages * page_size) << "\n"
            << std::left << std::setw(20) << "same_pages"       << ": " << csize(zram_ptr->stats.same_pages * page_size) << "\n"
            << std::left << std::setw(20) << "huge_pages"       << ": " << csize(zram_ptr->stats.huge_pages * page_size) << "\n"
            << std::left << std::setw(20) << "compacted_pages"  << ": " << csize(zram_ptr->mem_pool->stats.pages_compacted.counter * page_size) << "\n";
        fprintf(fp, "%s \n",oss.str().c_str());
    }
    fprintf(fp, "========================================================================\n");
}

#pragma GCC diagnostic pop
